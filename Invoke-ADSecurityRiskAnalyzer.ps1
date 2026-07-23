<#
.SYNOPSIS
    Read-only Active Directory sigurnosni analizator za lokalne AD domene.

.DESCRIPTION
    Prikuplja AD DS korisnike, racunare, grupe, politiku lozinki, metapodatke
    domene, clanstvo u privilegovanim grupama i failed login evente sa DC
    Security logova kada su dostupni. Generise JSON, CSV i HTML izvjestaje
    sa nalazima korisnim za pregled rizika i QBR sastanke.

    Skripta ne mijenja Active Directory.

    By: Adis Hadzovic

.REQUIREMENTS
    - Windows PowerShell 5.1 ili PowerShell 7+
    - RSAT Active Directory PowerShell modul
    - Mrezni pristup domenskom kontroleru
    - Domenski nalog sa read pristupom nad AD-om
    - Za failed logins: pravo citanja Security event loga na DC-evima
#>

[CmdletBinding()]
param(
    [ValidateSet('Security', 'Health')]
    [string]$AssessmentType = 'Security',

    [string]$ClientName,

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputPath,

    [string]$ConfigPath,

    [int]$StaleUserDays = 90,

    [int]$StaleComputerDays = 45,

    [int]$PrivilegedStaleDays = 180,

    [int]$MaxPasswordAgeDays = 365,

    [int]$ServiceAccountPasswordAgeDays = 180,

    [int]$KrbtgtMaxPasswordAgeDays = 180,

    [int]$MinPasswordLength = 15,

    [int]$MinPasswordHistory = 12,

    [int]$MaxDomainAdmins = 3,

    [int]$MaxEnterpriseAdmins = 1,

    [int]$FailedLoginLookbackHours = 24,

    [int]$FailedLoginMediumThreshold = 25,

    [int]$FailedLoginHighThreshold = 100,

    [int]$FailedLoginAccountThreshold = 10,

    [int]$FailedLoginMaxEventsPerDc = 1000,

    [int]$FailedLoginQueryTimeoutSeconds = 20,

    [switch]$SkipFailedLoginAudit,

    [switch]$AuditPasswordExpiration,

    [switch]$NoGui,

    [switch]$GuiChild,

    [switch]$SkipHtml,

    [switch]$NoCsv,

    [int]$HealthTcpTimeoutMilliseconds = 1800,

    [int]$HealthNativeCommandTimeoutSeconds = 120,

    [int]$HealthReplicationWarningHours = 4,

    [int]$HealthReplicationFailureHours = 24,

    [int]$HealthTimeWarningSeconds = 60,

    [int]$HealthTimeFailureSeconds = 300,

    [ValidateRange(1, 10000)]
    [int]$HealthMaxGpoChecks = 5000
)

$ErrorActionPreference = 'Stop'

$script:SelfScriptPath = $null
if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    $script:SelfScriptPath = $PSCommandPath
} elseif ($MyInvocation.MyCommand -and -not [string]::IsNullOrWhiteSpace($MyInvocation.MyCommand.Path)) {
    $script:SelfScriptPath = $MyInvocation.MyCommand.Path
}

$script:ScriptRoot = $null
if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $script:ScriptRoot = $PSScriptRoot
} elseif (-not [string]::IsNullOrWhiteSpace($script:SelfScriptPath)) {
    $script:ScriptRoot = Split-Path -Path $script:SelfScriptPath -Parent
} else {
    $script:ScriptRoot = (Get-Location).ProviderPath
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path $script:ScriptRoot -ChildPath 'reports'
}

function ConvertTo-CompatibleString {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $text = [string]$Value
    $text = $text.Replace(('D' + [string][char]0x017D), 'DZ')
    $text = $text.Replace(('D' + [string][char]0x017E), 'Dz')
    $text = $text.Replace(('d' + [string][char]0x017E), 'dz')
    $text = $text.Replace([string][char]0x0110, 'Dj')
    $text = $text.Replace([string][char]0x0111, 'dj')
    $text = $text.Replace([string][char]0x010C, 'C')
    $text = $text.Replace([string][char]0x0106, 'C')
    $text = $text.Replace([string][char]0x010D, 'c')
    $text = $text.Replace([string][char]0x0107, 'c')
    $text = $text.Replace([string][char]0x0160, 'S')
    $text = $text.Replace([string][char]0x0161, 's')
    $text = $text.Replace([string][char]0x017D, 'Z')
    $text = $text.Replace([string][char]0x017E, 'z')
    return $text
}

function ConvertTo-CompatibleObject {
    param(
        [AllowNull()]
        [object]$InputObject,
        [int]$Depth = 0
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($Depth -gt 8) {
        return (ConvertTo-CompatibleString $InputObject)
    }

    if ($InputObject -is [string]) {
        return (ConvertTo-CompatibleString $InputObject)
    }

    if ($InputObject -is [datetime] -or $InputObject.GetType().IsPrimitive) {
        return $InputObject
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $hash = [ordered]@{}
        try {
            foreach ($key in $InputObject.Keys) {
                $hash[(ConvertTo-CompatibleString $key)] = (ConvertTo-CompatibleObject -InputObject $InputObject[$key] -Depth ($Depth + 1))
            }
        }
        catch {
            return (ConvertTo-CompatibleString $InputObject)
        }
        return $hash
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $items = @()
        try {
            foreach ($item in $InputObject) {
                $items += ,(ConvertTo-CompatibleObject -InputObject $item -Depth ($Depth + 1))
            }
        }
        catch {
            return (ConvertTo-CompatibleString $InputObject)
        }
        return ,([object[]]$items)
    }

    if ($InputObject.PSObject -and $InputObject.PSObject.Properties.Count -gt 0) {
        $objectHash = [ordered]@{}
        try {
            foreach ($property in $InputObject.PSObject.Properties) {
                $objectHash[(ConvertTo-CompatibleString $property.Name)] = (ConvertTo-CompatibleObject -InputObject $property.Value -Depth ($Depth + 1))
            }
        }
        catch {
            return (ConvertTo-CompatibleString $InputObject)
        }
        return $objectHash
    }

    return (ConvertTo-CompatibleString $InputObject)
}

function Import-RequiredModule {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        throw 'Potreban je ActiveDirectory PowerShell modul. Instaliraj RSAT: Active Directory Domain Services and Lightweight Directory Tools.'
    }
}

function ConvertTo-EvidenceText {
    param(
        [AllowNull()]
        [object]$Evidence
    )

    if ($null -eq $Evidence) {
        return ''
    }

    if ($Evidence -is [string]) {
        return (ConvertTo-CompatibleString $Evidence)
    }

    try {
        return ((ConvertTo-CompatibleObject -InputObject $Evidence) | ConvertTo-Json -Compress -Depth 8)
    }
    catch {
        return (ConvertTo-CompatibleString $Evidence)
    }
}

function Get-SeverityScore {
    param(
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { return 100 }
        'High' { return 75 }
        'Medium' { return 50 }
        'Low' { return 25 }
        'Info' { return 5 }
    }
}

function Get-RiskAreaFromCategory {
    param(
        [string]$Category
    )

    switch ((ConvertTo-CompatibleString $Category)) {
        'Privilegovani pristup' { return 'PrivilegedAccounts' }
        'Trust odnosi' { return 'Trusts' }
        'Higijena naloga' { return 'StaleObjects' }
        'Higijena racunara' { return 'StaleObjects' }
        'Operativni sistem' { return 'StaleObjects' }
        'Putanja napada' { return 'StaleObjects' }
        default { return 'Anomalies' }
    }
}

function Get-RiskAreaLabel {
    param(
        [string]$RiskArea
    )

    switch ((ConvertTo-CompatibleString $RiskArea)) {
        'StaleObjects' { return 'Zastarjeli objekti' }
        'PrivilegedAccounts' { return 'Privilegovani nalozi' }
        'Trusts' { return 'Trust odnosi' }
        'Anomalies' { return 'Sigurnosne anomalije' }
        default { return 'Sigurnosne anomalije' }
    }
}

function New-ScoringRuleDefinition {
    param(
        [string]$Id,
        [string]$ScoreCategory,
        [string]$RuleModel,
        [string]$Method,
        [int]$Points = 0,
        [int]$MaxPoints = 0,
        [string]$Severity = '*',
        [string]$Denominator = '',
        [string]$EvidenceField = '',
        [object[]]$Tiers = @(),
        [int]$MinPoints = 0
    )

    return [pscustomobject][ordered]@{
        Id            = $Id
        ScoreCategory = $ScoreCategory
        RuleModel     = $RuleModel
        Method        = $Method
        Points        = $Points
        MaxPoints     = $MaxPoints
        Severity      = $Severity
        Denominator   = $Denominator
        EvidenceField = $EvidenceField
        Tiers         = @($Tiers)
        MinPoints     = $MinPoints
    }
}

function Get-ScoringRuleCatalog {
    if ($null -ne $script:ScoringRuleCatalog) {
        return $script:ScoringRuleCatalog
    }

    $definitions = @(
        (New-ScoringRuleDefinition -Id 'AD-POLICY-001' -ScoreCategory 'Anomalies' -RuleModel 'Slaba politika lozinki' -Method 'Presence' -Points 10 -MaxPoints 10),
        (New-ScoringRuleDefinition -Id 'AD-POLICY-002' -ScoreCategory 'Anomalies' -RuleModel 'Kontrolna informacija' -Method 'Presence' -Points 0 -MaxPoints 0),
        (New-ScoringRuleDefinition -Id 'AD-POLICY-003' -ScoreCategory 'Anomalies' -RuleModel 'Zastita od pogadjanja lozinki' -Method 'Presence' -Points 10 -MaxPoints 10),
        (New-ScoringRuleDefinition -Id 'AD-POLICY-004' -ScoreCategory 'Anomalies' -RuleModel 'Historija lozinki' -Method 'SeverityPresence' -MaxPoints 1),
        (New-ScoringRuleDefinition -Id 'AD-POLICY-005' -ScoreCategory 'Anomalies' -RuleModel 'Kontrolna informacija' -Method 'Presence' -Points 0 -MaxPoints 0),
        (New-ScoringRuleDefinition -Id 'AD-POLICY-006' -ScoreCategory 'Anomalies' -RuleModel 'Slaba detaljna politika lozinki' -Method 'PerFinding' -Points 5 -MaxPoints 15),

        (New-ScoringRuleDefinition -Id 'AD-PRIV-001' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Prevelik broj stalnih administratora' -Method 'Presence' -Points 10 -MaxPoints 10),
        (New-ScoringRuleDefinition -Id 'AD-PRIV-002' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Stalni forest administratori' -Method 'Presence' -Points 10 -MaxPoints 10),
        (New-ScoringRuleDefinition -Id 'AD-PRIV-003' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Osjetljive administratorske grupe' -Method 'PerFinding' -Points 2 -MaxPoints 10),
        (New-ScoringRuleDefinition -Id 'AD-PRIV-004' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Neodobreno privilegovano clanstvo' -Method 'PerFinding' -Points 20 -MaxPoints 100),
        (New-ScoringRuleDefinition -Id 'AD-PRIV-005' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Neaktivni privilegovani nalozi' -Method 'RatioTiers' -Denominator 'PrivilegedUsers' -MaxPoints 30 -Tiers @(
            @{ Min = 30; Points = 30 }, @{ Min = 15; Points = 20 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-PRIV-006' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Delegabilni privilegovani nalozi' -Method 'Presence' -Points 20 -MaxPoints 20),
        (New-ScoringRuleDefinition -Id 'AD-PRIV-007' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Stara privilegovana lozinka' -Method 'SeverityPresence' -MaxPoints 10),
        (New-ScoringRuleDefinition -Id 'AD-PRIV-008' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Onemoguceno privilegovano clanstvo' -Method 'Presence' -Points 1 -MaxPoints 1),
        (New-ScoringRuleDefinition -Id 'AD-PRIV-009' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Prevelik udio privilegovanih naloga' -Method 'Presence' -Points 10 -MaxPoints 10),

        (New-ScoringRuleDefinition -Id 'AD-USER-001' -ScoreCategory 'Anomalies' -RuleModel 'Ugradjeni Guest nalog' -Method 'Presence' -Points 15 -MaxPoints 15),
        (New-ScoringRuleDefinition -Id 'AD-USER-002' -ScoreCategory 'Anomalies' -RuleModel 'Starost krbtgt lozinke' -Method 'EvidenceTiers' -EvidenceField 'PasswordAgeDays' -MaxPoints 50 -Tiers @(
            @{ Min = 1464; Points = 50 }, @{ Min = 1098; Points = 40 }, @{ Min = 732; Points = 30 }, @{ Min = 366; Points = 20 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-USER-003' -ScoreCategory 'StaleObjects' -RuleModel 'Neaktivni korisnicki nalozi' -Method 'RatioTiers' -Denominator 'EnabledUsers' -MaxPoints 10 -Tiers @(
            @{ Min = 25; Points = 10 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-USER-004' -ScoreCategory 'StaleObjects' -RuleModel 'Nalozi bez isteka lozinke' -Method 'Presence' -Points 1 -MaxPoints 1),
        (New-ScoringRuleDefinition -Id 'AD-USER-005' -ScoreCategory 'StaleObjects' -RuleModel 'Legacy password audit' -Method 'Presence' -Points 0 -MaxPoints 0),
        (New-ScoringRuleDefinition -Id 'AD-USER-006' -ScoreCategory 'StaleObjects' -RuleModel 'AS-REP roastable nalozi' -Method 'Presence' -Points 5 -MaxPoints 5),
        (New-ScoringRuleDefinition -Id 'AD-USER-007' -ScoreCategory 'StaleObjects' -RuleModel 'Kerberoastable servisni nalozi' -Method 'CountTiers' -MaxPoints 10 -Tiers @(
            @{ Min = 15; Points = 10 }, @{ Min = 6; Points = 5 }, @{ Min = 1; Points = 2 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-USER-007' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Kerberoastable privilegovani nalozi' -Method 'PerFinding' -Points 5 -MaxPoints 50),
        (New-ScoringRuleDefinition -Id 'AD-USER-008' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Unconstrained delegacija' -Method 'PerFinding' -Points 5 -MaxPoints 100),
        (New-ScoringRuleDefinition -Id 'AD-USER-009' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Protocol transition prema DC servisu' -Method 'PerFinding' -Severity 'High' -Points 25 -MaxPoints 100),
        (New-ScoringRuleDefinition -Id 'AD-USER-009' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Protocol transition delegacija' -Method 'PerFinding' -Severity 'Medium' -Points 5 -MaxPoints 25),
        (New-ScoringRuleDefinition -Id 'AD-USER-010' -ScoreCategory 'StaleObjects' -RuleModel 'Zastarjela Kerberos kriptografija' -Method 'Presence' -Points 15 -MaxPoints 15),
        (New-ScoringRuleDefinition -Id 'AD-USER-011' -ScoreCategory 'StaleObjects' -RuleModel 'Reverzibilno cuvanje korisnickih lozinki' -Method 'Presence' -Points 5 -MaxPoints 5),
        (New-ScoringRuleDefinition -Id 'AD-USER-012' -ScoreCategory 'Anomalies' -RuleModel 'Zaostala AdminSDHolder zastita' -Method 'CountTiers' -MaxPoints 50 -Tiers @(
            @{ Min = 50; Points = 50 }, @{ Min = 40; Points = 40 }, @{ Min = 30; Points = 30 }, @{ Min = 20; Points = 20 }, @{ Min = 1; Points = 15 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-USER-013' -ScoreCategory 'StaleObjects' -RuleModel 'SIDHistory' -Method 'PerFindingMinimum' -Points 5 -MinPoints 15 -MaxPoints 50),

        (New-ScoringRuleDefinition -Id 'AD-COMP-001' -ScoreCategory 'StaleObjects' -RuleModel 'Neaktivni racunarski nalozi' -Method 'RatioTiers' -Denominator 'EnabledComputers' -MaxPoints 30 -Tiers @(
            @{ Min = 30; Points = 30 }, @{ Min = 20; Points = 10 }, @{ Min = 15; Points = 5 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-COMP-002' -ScoreCategory 'StaleObjects' -RuleModel 'Nerotirane masinske lozinke' -Method 'Presence' -Points 15 -MaxPoints 15),
        (New-ScoringRuleDefinition -Id 'AD-COMP-003' -ScoreCategory 'StaleObjects' -RuleModel 'Nepodrzani server operativni sistemi' -Method 'CountTiers' -Severity 'High' -MaxPoints 10 -Tiers @(
            @{ Min = 15; Points = 10 }, @{ Min = 6; Points = 5 }, @{ Min = 1; Points = 2 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-COMP-003' -ScoreCategory 'StaleObjects' -RuleModel 'Nepodrzani workstation operativni sistemi' -Method 'CountTiers' -Severity 'Medium' -MaxPoints 15 -Tiers @(
            @{ Min = 15; Points = 15 }, @{ Min = 6; Points = 10 }, @{ Min = 1; Points = 5 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-COMP-003' -ScoreCategory 'StaleObjects' -RuleModel 'Nepodrzani operativni sistemi' -Method 'CountTiers' -Severity 'Low' -MaxPoints 5 -Tiers @(
            @{ Min = 15; Points = 5 }, @{ Min = 1; Points = 2 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-COMP-004' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Unconstrained delegacija' -Method 'PerFinding' -Points 5 -MaxPoints 100),
        (New-ScoringRuleDefinition -Id 'AD-COMP-005' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Protocol transition prema DC servisu' -Method 'PerFinding' -Severity 'High' -Points 25 -MaxPoints 100),
        (New-ScoringRuleDefinition -Id 'AD-COMP-005' -ScoreCategory 'PrivilegedAccounts' -RuleModel 'Protocol transition delegacija' -Method 'PerFinding' -Severity 'Medium' -Points 5 -MaxPoints 25),

        (New-ScoringRuleDefinition -Id 'AD-AUTH-001' -ScoreCategory 'Anomalies' -RuleModel 'Operativna autentikacijska telemetrija' -Method 'Presence' -Points 0 -MaxPoints 0),
        (New-ScoringRuleDefinition -Id 'AD-AUTH-002' -ScoreCategory 'Anomalies' -RuleModel 'Operativna autentikacijska telemetrija' -Method 'Presence' -Points 0 -MaxPoints 0),

        (New-ScoringRuleDefinition -Id 'AD-TRUST-001' -ScoreCategory 'Trusts' -RuleModel 'Downlevel trust' -Method 'Presence' -Points 20 -MaxPoints 20),
        (New-ScoringRuleDefinition -Id 'AD-TRUST-002' -ScoreCategory 'Trusts' -RuleModel 'SID filtering nije aktivan' -Method 'CountTiers' -MaxPoints 100 -Tiers @(
            @{ Min = 4; Points = 100 }, @{ Min = 2; Points = 80 }, @{ Min = 1; Points = 50 }
        )),
        (New-ScoringRuleDefinition -Id 'AD-TRUST-003' -ScoreCategory 'Trusts' -RuleModel 'TGT delegation preko trusta' -Method 'PerFinding' -Points 10 -MaxPoints 50),
        (New-ScoringRuleDefinition -Id 'AD-TRUST-004' -ScoreCategory 'Trusts' -RuleModel 'Trust bez AES kljuceva' -Method 'Presence' -Points 1 -MaxPoints 1)
    )

    $catalog = @{}
    foreach ($definition in $definitions) {
        $key = '{0}|{1}|{2}' -f $definition.Id, $definition.ScoreCategory, $definition.Severity
        $catalog[$key] = $definition
    }

    $script:ScoringRuleCatalog = $catalog
    return $script:ScoringRuleCatalog
}

function Get-FindingEvidenceValue {
    param(
        [AllowNull()]
        [object]$Finding,
        [string]$PropertyName
    )

    if ($null -eq $Finding -or [string]::IsNullOrWhiteSpace($PropertyName)) {
        return $null
    }

    $evidenceProperty = $Finding.PSObject.Properties['Evidence']
    if ($null -eq $evidenceProperty -or $null -eq $evidenceProperty.Value) {
        return $null
    }

    $evidence = $evidenceProperty.Value
    if ($evidence -is [System.Collections.IDictionary]) {
        if ($evidence.Contains($PropertyName)) {
            return $evidence[$PropertyName]
        }
        return $null
    }

    $property = $evidence.PSObject.Properties[$PropertyName]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Test-FindingIsPrivileged {
    param(
        [AllowNull()]
        [object]$Finding
    )

    $value = Get-FindingEvidenceValue -Finding $Finding -PropertyName 'IsPrivileged'
    if ($value -is [bool]) {
        return $value
    }

    if ((ConvertTo-CompatibleString $value) -match '^(True|1)$') {
        return $true
    }

    $categories = @(Get-FindingEvidenceValue -Finding $Finding -PropertyName 'PrivilegedCategories')
    return ($categories.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace((ConvertTo-CompatibleString $categories[0])))
}

function Get-ScoringRuleDefinition {
    param(
        [string]$Id,
        [string]$ScoreCategory,
        [string]$Severity
    )

    $catalog = Get-ScoringRuleCatalog
    foreach ($key in @(
            ('{0}|{1}|{2}' -f $Id, $ScoreCategory, $Severity),
            ('{0}|{1}|*' -f $Id, $ScoreCategory)
        )) {
        if ($catalog.ContainsKey($key)) {
            return $catalog[$key]
        }
    }

    return (New-ScoringRuleDefinition -Id $Id -ScoreCategory $ScoreCategory -RuleModel 'Nekatalogizirano pravilo' -Method 'Presence' -Points 0 -MaxPoints 0)
}

function Get-FindingRuleMetadata {
    param(
        [string]$Id,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        [string]$Category,
        [AllowNull()]
        [object]$Finding
    )

    $scoreCategory = Get-RiskAreaFromCategory -Category $Category
    switch -Regex ((ConvertTo-CompatibleString $Id)) {
        '^AD-PRIV-' { $scoreCategory = 'PrivilegedAccounts'; break }
        '^AD-TRUST-' { $scoreCategory = 'Trusts'; break }
        '^AD-POLICY-|^AD-AUTH-|^AD-USER-(001|002|012)$' { $scoreCategory = 'Anomalies'; break }
        '^AD-USER-(008|009)$|^AD-COMP-(004|005)$' { $scoreCategory = 'PrivilegedAccounts'; break }
        '^AD-COMP-|^AD-USER-' { $scoreCategory = 'StaleObjects'; break }
    }

    if ($Id -eq 'AD-USER-007' -and (Test-FindingIsPrivileged -Finding $Finding)) {
        $scoreCategory = 'PrivilegedAccounts'
    }

    $definition = Get-ScoringRuleDefinition -Id $Id -ScoreCategory $scoreCategory -Severity $Severity
    return [pscustomobject][ordered]@{
        RiskArea        = $scoreCategory
        RiskAreaName    = Get-RiskAreaLabel -RiskArea $scoreCategory
        ScoreCategory   = $scoreCategory
        RuleModel       = ConvertTo-CompatibleString $definition.RuleModel
        ScoringMethod   = ConvertTo-CompatibleString $definition.Method
        RuleWeight      = [int]$definition.MaxPoints
        RuleMaxPoints   = [int]$definition.MaxPoints
        RuleDefinition  = $definition
    }
}

function Get-FindingEffectiveRuleMetadata {
    param(
        [object]$Finding
    )

    $severity = ConvertTo-CompatibleString $Finding.Severity
    if ($severity -notin @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $severity = 'Info'
    }

    if ((ConvertTo-CompatibleString $Finding.AssessmentType) -eq 'Health') {
        $healthArea = if ($Finding.PSObject.Properties['RiskAreaName']) {
            ConvertTo-CompatibleString $Finding.RiskAreaName
        }
        else {
            ConvertTo-CompatibleString $Finding.Category
        }
        $healthWeight = if ($Finding.PSObject.Properties['HealthWeight']) {
            [int]$Finding.HealthWeight
        }
        elseif ($Finding.PSObject.Properties['RuleWeight']) {
            [int]$Finding.RuleWeight
        }
        else {
            0
        }
        return [pscustomobject][ordered]@{
            RiskArea       = $healthArea
            RiskAreaName   = $healthArea
            ScoreCategory  = $healthArea
            RuleModel      = 'AD Health provjera'
            ScoringMethod  = 'Weighted pass/warning/fail'
            RuleWeight     = $healthWeight
            RuleMaxPoints  = $healthWeight
            RuleDefinition = $null
        }
    }

    return (Get-FindingRuleMetadata -Id (ConvertTo-CompatibleString $Finding.Id) -Severity $severity -Category (ConvertTo-CompatibleString $Finding.Category) -Finding $Finding)
}

function Get-ScoringContextValue {
    param(
        [AllowNull()]
        [object]$Context,
        [string]$PropertyName
    )

    if ($null -eq $Context -or [string]::IsNullOrWhiteSpace($PropertyName)) {
        return 0
    }

    if ($Context -is [System.Collections.IDictionary]) {
        if ($Context.Contains($PropertyName)) {
            return [double]$Context[$PropertyName]
        }
        return 0
    }

    $property = $Context.PSObject.Properties[$PropertyName]
    if ($null -ne $property -and $null -ne $property.Value) {
        return [double]$property.Value
    }

    return 0
}

function Get-TierPoints {
    param(
        [double]$Value,
        [object[]]$Tiers
    )

    foreach ($tier in @($Tiers | Sort-Object -Property { [double]$_.Min } -Descending)) {
        if ($Value -ge [double]$tier.Min) {
            return [int]$tier.Points
        }
    }

    return 0
}

function Get-RulePointResult {
    param(
        [object[]]$Findings,
        [object]$Definition,
        [AllowNull()]
        [object]$Context
    )

    $items = @($Findings)
    $count = $items.Count
    $points = 0
    $metric = [double]$count
    $denominator = 0.0
    $calculation = ''

    switch ((ConvertTo-CompatibleString $Definition.Method)) {
        'Presence' {
            $points = if ($count -gt 0) { [int]$Definition.Points } else { 0 }
            $calculation = "Prisustvo pravila: $points bodova"
        }
        'PerFinding' {
            $points = [math]::Min([int]$Definition.MaxPoints, ($count * [int]$Definition.Points))
            $calculation = "$count x $([int]$Definition.Points), maksimum $([int]$Definition.MaxPoints)"
        }
        'PerFindingMinimum' {
            if ($count -gt 0) {
                $points = [math]::Max([int]$Definition.MinPoints, ($count * [int]$Definition.Points))
                if (@($items | Where-Object { $_.Severity -eq 'High' -and (Get-FindingEvidenceValue -Finding $_ -PropertyName 'ContainsPrivilegedSid') }).Count -gt 0) {
                    $points = [math]::Max(30, $points)
                }
                $points = [math]::Min([int]$Definition.MaxPoints, $points)
            }
            $calculation = "$count x $([int]$Definition.Points), minimum $([int]$Definition.MinPoints), maksimum $([int]$Definition.MaxPoints)"
        }
        'CountTiers' {
            $points = Get-TierPoints -Value $count -Tiers $Definition.Tiers
            $calculation = "Prag prema broju nalaza: $count"
        }
        'RatioTiers' {
            $denominator = Get-ScoringContextValue -Context $Context -PropertyName $Definition.Denominator
            $metric = if ($denominator -gt 0) { [math]::Round((100.0 * $count / $denominator), 2) } else { 0.0 }
            $points = if ($denominator -gt 0) { Get-TierPoints -Value $metric -Tiers $Definition.Tiers } else { 0 }
            $calculation = "$count / $([int]$denominator) = $metric%"
        }
        'EvidenceTiers' {
            $values = @($items | ForEach-Object {
                $value = Get-FindingEvidenceValue -Finding $_ -PropertyName $Definition.EvidenceField
                if ($null -ne $value -and (ConvertTo-CompatibleString $value) -match '^-?\d+([.,]\d+)?$') {
                    [double]$value
                }
            })
            $metric = if ($values.Count -gt 0) { [double](@($values | Measure-Object -Maximum).Maximum) } else { 0.0 }
            $points = Get-TierPoints -Value $metric -Tiers $Definition.Tiers
            $calculation = "$($Definition.EvidenceField) = $metric"
        }
        'EvidenceCountCapped' {
            $sum = 0.0
            foreach ($item in $items) {
                $value = Get-FindingEvidenceValue -Finding $item -PropertyName $Definition.EvidenceField
                if ($null -ne $value) {
                    $sum += [double]$value
                }
            }
            $metric = $sum
            $points = [math]::Min([int]$Definition.MaxPoints, ([int][math]::Ceiling($sum) * [int]$Definition.Points))
            $calculation = "$([int]$sum) clanstava x $([int]$Definition.Points), maksimum $([int]$Definition.MaxPoints)"
        }
        'SeverityPresence' {
            $severity = if (@($items | Where-Object { $_.Severity -eq 'Critical' }).Count -gt 0) {
                'Critical'
            } elseif (@($items | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) {
                'High'
            } elseif (@($items | Where-Object { $_.Severity -eq 'Medium' }).Count -gt 0) {
                'Medium'
            } elseif (@($items | Where-Object { $_.Severity -eq 'Low' }).Count -gt 0) {
                'Low'
            } else {
                'Info'
            }

            if ($Definition.Id -eq 'AD-PRIV-007') {
                $points = if ($severity -in @('Critical', 'High', 'Medium')) { 10 } else { 0 }
            } elseif ($Definition.Id -eq 'AD-POLICY-004') {
                $points = if ($severity -eq 'Low') { 1 } else { 0 }
            }
            $calculation = "Ozbiljnost pravila: $severity"
        }
        default {
            $points = 0
            $calculation = 'Pravilo ne utice na ocjenu'
        }
    }

    $points = [int][math]::Max(0, [math]::Min([int]$Definition.MaxPoints, $points))
    return [pscustomobject][ordered]@{
        Points      = $points
        Metric      = [math]::Round($metric, 2)
        Denominator = [math]::Round($denominator, 2)
        Calculation = ConvertTo-CompatibleString $calculation
    }
}

function Get-CoverageStatus {
    param(
        [AllowNull()]
        [object]$Coverage,
        [string]$ScoreCategory
    )

    if ($null -eq $Coverage) {
        return 'Complete'
    }

    $value = $null
    if ($Coverage -is [System.Collections.IDictionary]) {
        if ($Coverage.Contains($ScoreCategory)) {
            $value = $Coverage[$ScoreCategory]
        }
    }
    else {
        $property = $Coverage.PSObject.Properties[$ScoreCategory]
        if ($null -ne $property) {
            $value = $property.Value
        }
    }

    if ($null -eq $value) {
        return 'Complete'
    }
    if ($value -is [string]) {
        return (ConvertTo-CompatibleString $value)
    }
    if ($value.PSObject.Properties['Status']) {
        return (ConvertTo-CompatibleString $value.Status)
    }

    return (ConvertTo-CompatibleString $value)
}

function Get-RiskScoreAnalysis {
    param(
        [object[]]$Findings,
        [AllowNull()]
        [object]$Context,
        [AllowNull()]
        [object]$Coverage
    )

    $allFindings = ConvertTo-GuiFindingArray -InputObject $Findings
    $ruleSummaries = New-Object System.Collections.Generic.List[object]
    $categoryPoints = @{
        StaleObjects      = 0
        PrivilegedAccounts = 0
        Trusts            = 0
        Anomalies         = 0
    }

    $prepared = New-Object System.Collections.Generic.List[object]
    foreach ($finding in $allFindings) {
        $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
        $prepared.Add([pscustomobject]@{
            Finding = $finding
            GroupKey = ('{0}|{1}|{2}' -f $finding.Id, $metadata.RiskArea, $metadata.RuleDefinition.Severity)
            Metadata = $metadata
        }) | Out-Null
    }

    foreach ($group in @($prepared.ToArray() | Group-Object -Property GroupKey)) {
        $samples = @($group.Group)
        $sample = @($samples | Sort-Object -Property { $_.Finding.Score } -Descending)[0].Finding
        $metadata = $samples[0].Metadata
        $groupFindings = @($samples | ForEach-Object { $_.Finding })
        $definition = $metadata.RuleDefinition
        $pointResult = Get-RulePointResult -Findings $groupFindings -Definition $definition -Context $Context
        $points = [int]$pointResult.Points
        $scoreCategory = ConvertTo-CompatibleString $metadata.RiskArea
        $categoryPoints[$scoreCategory] = [int]$categoryPoints[$scoreCategory] + $points

        $ruleSummaries.Add([pscustomobject][ordered]@{
            Id               = ConvertTo-CompatibleString $sample.Id
            Title            = ConvertTo-CompatibleString $sample.Title
            Severity         = ConvertTo-CompatibleString $sample.Severity
            RiskArea         = $scoreCategory
            RiskAreaName     = Get-RiskAreaLabel -RiskArea $scoreCategory
            ScoreCategory    = $scoreCategory
            RuleModel        = ConvertTo-CompatibleString $definition.RuleModel
            ScoringMethod    = ConvertTo-CompatibleString $definition.Method
            Count            = [int]$groupFindings.Count
            RuleWeight       = [int]$definition.MaxPoints
            RuleMaxPoints    = [int]$definition.MaxPoints
            Metric           = [double]$pointResult.Metric
            Denominator      = [double]$pointResult.Denominator
            Calculation      = ConvertTo-CompatibleString $pointResult.Calculation
            Contribution     = $points
        }) | Out-Null
    }

    $areaSummaries = New-Object System.Collections.Generic.List[object]
    $isComplete = $true
    foreach ($scoreCategory in @('StaleObjects', 'PrivilegedAccounts', 'Trusts', 'Anomalies')) {
        $rawPoints = [int]$categoryPoints[$scoreCategory]
        $score = [int][math]::Min(100, $rawPoints)
        $status = Get-CoverageStatus -Coverage $Coverage -ScoreCategory $scoreCategory
        if ($status -notin @('Complete', 'Assessed')) {
            $isComplete = $false
        }
        $areaRules = @($ruleSummaries.ToArray() | Where-Object { $_.RiskArea -eq $scoreCategory })
        $dominant = if ($areaRules.Count -gt 0) { [int](@($areaRules | Measure-Object -Property Contribution -Maximum).Maximum) } else { 0 }

        $areaSummaries.Add([pscustomobject][ordered]@{
            RiskArea                 = $scoreCategory
            Name                     = Get-RiskAreaLabel -RiskArea $scoreCategory
            Score                    = $score
            RawPoints                = $rawPoints
            CoverageStatus           = $status
            DominantRuleContribution = $dominant
        }) | Out-Null
    }

    $overallScore = [int](@($areaSummaries.ToArray() | Measure-Object -Property Score -Maximum).Maximum)
    return [pscustomobject][ordered]@{
        Score         = $overallScore
        Model         = 'Kategorijski AD bodovni model v9'
        Methodology   = 'Svaka oblast je zbir eksplicitnih bodova pravila, najvise 100. Ukupna ocjena je najvisi od cetiri podskora.'
        IsComplete    = [bool]$isComplete
        ScoreStatus   = if ($isComplete) { 'Complete' } else { 'Incomplete' }
        DominantScore = $overallScore
        Counts        = [pscustomobject][ordered]@{
            Critical = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High     = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
            Medium   = @($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
            Low      = @($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
            Info     = @($allFindings | Where-Object { $_.Severity -eq 'Info' }).Count
            Total    = $allFindings.Count
        }
        AreaScores    = @($areaSummaries.ToArray() | Sort-Object -Property Score -Descending)
        CategoryScores = @($areaSummaries.ToArray() | Sort-Object -Property Score -Descending)
        RuleScores    = @($ruleSummaries.ToArray() | Sort-Object -Property Contribution -Descending)
    }
}

function Get-RiskScoreBaselineBands {
    return @(
        [pscustomobject][ordered]@{ Key = 'Minimal'; Label = 'Minimalan rizik'; Range = '0-9'; Min = 0; Max = 9; Meaning = 'Minimalan detektovani AD rizik.'; Action = 'Odrzavanje' },
        [pscustomobject][ordered]@{ Key = 'Low'; Label = 'Nizak rizik'; Range = '10-29'; Min = 10; Max = 29; Meaning = 'Ogranicen rizik i manji broj slabosti.'; Action = 'Redovni plan' },
        [pscustomobject][ordered]@{ Key = 'Elevated'; Label = 'Povisen rizik'; Range = '30-49'; Min = 30; Max = 49; Meaning = 'Znacajne slabosti u najmanje jednoj AD oblasti.'; Action = 'Planirana sanacija' },
        [pscustomobject][ordered]@{ Key = 'High'; Label = 'Visok rizik'; Range = '50-69'; Min = 50; Max = 69; Meaning = 'Visok rizik u najmanje jednoj AD oblasti.'; Action = 'Prioritetna sanacija' },
        [pscustomobject][ordered]@{ Key = 'Critical'; Label = 'Kritican rizik'; Range = '70-100'; Min = 70; Max = 100; Meaning = 'Kritican zbir rizika u najmanje jednoj AD oblasti.'; Action = 'Hitna sanacija' }
    )
}

function Get-RiskScoreBaseline {
    param(
        [int]$Score,
        [object]$RiskScoreDetails
    )

    $scoreValue = [math]::Max(0, [math]::Min(100, $Score))
    $bands = @(Get-RiskScoreBaselineBands)
    $band = @($bands | Where-Object { $scoreValue -ge [int]$_.Min -and $scoreValue -le [int]$_.Max } | Select-Object -First 1)[0]
    if ($null -eq $band) {
        $band = $bands[-1]
    }

    $targetMax = 29
    $idealMax = 9
    $gapToTarget = [math]::Max(0, $scoreValue - $targetMax)
    $baselineComparison = if ($scoreValue -le $targetMax) {
        'Unutar ciljnog raspona 0-29.'
    }
    else {
        "$gapToTarget poena iznad ciljnog raspona 0-29."
    }

    $topDrivers = @()
    $topAreas = @()
    if ($null -ne $RiskScoreDetails) {
        if ($RiskScoreDetails.PSObject.Properties['RuleScores']) {
            $topDrivers = @($RiskScoreDetails.RuleScores | Sort-Object -Property Contribution -Descending | Select-Object -First 8 | ForEach-Object {
                [pscustomobject][ordered]@{
                    Id = ConvertTo-CompatibleString $_.Id
                    Severity = ConvertTo-CompatibleString $_.Severity
                    Count = [int]$_.Count
                    Contribution = [int]$_.Contribution
                    RuleWeight = [int]$_.RuleMaxPoints
                    Title = ConvertTo-CompatibleString $_.Title
                    RiskAreaName = ConvertTo-CompatibleString $_.RiskAreaName
                    Calculation = ConvertTo-CompatibleString $_.Calculation
                }
            })
        }
        if ($RiskScoreDetails.PSObject.Properties['AreaScores']) {
            $topAreas = @($RiskScoreDetails.AreaScores | Sort-Object -Property Score -Descending | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = ConvertTo-CompatibleString $_.Name
                    Score = [int]$_.Score
                    RawPoints = [int]$_.RawPoints
                    CoverageStatus = ConvertTo-CompatibleString $_.CoverageStatus
                    DominantRuleContribution = [int]$_.DominantRuleContribution
                }
            })
        }
    }

    return [pscustomobject][ordered]@{
        Score = [int]$scoreValue
        BandKey = ConvertTo-CompatibleString $band.Key
        BandLabel = ConvertTo-CompatibleString $band.Label
        BandRange = ConvertTo-CompatibleString $band.Range
        Meaning = ConvertTo-CompatibleString $band.Meaning
        RecommendedAction = ConvertTo-CompatibleString $band.Action
        ScaleDirection = '0 je najbolje; 100 je najgori detektovani rizik.'
        TargetBaselineLabel = 'Ciljni raspon za lokalni Active Directory (0-29)'
        TargetScoreMax = $targetMax
        IdealBaselineLabel = 'Minimalan rizik (0-9)'
        IdealScoreMax = $idealMax
        GapToTarget = [int]$gapToTarget
        GapToIdeal = [int][math]::Max(0, $scoreValue - $idealMax)
        BaselineComparison = ConvertTo-CompatibleString $baselineComparison
        Legend = $bands
        TopDrivers = $topDrivers
        TopAreas = $topAreas
        Notes = @()
    }
}

function Get-OverallRiskScore {
    param(
        [int]$Critical,
        [int]$High,
        [int]$Medium,
        [int]$Low,
        [int]$Info
    )

    # Legacy compatibility only. Production scoring requires finding IDs and Get-RiskScoreAnalysis.
    if ($Critical -gt 0) { return [int][math]::Min(100, (70 + (($Critical - 1) * 10))) }
    if ($High -gt 0) { return [int][math]::Min(69, (30 + ($High * 10))) }
    if ($Medium -gt 0) { return [int][math]::Min(49, (10 + ($Medium * 3))) }
    if ($Low -gt 0) { return [int][math]::Min(29, $Low) }
    return 0
}

function New-SecurityFrameworkReference {
    param(
        [string]$Framework,
        [string]$Id,
        [string]$Name,
        [string]$Url,
        [ValidateSet('Direct', 'Related', 'Contextual')]
        [string]$Relationship,
        [string]$Note
    )

    return [pscustomobject][ordered]@{
        Framework = ConvertTo-CompatibleString $Framework
        Id = ConvertTo-CompatibleString $Id
        Name = ConvertTo-CompatibleString $Name
        Url = ConvertTo-CompatibleString $Url
        Relationship = ConvertTo-CompatibleString $Relationship
        Note = ConvertTo-CompatibleString $Note
    }
}

function Get-SecurityFrameworkReferenceCatalog {
    if ($null -ne $script:SecurityFrameworkReferenceCatalog) {
        return $script:SecurityFrameworkReferenceCatalog
    }

    $catalog = @{
        'AD-POLICY-001' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1110' -Name 'Brute Force' -Url 'https://attack.mitre.org/techniques/T1110/' -Relationship 'Contextual' -Note 'Slaba minimalna duzina povecava izvodljivost password guessing/cracking napada; nalaz nije dokaz napada.')
        )
        'AD-POLICY-003' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1110' -Name 'Brute Force' -Url 'https://attack.mitre.org/techniques/T1110/' -Relationship 'Contextual' -Note 'Odsustvo lockout/rate limiting kontrole olaksava ponavljane pokusaje autentikacije.')
        )
        'AD-PRIV-004' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1098' -Name 'Account Manipulation' -Url 'https://attack.mitre.org/techniques/T1098/' -Relationship 'Contextual' -Note 'Neocekivano privilegovano clanstvo moze biti posljedica ili cilj account manipulation aktivnosti.')
        )
        'AD-USER-001' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1078' -Name 'Valid Accounts' -Url 'https://attack.mitre.org/techniques/T1078/' -Relationship 'Contextual' -Note 'Omogucen Guest nalog predstavlja dodatnu valid-account povrsinu; nalaz ne potvrduje upotrebu naloga.')
        )
        'AD-USER-002' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1558.001' -Name 'Golden Ticket' -Url 'https://attack.mitre.org/techniques/T1558/001/' -Relationship 'Contextual' -Note 'Stara krbtgt lozinka produzava moguci period upotrebe ranije kompromitovanog hash-a. Starost sama nije dokaz Golden Ticket napada.')
        )
        'AD-USER-006' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1558.004' -Name 'AS-REP Roasting' -Url 'https://attack.mitre.org/techniques/T1558/004/' -Relationship 'Direct' -Note 'Nalog bez Kerberos preauthentication je direktno izlozen AS-REP roasting tehnici.')
        )
        'AD-USER-007' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1558.003' -Name 'Kerberoasting' -Url 'https://attack.mitre.org/techniques/T1558/003/' -Relationship 'Direct' -Note 'Korisnicki nalog sa SPN-om moze biti cilj Kerberoasting tehnike.')
        )
        'AD-USER-008' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1550.003' -Name 'Pass the Ticket' -Url 'https://attack.mitre.org/techniques/T1550/003/' -Relationship 'Related' -Note 'Unconstrained delegation moze izloziti Kerberos tikete koji se zatim mogu zloupotrijebiti.')
        )
        'AD-USER-009' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1550.003' -Name 'Pass the Ticket' -Url 'https://attack.mitre.org/techniques/T1550/003/' -Relationship 'Related' -Note 'Delegacijska konfiguracija moze prosiriti mogucnost zloupotrebe Kerberos autentikacijskog materijala.')
        )
        'AD-USER-013' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1134.005' -Name 'SID-History Injection' -Url 'https://attack.mitre.org/techniques/T1134/005/' -Relationship 'Related' -Note 'Legitimni SIDHistory nije automatski napad, ali neocekivani ili privilegovani SID moze omoguciti eskalaciju.')
        )
        'AD-COMP-004' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1550.003' -Name 'Pass the Ticket' -Url 'https://attack.mitre.org/techniques/T1550/003/' -Relationship 'Related' -Note 'Unconstrained delegation na racunaru moze izloziti Kerberos tikete.')
        )
        'AD-COMP-005' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1550.003' -Name 'Pass the Ticket' -Url 'https://attack.mitre.org/techniques/T1550/003/' -Relationship 'Related' -Note 'Protocol transition delegacija moze prosiriti putanje zloupotrebe Kerberos autentikacije.')
        )
        'AD-TRUST-002' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1134.005' -Name 'SID-History Injection' -Url 'https://attack.mitre.org/techniques/T1134/005/' -Relationship 'Related' -Note 'SID filtering je mitigacija protiv prenosa neocekivanih SIDHistory vrijednosti preko trust granice.')
        )
        'AD-TRUST-003' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1550.003' -Name 'Pass the Ticket' -Url 'https://attack.mitre.org/techniques/T1550/003/' -Relationship 'Related' -Note 'TGT delegation preko trusta povecava mogucnost prenosa i zloupotrebe Kerberos tiketa.')
        )
        'AD-AUTH-001' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1110' -Name 'Brute Force' -Url 'https://attack.mitre.org/techniques/T1110/' -Relationship 'Contextual' -Note 'Povecani failed logini mogu odgovarati brute-force ili password-spraying aktivnosti, ali zahtijevaju korelaciju.')
        )
        'AD-AUTH-002' = @(
            (New-SecurityFrameworkReference -Framework 'MITRE ATT&CK' -Id 'T1110' -Name 'Brute Force' -Url 'https://attack.mitre.org/techniques/T1110/' -Relationship 'Contextual' -Note 'Ponavljani failed logini na nalogu zahtijevaju korelaciju sa izvorima i obrascem autentikacije.')
        )
    }

    $script:SecurityFrameworkReferenceCatalog = $catalog
    return $script:SecurityFrameworkReferenceCatalog
}

function Get-SecurityFrameworkReferences {
    param([string]$FindingId)

    $catalog = Get-SecurityFrameworkReferenceCatalog
    if ($catalog.ContainsKey($FindingId)) {
        return @($catalog[$FindingId])
    }
    return @()
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [string]$AffectedObject = '',

        [string]$ObjectType = '',

        [object]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation
    )

    try {
        $compatibleEvidence = ConvertTo-CompatibleObject -InputObject $Evidence
    }
    catch {
        $compatibleEvidence = [ordered]@{
            EvidenceConversionError = ConvertTo-CompatibleString $_.Exception.Message
            RawEvidence             = ConvertTo-CompatibleString $Evidence
        }
    }

    $findingShell = [pscustomobject]@{
        Id       = $Id
        Severity = $Severity
        Category = $Category
        Evidence = $compatibleEvidence
    }
    $ruleMetadata = Get-FindingRuleMetadata -Id $Id -Severity $Severity -Category $Category -Finding $findingShell

    $script:Findings.Add([pscustomobject][ordered]@{
        Id             = $Id
        Severity       = $Severity
        Score          = Get-SeverityScore -Severity $Severity
        RiskArea       = ConvertTo-CompatibleString $ruleMetadata.RiskArea
        RiskAreaName   = Get-RiskAreaLabel -RiskArea $ruleMetadata.RiskArea
        ScoreCategory  = ConvertTo-CompatibleString $ruleMetadata.ScoreCategory
        RuleModel      = ConvertTo-CompatibleString $ruleMetadata.RuleModel
        ScoringMethod  = ConvertTo-CompatibleString $ruleMetadata.ScoringMethod
        RuleWeight     = [int]$ruleMetadata.RuleWeight
        RuleMaxPoints  = [int]$ruleMetadata.RuleMaxPoints
        Category       = ConvertTo-CompatibleString $Category
        Title          = ConvertTo-CompatibleString $Title
        AffectedObject = ConvertTo-CompatibleString $AffectedObject
        ObjectType     = ConvertTo-CompatibleString $ObjectType
        Evidence       = $compatibleEvidence
        EvidenceText   = ConvertTo-EvidenceText -Evidence $compatibleEvidence
        Recommendation = ConvertTo-CompatibleString $Recommendation
        FrameworkReferences = @(Get-SecurityFrameworkReferences -FindingId $Id)
    }) | Out-Null
}

function Add-CollectionWarning {
    param(
        [string]$Message,
        [object]$Detail
    )

    try {
        $detailText = ConvertTo-EvidenceText -Evidence $Detail
    }
    catch {
        $detailText = ConvertTo-CompatibleString $Detail
    }

    $script:CollectionWarnings.Add([pscustomobject][ordered]@{
        Message = ConvertTo-CompatibleString $Message
        Detail  = $detailText
    }) | Out-Null
}

function Get-EventDataMap {
    param(
        [object]$EventRecord
    )

    $map = [ordered]@{}
    try {
        [xml]$eventXml = $EventRecord.ToXml()
        foreach ($data in @($eventXml.Event.EventData.Data)) {
            $name = ConvertTo-CompatibleString $data.Name
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }
            $map[$name] = ConvertTo-CompatibleString $data.'#text'
        }
    }
    catch {
    }

    return $map
}

function Get-EventDataValue {
    param(
        [object]$Data,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($null -ne $Data -and $Data.Contains($name) -and -not [string]::IsNullOrWhiteSpace([string]$Data[$name]) -and [string]$Data[$name] -ne '-') {
            return (ConvertTo-CompatibleString $Data[$name])
        }
    }

    return ''
}

function Format-FailedLoginAccount {
    param(
        [string]$Domain,
        [string]$UserName
    )

    $user = (ConvertTo-CompatibleString $UserName).Trim()
    $domainName = (ConvertTo-CompatibleString $Domain).Trim()

    if ([string]::IsNullOrWhiteSpace($user) -or $user -eq '-') {
        return 'Unknown'
    }

    if ($user -like '*\*' -or [string]::IsNullOrWhiteSpace($domainName) -or $domainName -eq '-') {
        return $user
    }

    return "$domainName\$user"
}

function ConvertFrom-FailedLoginEvent {
    param(
        [object]$EventRecord,
        [string]$DomainController
    )

    $data = Get-EventDataMap -EventRecord $EventRecord
    $eventId = [int]$EventRecord.Id

    $eventName = switch ($eventId) {
        4625 { 'Failed logon' }
        4771 { 'Kerberos pre-auth failed' }
        4776 { 'NTLM credential validation failed' }
        default { 'Failed authentication' }
    }

    $targetUser = Get-EventDataValue -Data $data -Names @('TargetUserName', 'AccountName')
    $targetDomain = Get-EventDataValue -Data $data -Names @('TargetDomainName', 'TargetDomain')
    $account = Format-FailedLoginAccount -Domain $targetDomain -UserName $targetUser
    $source = Get-EventDataValue -Data $data -Names @('IpAddress', 'ClientAddress', 'WorkstationName', 'Workstation')
    $workstation = Get-EventDataValue -Data $data -Names @('WorkstationName', 'Workstation')
    $status = Get-EventDataValue -Data $data -Names @('Status')
    $subStatus = Get-EventDataValue -Data $data -Names @('SubStatus')
    $failureReason = Get-EventDataValue -Data $data -Names @('FailureReason')
    $logonType = Get-EventDataValue -Data $data -Names @('LogonType')
    $authPackage = Get-EventDataValue -Data $data -Names @('AuthenticationPackageName', 'PackageName')

    if ($eventId -eq 4776 -and $status -eq '0x0') {
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($source)) {
        $source = 'Unknown'
    }

    return [pscustomobject][ordered]@{
        DomainController = ConvertTo-CompatibleString $DomainController
        EventId          = $eventId
        EventName        = $eventName
        TimeCreated      = $EventRecord.TimeCreated
        Account          = $account
        Source           = ConvertTo-CompatibleString $source
        Workstation      = ConvertTo-CompatibleString $workstation
        LogonType        = ConvertTo-CompatibleString $logonType
        Status           = ConvertTo-CompatibleString $status
        SubStatus        = ConvertTo-CompatibleString $subStatus
        FailureReason    = ConvertTo-CompatibleString $failureReason
        AuthPackage      = ConvertTo-CompatibleString $authPackage
    }
}

function New-FailedLoginGroupSummary {
    param(
        [object[]]$Events,
        [string]$PropertyName,
        [int]$First = 10
    )

    $summaries = New-Object System.Collections.Generic.List[object]
    $groups = @($Events |
        Where-Object {
            $property = $_.PSObject.Properties[$PropertyName]
            $null -ne $property -and -not [string]::IsNullOrWhiteSpace((ConvertTo-CompatibleString $property.Value))
        } |
        Group-Object -Property $PropertyName |
        Sort-Object -Property Count -Descending |
        Select-Object -First $First)

    foreach ($group in $groups) {
        $groupEvents = @($group.Group)
        $lastEvent = @($groupEvents | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1)
        $lastSeen = if ($lastEvent.Count -gt 0 -and $null -ne $lastEvent[0].TimeCreated) { ([datetime]$lastEvent[0].TimeCreated).ToString('s') } else { '' }

        $summaries.Add([pscustomobject][ordered]@{
            Name              = ConvertTo-CompatibleString $group.Name
            Count             = [int]$group.Count
            Sources           = @($groupEvents | Select-Object -ExpandProperty Source -Unique | Select-Object -First 8)
            DomainControllers = @($groupEvents | Select-Object -ExpandProperty DomainController -Unique | Select-Object -First 8)
            LastSeen          = $lastSeen
        }) | Out-Null
    }

    return @($summaries.ToArray())
}

function Get-FailedLoginAudit {
    param(
        [object[]]$DomainControllers,
        [datetime]$StartTime,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$MaxEventsPerDc = 1000,
        [int]$QueryTimeoutSeconds = 20
    )

    $eventsList = New-Object System.Collections.Generic.List[object]
    $dcStats = New-Object System.Collections.Generic.List[object]
    $maxEvents = [math]::Max(1, $MaxEventsPerDc)
    $timeoutSeconds = [math]::Max(5, $QueryTimeoutSeconds)
    $jobs = New-Object System.Collections.Generic.List[object]

    $eventQueryScript = {
        param(
            [string]$ComputerName,
            [datetime]$QueryStartTime,
            [int]$QueryMaxEvents,
            [System.Management.Automation.PSCredential]$QueryCredential
        )

        function Convert-JobString {
            param([AllowNull()][object]$Value)
            if ($null -eq $Value) { return '' }
            return [string]$Value
        }

        function Get-JobEventDataMap {
            param([object]$EventRecord)
            $map = [ordered]@{}
            try {
                [xml]$eventXml = $EventRecord.ToXml()
                foreach ($data in @($eventXml.Event.EventData.Data)) {
                    $name = Convert-JobString $data.Name
                    if (-not [string]::IsNullOrWhiteSpace($name)) {
                        $map[$name] = Convert-JobString $data.'#text'
                    }
                }
            }
            catch {
            }
            return $map
        }

        function Get-JobEventDataValue {
            param(
                [object]$Data,
                [string[]]$Names
            )

            foreach ($name in $Names) {
                if ($null -ne $Data -and $Data.Contains($name) -and -not [string]::IsNullOrWhiteSpace([string]$Data[$name]) -and [string]$Data[$name] -ne '-') {
                    return (Convert-JobString $Data[$name])
                }
            }

            return ''
        }

        function Format-JobFailedLoginAccount {
            param(
                [string]$Domain,
                [string]$UserName
            )

            $user = (Convert-JobString $UserName).Trim()
            $domainName = (Convert-JobString $Domain).Trim()
            if ([string]::IsNullOrWhiteSpace($user) -or $user -eq '-') {
                return 'Unknown'
            }
            if ($user -like '*\*' -or [string]::IsNullOrWhiteSpace($domainName) -or $domainName -eq '-') {
                return $user
            }
            return "$domainName\$user"
        }

        function Convert-JobFailedLoginEvent {
            param(
                [object]$EventRecord,
                [string]$DomainController
            )

            $data = Get-JobEventDataMap -EventRecord $EventRecord
            $eventId = [int]$EventRecord.Id
            $eventName = switch ($eventId) {
                4625 { 'Failed logon' }
                4771 { 'Kerberos pre-auth failed' }
                4776 { 'NTLM credential validation failed' }
                default { 'Failed authentication' }
            }
            $targetUser = Get-JobEventDataValue -Data $data -Names @('TargetUserName', 'AccountName')
            $targetDomain = Get-JobEventDataValue -Data $data -Names @('TargetDomainName', 'TargetDomain')
            $source = Get-JobEventDataValue -Data $data -Names @('IpAddress', 'ClientAddress', 'WorkstationName', 'Workstation')
            $status = Get-JobEventDataValue -Data $data -Names @('Status')
            if ([string]::IsNullOrWhiteSpace($source)) {
                $source = 'Unknown'
            }
            if ($eventId -eq 4776 -and $status -eq '0x0') {
                return $null
            }

            return [pscustomobject][ordered]@{
                RecordType       = 'Event'
                DomainController = Convert-JobString $DomainController
                EventId          = $eventId
                EventName        = $eventName
                TimeCreated      = $EventRecord.TimeCreated
                Account          = Format-JobFailedLoginAccount -Domain $targetDomain -UserName $targetUser
                Source           = Convert-JobString $source
                Workstation      = Get-JobEventDataValue -Data $data -Names @('WorkstationName', 'Workstation')
                LogonType        = Get-JobEventDataValue -Data $data -Names @('LogonType')
                Status           = $status
                SubStatus        = Get-JobEventDataValue -Data $data -Names @('SubStatus')
                FailureReason    = Get-JobEventDataValue -Data $data -Names @('FailureReason')
                AuthPackage      = Get-JobEventDataValue -Data $data -Names @('AuthenticationPackageName', 'PackageName')
            }
        }

        $results = New-Object System.Collections.Generic.List[object]
        $queryStartUtc = $QueryStartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $failedLoginXPath = "*[System[(EventID=4625 or EventID=4771 or EventID=4776) and TimeCreated[@SystemTime >= '$queryStartUtc']]] and *[EventData[Data[@Name='Status'] != '0x0']]"
        $eventParams = @{
            LogName      = 'Security'
            FilterXPath  = $failedLoginXPath
            ComputerName = $ComputerName
            MaxEvents    = $QueryMaxEvents
            ErrorAction  = 'Stop'
        }
        if ($null -ne $QueryCredential) {
            $eventParams.Credential = $QueryCredential
        }

        try {
            $events = @(Get-WinEvent @eventParams)
            $parsed = 0
            foreach ($event in $events) {
                $observation = Convert-JobFailedLoginEvent -EventRecord $event -DomainController $ComputerName
                if ($null -ne $observation) {
                    $results.Add($observation) | Out-Null
                    $parsed++
                }
            }
            $results.Add([pscustomobject][ordered]@{
                RecordType       = 'Stats'
                DomainController = $ComputerName
                Status           = 'OK'
                EventsRead       = [int]$events.Count
                EventsParsed     = [int]$parsed
                ReachedMaxEvents = [bool]($events.Count -ge $QueryMaxEvents)
            }) | Out-Null
        }
        catch {
            $results.Add([pscustomobject][ordered]@{
                RecordType       = 'Stats'
                DomainController = $ComputerName
                Status           = 'Failed'
                EventsRead       = 0
                EventsParsed     = 0
                ReachedMaxEvents = $false
                Error            = Convert-JobString $_.Exception.Message
            }) | Out-Null
        }

        return @($results.ToArray())
    }

    foreach ($dc in @($DomainControllers)) {
        $dcName = ConvertTo-CompatibleString $dc.HostName
        if ([string]::IsNullOrWhiteSpace($dcName)) {
            $dcName = ConvertTo-CompatibleString $dc.Name
        }
        if ([string]::IsNullOrWhiteSpace($dcName)) {
            continue
        }

        try {
            $job = Start-Job -ScriptBlock $eventQueryScript -ArgumentList $dcName, $StartTime, $maxEvents, $Credential
            $jobs.Add([pscustomobject][ordered]@{
                DomainController = $dcName
                Job              = $job
            }) | Out-Null
        }
        catch {
            Add-CollectionWarning -Message "Nije moguce pokrenuti failed login query za DC: $dcName" -Detail $_.Exception.Message
            $dcStats.Add([pscustomobject][ordered]@{
                DomainController = $dcName
                Status           = 'JobStartFailed'
                EventsRead       = 0
                EventsParsed     = 0
                ReachedMaxEvents = $false
                Error            = ConvertTo-CompatibleString $_.Exception.Message
            }) | Out-Null
        }
    }

    $pending = @($jobs.ToArray())
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
        $pendingJobs = @($pending | ForEach-Object { $_.Job })
        if ($pendingJobs.Count -eq 0) {
            break
        }

        $completedJobs = @(Wait-Job -Job $pendingJobs -Any -Timeout 1)
        if ($completedJobs.Count -eq 0) {
            continue
        }

        foreach ($completedJob in $completedJobs) {
            $jobInfo = @($pending | Where-Object { $_.Job.Id -eq $completedJob.Id } | Select-Object -First 1)
            $dcName = if ($jobInfo.Count -gt 0) { $jobInfo[0].DomainController } else { "Job-$($completedJob.Id)" }
            $records = @(Receive-Job -Job $completedJob -ErrorAction SilentlyContinue)
            $hasStats = $false

            foreach ($record in $records) {
                $recordType = ConvertTo-CompatibleString $record.RecordType
                if ($recordType -eq 'Event') {
                    $eventsList.Add([pscustomobject][ordered]@{
                        DomainController = ConvertTo-CompatibleString $record.DomainController
                        EventId          = [int]$record.EventId
                        EventName        = ConvertTo-CompatibleString $record.EventName
                        TimeCreated      = $record.TimeCreated
                        Account          = ConvertTo-CompatibleString $record.Account
                        Source           = ConvertTo-CompatibleString $record.Source
                        Workstation      = ConvertTo-CompatibleString $record.Workstation
                        LogonType        = ConvertTo-CompatibleString $record.LogonType
                        Status           = ConvertTo-CompatibleString $record.Status
                        SubStatus        = ConvertTo-CompatibleString $record.SubStatus
                        FailureReason    = ConvertTo-CompatibleString $record.FailureReason
                        AuthPackage      = ConvertTo-CompatibleString $record.AuthPackage
                    }) | Out-Null
                }
                elseif ($recordType -eq 'Stats') {
                    $hasStats = $true
                    $status = ConvertTo-CompatibleString $record.Status
                    if ($status -ne 'OK') {
                        Add-CollectionWarning -Message "Nije moguce procitati failed login evente sa DC-a: $dcName" -Detail $record.Error
                    }

                    $dcStats.Add([pscustomobject][ordered]@{
                        DomainController = ConvertTo-CompatibleString $record.DomainController
                        Status           = $status
                        EventsRead       = [int]$record.EventsRead
                        EventsParsed     = [int]$record.EventsParsed
                        ReachedMaxEvents = [bool]$record.ReachedMaxEvents
                        Error            = ConvertTo-CompatibleString $record.Error
                    }) | Out-Null
                }
            }

            if (-not $hasStats) {
                Add-CollectionWarning -Message "Failed login query nije vratio status za DC: $dcName" -Detail 'Job je zavrsio bez status zapisa.'
                $dcStats.Add([pscustomobject][ordered]@{
                    DomainController = $dcName
                    Status           = 'NoStatus'
                    EventsRead       = 0
                    EventsParsed     = 0
                    ReachedMaxEvents = $false
                    Error            = 'Job je zavrsio bez status zapisa.'
                }) | Out-Null
            }

            Remove-Job -Job $completedJob -Force -ErrorAction SilentlyContinue
            $pending = @($pending | Where-Object { $_.Job.Id -ne $completedJob.Id })
        }
    }

    foreach ($jobInfo in @($pending)) {
        Stop-Job -Job $jobInfo.Job -ErrorAction SilentlyContinue
        Remove-Job -Job $jobInfo.Job -Force -ErrorAction SilentlyContinue
        Add-CollectionWarning -Message "Failed login query timeout za DC: $($jobInfo.DomainController)" -Detail "Prekoracen limit od $timeoutSeconds sekundi. Scan nastavlja bez tih eventa."
        $dcStats.Add([pscustomobject][ordered]@{
            DomainController = $jobInfo.DomainController
            Status           = 'Timeout'
            EventsRead       = 0
            EventsParsed     = 0
            ReachedMaxEvents = $false
            Error            = "Timeout after $timeoutSeconds seconds"
        }) | Out-Null
    }

    return [pscustomobject][ordered]@{
        Events            = @($eventsList.ToArray())
        DomainControllers = @($dcStats.ToArray())
    }
}

function Set-ScanStage {
    param([string]$Name)
    $script:CurrentScanStage = $Name
    Write-Verbose $Name
}

function ConvertTo-SidText {
    param(
        [AllowNull()]
        [object]$SidObject
    )

    if ($null -eq $SidObject) {
        return $null
    }

    if ($SidObject -is [string] -and -not [string]::IsNullOrWhiteSpace($SidObject)) {
        return $SidObject
    }

    if ($SidObject -is [byte[]]) {
        try {
            return ([System.Security.Principal.SecurityIdentifier]::new($SidObject, 0)).Value
        }
        catch {
            return $null
        }
    }

    foreach ($propertyName in @('Value', 'Sid', 'SID', 'ObjectSid', 'objectSid')) {
        $property = $SidObject.PSObject.Properties[$propertyName]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }

    $sidText = [string]$SidObject
    if ($sidText -match '(S-\d(?:-\d+)+)') {
        return $Matches[1]
    }

    return $null
}

function Get-DomainSidValue {
    param(
        [object]$Domain
    )

    $domainSid = ConvertTo-SidText -SidObject $Domain.DomainSID
    if (-not [string]::IsNullOrWhiteSpace($domainSid)) {
        return $domainSid
    }

    try {
        $domainObject = Get-ADObject @script:AdParams -Identity $Domain.DistinguishedName -Properties objectSid -ErrorAction Stop
        $domainSid = ConvertTo-SidText -SidObject $domainObject.objectSid
        if (-not [string]::IsNullOrWhiteSpace($domainSid)) {
            return $domainSid
        }
    }
    catch {
        Add-CollectionWarning -Message 'Nije moguce procitati SID domene preko AD objekta domene.' -Detail $_.Exception.Message
    }

    throw 'Nije moguce odrediti SID domene. Pokrenuti skriptu u Windows PowerShell 5.1 ili navesti ispravan domain controller preko -Server parametra.'
}

function Get-DaysSince {
    param(
        [AllowNull()]
        [object]$Date
    )

    if ($null -eq $Date) {
        return $null
    }

    if ($Date -is [string] -and [string]::IsNullOrWhiteSpace($Date)) {
        return $null
    }

    try {
        $dateValue = [datetime]$Date
        return [int]((Get-Date) - $dateValue).TotalDays
    }
    catch {
        Add-CollectionWarning -Message 'Nije moguce konvertovati AD datum.' -Detail @{
            Value = [string]$Date
            Error = $_.Exception.Message
        }
        return $null
    }
}

function Test-PatternMatch {
    param(
        [string]$Value,
        [object[]]$Patterns
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $null -eq $Patterns -or $Patterns.Count -eq 0) {
        return $false
    }

    foreach ($pattern in $Patterns) {
        if ($Value -like [string]$pattern) {
            return $true
        }
    }

    return $false
}

function Get-ConfigPropertyValue {
    param(
        [object]$Object,
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-ConfigArray {
    param(
        [string]$PropertyName
    )

    $value = Get-ConfigPropertyValue -Object $script:Config -PropertyName $PropertyName
    if ($null -eq $value) {
        return @()
    }

    return @($value)
}

function Get-GroupConfigPatterns {
    param(
        [string]$SectionName,
        [string]$GroupName
    )

    $section = Get-ConfigPropertyValue -Object $script:Config -PropertyName $SectionName
    if ($null -eq $section) {
        return @()
    }

    $value = Get-ConfigPropertyValue -Object $section -PropertyName $GroupName
    if ($null -eq $value) {
        return @()
    }

    return @($value)
}

function Test-IgnoredSamAccountName {
    param(
        [string]$SamAccountName
    )

    $patterns = Get-ConfigArray -PropertyName 'IgnoredSamAccountNamePatterns'
    return (Test-PatternMatch -Value $SamAccountName -Patterns $patterns)
}

function Get-PrincipalDisplayName {
    param(
        [object]$Principal,
        [string]$NetBIOSName
    )

    if ($null -eq $Principal) {
        return ''
    }

    if ($Principal.PSObject.Properties['SamAccountName'] -and -not [string]::IsNullOrWhiteSpace($Principal.SamAccountName)) {
        return "$NetBIOSName\$($Principal.SamAccountName)"
    }

    if ($Principal.PSObject.Properties['Name'] -and -not [string]::IsNullOrWhiteSpace($Principal.Name)) {
        return $Principal.Name
    }

    if ($Principal.PSObject.Properties['DistinguishedName']) {
        return $Principal.DistinguishedName
    }

    return [string]$Principal
}

function Get-KnownUserForPrincipal {
    param(
        [object]$Principal,
        [hashtable]$UsersByDn
    )

    if ($null -eq $Principal -or $null -eq $UsersByDn -or -not $Principal.PSObject.Properties['DistinguishedName']) {
        return $null
    }

    $dn = [string]$Principal.DistinguishedName
    if ([string]::IsNullOrWhiteSpace($dn) -or -not $UsersByDn.ContainsKey($dn)) {
        return $null
    }

    return $UsersByDn[$dn]
}

function Test-PrivilegedSidValue {
    param(
        [AllowNull()]
        [object]$SidValue
    )

    $sidText = ConvertTo-SidText -SidObject $SidValue
    if ([string]::IsNullOrWhiteSpace($sidText)) {
        return $false
    }

    if ($sidText -match '^S-1-5-32-(544|548|549|550|551|552)$') {
        return $true
    }

    return ($sidText -match '-(512|518|519|520)$')
}

function Get-ADGroupSafe {
    param(
        [string]$Identity,
        [string]$DisplayName
    )

    try {
        return Get-ADGroup @script:AdParams -Identity $Identity -Properties Members, DistinguishedName, Name, SID -ErrorAction Stop
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
            try {
                return Get-ADGroup @script:AdParams -Filter "Name -eq '$DisplayName'" -Properties Members, DistinguishedName, Name, SID -ErrorAction Stop
            }
            catch {
                return $null
            }
        }

        return $null
    }
}

function Get-ADGroupMembersSafe {
    param(
        [object]$Group
    )

    if ($null -eq $Group) {
        return @()
    }

    try {
        return @(Get-ADGroupMember @script:AdParams -Identity $Group.DistinguishedName -Recursive -ErrorAction Stop)
    }
    catch {
        Add-CollectionWarning -Message "Nije moguce enumerisati rekurzivno clanstvo za grupu '$($Group.Name)'." -Detail $_.Exception.Message
        return @()
    }
}

function Get-ADGroupDirectMembersSafe {
    param(
        [object]$Group
    )

    if ($null -eq $Group) {
        return @()
    }

    try {
        return @(Get-ADGroupMember @script:AdParams -Identity $Group.DistinguishedName -ErrorAction Stop)
    }
    catch {
        Add-CollectionWarning -Message "Nije moguce enumerisati direktno clanstvo za grupu '$($Group.Name)'." -Detail $_.Exception.Message
        return @()
    }
}

function Get-TrustPropertyValue {
    param(
        [AllowNull()]
        [object]$Trust,
        [string]$PropertyName
    )

    if ($null -eq $Trust) {
        return $null
    }

    $property = $Trust.PSObject.Properties[$PropertyName]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Get-TrustDirectionCode {
    param(
        [object]$Trust
    )

    $rawDirection = Get-TrustPropertyValue -Trust $Trust -PropertyName 'trustDirection'
    if ($null -ne $rawDirection -and (ConvertTo-CompatibleString $rawDirection) -match '^\d+$') {
        return [int]$rawDirection
    }

    switch -Regex ((ConvertTo-CompatibleString (Get-TrustPropertyValue -Trust $Trust -PropertyName 'Direction'))) {
        '^Inbound$' { return 1 }
        '^Outbound$' { return 2 }
        '^Bidirectional$' { return 3 }
        default { return 0 }
    }
}

function Get-TrustAttributesValue {
    param(
        [object]$Trust
    )

    $rawAttributes = Get-TrustPropertyValue -Trust $Trust -PropertyName 'TrustAttributes'
    if ($null -ne $rawAttributes -and (ConvertTo-CompatibleString $rawAttributes) -match '^\d+$') {
        return [int64]$rawAttributes
    }

    $attributes = [int64]0
    if ((Get-TrustPropertyValue -Trust $Trust -PropertyName 'IntraForest') -eq $true) { $attributes = $attributes -bor 0x20 }
    if ((Get-TrustPropertyValue -Trust $Trust -PropertyName 'ForestTransitive') -eq $true) { $attributes = $attributes -bor 0x08 }
    if ((Get-TrustPropertyValue -Trust $Trust -PropertyName 'SIDFilteringQuarantined') -eq $true) { $attributes = $attributes -bor 0x04 }
    if ((Get-TrustPropertyValue -Trust $Trust -PropertyName 'SIDFilteringForestAware') -eq $true) { $attributes = $attributes -bor 0x40 }
    if ((Get-TrustPropertyValue -Trust $Trust -PropertyName 'TGTDelegation') -eq $true) { $attributes = $attributes -bor 0x800 }
    return $attributes
}

function Test-TrustSidFilteringDisabled {
    param(
        [object]$Trust
    )

    $direction = Get-TrustDirectionCode -Trust $Trust
    $attributes = Get-TrustAttributesValue -Trust $Trust

    if ($direction -in @(0, 1)) {
        return $false
    }
    if (($attributes -band 0x20) -ne 0 -or ($attributes -band 0x400) -ne 0 -or
        ($attributes -band 0x00400000) -ne 0 -or ($attributes -band 0x00800000) -ne 0) {
        return $false
    }

    if (($attributes -band 0x08) -ne 0) {
        return (($attributes -band 0x04) -eq 0 -and ($attributes -band 0x40) -ne 0)
    }

    return (($attributes -band 0x04) -eq 0)
}

function Test-TrustTgtDelegationEnabled {
    param(
        [object]$Trust
    )

    $direction = Get-TrustDirectionCode -Trust $Trust
    $attributes = Get-TrustAttributesValue -Trust $Trust
    if ($direction -in @(0, 2) -or ($attributes -band 0x08) -eq 0) {
        return $false
    }

    return (($attributes -band 0x200) -eq 0 -and ($attributes -band 0x800) -ne 0)
}

function Get-TrustPartnerName {
    param(
        [object]$Trust
    )

    foreach ($propertyName in @('Target', 'Name', 'DistinguishedName')) {
        $value = ConvertTo-CompatibleString (Get-TrustPropertyValue -Trust $Trust -PropertyName $propertyName)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return 'Unknown trust'
}

function Test-DelegationTargetsDomainController {
    param(
        [object[]]$Targets,
        [hashtable]$DomainControllerHostNames
    )

    foreach ($target in @($Targets)) {
        $targetText = (ConvertTo-CompatibleString $target).Trim()
        if ($targetText -notmatch '^[^/]+/([^/:]+)') {
            continue
        }

        $targetHost = $Matches[1].ToLowerInvariant()
        $targetShort = @($targetHost -split '\.')[0]
        foreach ($dcHost in @($DomainControllerHostNames.Keys)) {
            $dcText = (ConvertTo-CompatibleString $dcHost).ToLowerInvariant()
            $dcShort = @($dcText -split '\.')[0]
            if ($targetHost -eq $dcText -or $targetShort -eq $dcShort) {
                return $true
            }
        }
    }

    return $false
}

function Test-UnsupportedOperatingSystem {
    param(
        [string]$OperatingSystem
    )

    if ([string]::IsNullOrWhiteSpace($OperatingSystem)) {
        return $null
    }

    if ($OperatingSystem -match 'Windows 10.*(LTSC|LTSB|IoT Enterprise)') {
        return $null
    }

    $highRiskPatterns = @(
        'Windows XP',
        'Windows Vista',
        'Windows 7',
        'Windows 8',
        'Windows Server 2003',
        'Windows Server 2008'
    )

    foreach ($pattern in $highRiskPatterns) {
        if ($OperatingSystem -like "*$pattern*") {
            return [pscustomobject]@{
                Severity = 'High'
                Match    = $pattern
            }
        }
    }

    if ($OperatingSystem -like '*Windows Server 2012*') {
        return [pscustomobject]@{
            Severity = 'Medium'
            Match    = 'Windows Server 2012'
        }
    }

    if ($OperatingSystem -like '*Windows 10*') {
        return [pscustomobject]@{
            Severity = 'Medium'
            Match    = 'Windows 10'
        }
    }

    return $null
}

function Get-UnsupportedOsFindingSeverity {
    param(
        [object]$Computer,
        [object]$OsRisk,
        [bool]$IsDomainController
    )

    if ($null -eq $OsRisk) {
        return $null
    }

    $osText = ConvertTo-CompatibleString $Computer.OperatingSystem
    if ($IsDomainController -or $osText -like '*Server*') {
        return (ConvertTo-CompatibleString $OsRisk.Severity)
    }

    if ((ConvertTo-CompatibleString $OsRisk.Severity) -eq 'High') {
        return 'Medium'
    }

    return (ConvertTo-CompatibleString $OsRisk.Severity)
}

function Select-ReportFindingFields {
    param(
        [object[]]$Findings
    )

    $normalizedFindings = ConvertTo-GuiFindingArray -InputObject $Findings
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($finding in $normalizedFindings) {
        $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
        $rows.Add([pscustomobject][ordered]@{
            Id             = $finding.Id
            Severity       = $finding.Severity
            Score          = Get-SeverityScore -Severity $finding.Severity
            RiskArea       = $metadata.RiskArea
            RiskAreaName   = $metadata.RiskAreaName
            ScoreCategory  = $metadata.ScoreCategory
            RuleModel      = $metadata.RuleModel
            ScoringMethod  = $metadata.ScoringMethod
            RuleWeight     = $metadata.RuleWeight
            RuleMaxPoints  = $metadata.RuleMaxPoints
            Category       = $finding.Category
            Title          = $finding.Title
            AffectedObject = $finding.AffectedObject
            ObjectType     = $finding.ObjectType
            EvidenceText   = $finding.EvidenceText
            Recommendation = $finding.Recommendation
            FrameworkReferences = if ($finding.PSObject.Properties['FrameworkReferences']) { @($finding.FrameworkReferences) } else { @() }
        }) | Out-Null
    }

    return @($rows.ToArray())
}

function Get-SeverityLabel {
    param(
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { return 'Kriticno' }
        'High' { return 'Visoko' }
        'Medium' { return 'Srednje' }
        'Low' { return 'Nisko' }
        'Info' { return 'Info' }
        default { return $Severity }
    }
}

function ConvertTo-HtmlText {
    param(
        [AllowNull()]
        [object]$Value
    )

    Add-Type -AssemblyName System.Web

    if ($null -eq $Value) {
        return ''
    }

    return [System.Web.HttpUtility]::HtmlEncode((ConvertTo-CompatibleString $Value))
}

function New-DonutChartSvg {
    param(
        [hashtable]$Counts,
        [hashtable]$Colors,
        [int]$Size = 220
    )

    $total = 0
    foreach ($value in $Counts.Values) {
        $total += [int]$value
    }

    if ($total -le 0) {
        return "<div class=`"empty-chart`">Nema nalaza za prikaz.</div>"
    }

    $radius = 15.915
    $offset = 25
    $segments = New-Object System.Collections.Generic.List[string]

    foreach ($key in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $count = 0
        if ($Counts.ContainsKey($key)) {
            $count = [int]$Counts[$key]
        }

        if ($count -le 0) {
            continue
        }

        $percent = [math]::Round(($count / $total) * 100, 3)
        $color = if ($Colors.ContainsKey($key)) { $Colors[$key] } else { '#667085' }
        $label = Get-SeverityLabel -Severity $key
        $segments.Add("<circle class=`"donut-segment`" cx=`"21`" cy=`"21`" r=`"$radius`" fill=`"transparent`" stroke=`"$color`" stroke-width=`"8`" stroke-dasharray=`"$percent $([math]::Round(100 - $percent, 3))`" stroke-dashoffset=`"$offset`"><title>$($label): $count</title></circle>") | Out-Null
        $offset -= $percent
    }

    $legend = New-Object System.Collections.Generic.List[string]
    foreach ($key in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $count = if ($Counts.ContainsKey($key)) { [int]$Counts[$key] } else { 0 }
        $color = if ($Colors.ContainsKey($key)) { $Colors[$key] } else { '#667085' }
        $label = Get-SeverityLabel -Severity $key
        $legend.Add("<div class=`"legend-row`"><span class=`"legend-swatch`" style=`"background:$color`"></span><span>$label</span><strong>$count</strong></div>") | Out-Null
    }

    return @"
<div class="donut-wrap">
  <svg width="$Size" height="$Size" viewBox="0 0 42 42" role="img" aria-label="Nalazi po ozbiljnosti">
    <circle cx="21" cy="21" r="$radius" fill="transparent" stroke="#e4e7ec" stroke-width="8"></circle>
    $($segments -join [Environment]::NewLine)
    <circle cx="21" cy="21" r="10" fill="#ffffff"></circle>
    <text x="21" y="20" text-anchor="middle" class="donut-total">$total</text>
    <text x="21" y="25" text-anchor="middle" class="donut-label">nalaza</text>
  </svg>
  <div class="legend">$($legend -join [Environment]::NewLine)</div>
</div>
"@
}

function New-BarListHtml {
    param(
        [object[]]$Items,
        [string]$EmptyText = 'Nema podataka za prikaz.'
    )

    if ($null -eq $Items -or $Items.Count -eq 0) {
        return "<div class=`"empty-chart`">$EmptyText</div>"
    }

    $max = [int](@($Items | Measure-Object -Property Count -Maximum).Maximum)
    if ($max -le 0) {
        $max = 1
    }

    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Items) {
        $name = ConvertTo-HtmlText $item.Name
        $count = [int]$item.Count
        $width = [math]::Max(2, [math]::Round(($count / $max) * 100, 0))
        $rows.Add("<div class=`"bar-row`"><div class=`"bar-label`">$name</div><div class=`"bar-track`"><span style=`"width:$width%`"></span></div><strong>$count</strong></div>") | Out-Null
    }

    return ($rows -join [Environment]::NewLine)
}

function Get-ReportGroupItems {
    param(
        [object[]]$Items,
        [string]$PropertyName,
        [int]$First = 12
    )

    $counts = @{}
    foreach ($item in @($Items)) {
        if ($null -eq $item) {
            continue
        }

        $value = ''
        try {
            $value = ConvertTo-CompatibleString $item.$PropertyName
        }
        catch {
            $value = ''
        }

        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        if (-not $counts.ContainsKey($value)) {
            $counts[$value] = 0
        }
        $counts[$value] = [int]$counts[$value] + 1
    }

    $groups = @()
    foreach ($key in $counts.Keys) {
        $groups += [pscustomobject]@{
            Name = [string]$key
            Count = [int]$counts[$key]
        }
    }

    return @($groups | Sort-Object -Property Count -Descending | Select-Object -First $First)
}

function New-FindingsTableHtml {
    param(
        [object[]]$Findings
    )

    $reportFindings = ConvertTo-GuiFindingArray -InputObject $Findings
    $rows = New-Object System.Collections.Generic.List[string]
    $rows.Add('<table><thead><tr><th>ID</th><th>Maks. bodovi pravila</th><th>Oblast ocjene</th><th>Ozbiljnost</th><th>Kategorija</th><th>Nalaz</th><th>Objekat</th><th>Tip objekta</th><th>Detalji</th><th>Preporuka</th></tr></thead><tbody>') | Out-Null

    if ($reportFindings.Count -eq 0) {
        $rows.Add('<tr><td colspan="10">Nema nalaza za prikaz.</td></tr>') | Out-Null
    }

    foreach ($finding in @($reportFindings | Sort-Object -Property Score -Descending)) {
        $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
        $id = ConvertTo-HtmlText $finding.Id
        $score = ConvertTo-HtmlText $metadata.RuleWeight
        $riskArea = ConvertTo-HtmlText $metadata.RiskAreaName
        $severityLabel = ConvertTo-HtmlText (Get-SeverityLabel -Severity $finding.Severity)
        $severityClass = ConvertTo-HtmlText $finding.Severity
        $category = ConvertTo-HtmlText $finding.Category
        $title = ConvertTo-HtmlText $finding.Title
        $object = ConvertTo-HtmlText $finding.AffectedObject
        $type = ConvertTo-HtmlText $finding.ObjectType
        $details = ConvertTo-HtmlText $finding.EvidenceText
        $recommendation = ConvertTo-HtmlText $finding.Recommendation
        $rows.Add("<tr><td>$id</td><td>$score</td><td>$riskArea</td><td class=`"$severityClass`">$severityLabel</td><td>$category</td><td>$title</td><td>$object</td><td>$type</td><td>$details</td><td>$recommendation</td></tr>") | Out-Null
    }

    $rows.Add('</tbody></table>') | Out-Null
    return ($rows -join [Environment]::NewLine)
}

function New-SeverityGroupedFindingsHtml {
    param(
        [object[]]$Findings
    )

    $reportFindings = ConvertTo-GuiFindingArray -InputObject $Findings
    if ($null -eq $reportFindings -or $reportFindings.Count -eq 0) {
        return '<p>Nema nalaza.</p>'
    }

    $html = New-Object System.Collections.Generic.List[string]
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $severityFindings = @($reportFindings | Where-Object { (Get-GuiSeverityKey -Value $_.Severity) -eq $severity } | Sort-Object -Property Score -Descending)
        if ($severityFindings.Count -eq 0) {
            continue
        }

        $severityLabel = ConvertTo-HtmlText (Get-SeverityLabel -Severity $severity)
        $severityClass = ConvertTo-HtmlText $severity
        $html.Add("<details><summary><span class=`"$severityClass`">$severityLabel</span> <span>$($severityFindings.Count)</span></summary>") | Out-Null
        $html.Add('<table><thead><tr><th>ID</th><th>Maks. bodovi pravila</th><th>Oblast ocjene</th><th>Kategorija</th><th>Nalaz</th><th>Objekat</th><th>Tip objekta</th><th>Detalji</th><th>Preporuka</th></tr></thead><tbody>') | Out-Null

        foreach ($finding in $severityFindings) {
            $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
            $id = ConvertTo-HtmlText $finding.Id
            $score = ConvertTo-HtmlText $metadata.RuleWeight
            $riskArea = ConvertTo-HtmlText $metadata.RiskAreaName
            $category = ConvertTo-HtmlText $finding.Category
            $title = ConvertTo-HtmlText $finding.Title
            $object = ConvertTo-HtmlText $finding.AffectedObject
            $type = ConvertTo-HtmlText $finding.ObjectType
            $details = ConvertTo-HtmlText $finding.EvidenceText
            $recommendation = ConvertTo-HtmlText $finding.Recommendation
            $html.Add("<tr><td>$id</td><td>$score</td><td>$riskArea</td><td>$category</td><td>$title</td><td>$object</td><td>$type</td><td>$details</td><td>$recommendation</td></tr>") | Out-Null
        }

        $html.Add('</tbody></table></details>') | Out-Null
    }

    if ($html.Count -eq 0) {
        return '<p>Nema nalaza.</p>'
    }

    return ($html -join [Environment]::NewLine)
}

function New-WarningsHtml {
    param(
        [object[]]$Warnings
    )

    if ($null -eq $Warnings -or $Warnings.Count -eq 0) {
        return ''
    }

    $rows = New-Object System.Collections.Generic.List[string]
    $rows.Add('<h2>Upozorenja tokom prikupljanja</h2><table><thead><tr><th>Upozorenje</th><th>Detalji</th></tr></thead><tbody>') | Out-Null
    foreach ($warning in @($Warnings)) {
        $message = ConvertTo-HtmlText $warning.Message
        $detail = ConvertTo-HtmlText $warning.Detail
        $rows.Add("<tr><td>$message</td><td>$detail</td></tr>") | Out-Null
    }
    $rows.Add('</tbody></table>') | Out-Null
    return ($rows -join [Environment]::NewLine)
}

function New-RiskBaselineHtml {
    param(
        [object]$Summary
    )

    if ($null -eq $Summary -or -not $Summary.PSObject.Properties['RiskBaseline'] -or $null -eq $Summary.RiskBaseline) {
        return ''
    }

    $baseline = $Summary.RiskBaseline
    $score = [int]$baseline.Score
    $marker = [math]::Max(0, [math]::Min(100, $score))
    $bandLabel = ConvertTo-HtmlText $baseline.BandLabel
    $bandRange = ConvertTo-HtmlText $baseline.BandRange
    $comparison = ConvertTo-HtmlText $baseline.BaselineComparison
    $scaleDirection = ConvertTo-HtmlText $baseline.ScaleDirection

    $driverRows = New-Object System.Collections.Generic.List[string]
    foreach ($driver in @($baseline.TopDrivers | Select-Object -First 6)) {
        $id = ConvertTo-HtmlText $driver.Id
        $riskArea = ConvertTo-HtmlText $driver.RiskAreaName
        $count = [int]$driver.Count
        $maxPoints = [int]$driver.RuleWeight
        $contribution = [int]$driver.Contribution
        $calculation = ConvertTo-HtmlText $driver.Calculation
        $title = ConvertTo-HtmlText $driver.Title
        $driverRows.Add("<tr><td>$riskArea</td><td>$id</td><td>$count</td><td>$calculation</td><td>$contribution</td><td>$maxPoints</td><td>$title</td></tr>") | Out-Null
    }

    $driverTable = if ($driverRows.Count -gt 0) {
        "<table class=`"compact-table`"><thead><tr><th>Oblast</th><th>ID</th><th>Broj</th><th>Obracun</th><th>Bodovi</th><th>Maks.</th><th>Nalaz</th></tr></thead><tbody>$($driverRows -join [Environment]::NewLine)</tbody></table>"
    }
    else {
        '<div class="empty-chart">Nema drivera ocjene za prikaz.</div>'
    }

    $areaRows = New-Object System.Collections.Generic.List[string]
    foreach ($area in @($baseline.TopAreas)) {
        $areaName = ConvertTo-HtmlText $area.Name
        $areaScore = [int]$area.Score
        $rawPoints = [int]$area.RawPoints
        $coverage = switch (ConvertTo-CompatibleString $area.CoverageStatus) {
            'Complete' { 'Kompletno' }
            'Partial' { 'Djelimicno' }
            'Failed' { 'Neuspjelo' }
            default { ConvertTo-HtmlText $area.CoverageStatus }
        }
        $areaRows.Add("<tr><td>$areaName</td><td><strong>$areaScore</strong></td><td>$rawPoints</td><td>$coverage</td></tr>") | Out-Null
    }
    $areaTable = "<table class=`"compact-table`"><thead><tr><th>Oblast ocjene</th><th>Podskor</th><th>Zbir prije limita</th><th>Pokrivenost</th></tr></thead><tbody>$($areaRows -join [Environment]::NewLine)</tbody></table>"

    $coverageWarning = ''
    if ($Summary.PSObject.Properties['RiskScoreComplete'] -and -not [bool]$Summary.RiskScoreComplete) {
        $coverageWarning = '<p class="High"><strong>NEPOTPUNA PROCJENA:</strong> jedan ili vise izvora nije uspjesno procitan. Ocjena moze biti niza od stvarnog rizika.</p>'
    }

    return @"
<section class="baseline-card">
  <h2>Ocjena rizika</h2>
  <div class="risk-scale">
    <span style="left:0%">0<br />najbolje</span>
    <span style="left:29%">29<br />cilj</span>
    <span style="left:$marker%">$score</span>
    <span style="left:100%">100<br />kritican rizik</span>
  </div>
  <div class="scale-track"><span class="scale-marker" style="left:$marker%"></span></div>
  <p class="baseline-headline"><strong>$score</strong> = $bandLabel ($bandRange). $comparison</p>
  <p>$scaleDirection Ukupna ocjena je najvisi podskor, nije zbir sva cetiri podskora.</p>
  $coverageWarning
  <h3>Podskorovi</h3>
  $areaTable
  <h3>Pregled bodovanja</h3>
  $driverTable
</section>
"@
}

function New-GroupedFindingsHtml {
    param(
        [object[]]$Findings
    )

    $reportFindings = ConvertTo-GuiFindingArray -InputObject $Findings
    if ($null -eq $reportFindings -or $reportFindings.Count -eq 0) {
        return '<p>Nema nalaza.</p>'
    }

    $html = New-Object System.Collections.Generic.List[string]
    $categories = Get-ReportGroupItems -Items $reportFindings -PropertyName 'Category' -First 500

    foreach ($category in $categories) {
        $categoryName = ConvertTo-HtmlText $category.Name
        $html.Add("<details><summary>$categoryName <span>$($category.Count)</span></summary>") | Out-Null
        $html.Add('<table><thead><tr><th>Ozbiljnost</th><th>Maks. bodovi pravila</th><th>Oblast ocjene</th><th>Nalaz</th><th>Objekat</th><th>Tip objekta</th><th>Preporuka</th></tr></thead><tbody>') | Out-Null

        $categoryFindings = @($reportFindings | Where-Object { (ConvertTo-CompatibleString $_.Category) -eq $category.Name } | Sort-Object -Property Score -Descending)
        foreach ($finding in $categoryFindings) {
            $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
            $severity = Get-SeverityLabel -Severity $finding.Severity
            $severityClass = ConvertTo-HtmlText $finding.Severity
            $score = ConvertTo-HtmlText $metadata.RuleWeight
            $riskArea = ConvertTo-HtmlText $metadata.RiskAreaName
            $title = ConvertTo-HtmlText $finding.Title
            $object = ConvertTo-HtmlText $finding.AffectedObject
            $type = ConvertTo-HtmlText $finding.ObjectType
            $recommendation = ConvertTo-HtmlText $finding.Recommendation
            $html.Add("<tr><td class=`"$severityClass`">$severity</td><td>$score</td><td>$riskArea</td><td>$title</td><td>$object</td><td>$type</td><td>$recommendation</td></tr>") | Out-Null
        }
        $html.Add('</tbody></table></details>') | Out-Null
    }

    return ($html -join [Environment]::NewLine)
}

function New-SecurityFrameworkReferencesHtml {
    param([object[]]$Findings)

    $mapped = New-Object System.Collections.Generic.List[object]
    foreach ($finding in @(ConvertTo-GuiFindingArray -InputObject $Findings)) {
        if (-not $finding.PSObject.Properties['FrameworkReferences']) {
            continue
        }
        foreach ($reference in @($finding.FrameworkReferences)) {
            if ($null -eq $reference -or [string]::IsNullOrWhiteSpace((ConvertTo-CompatibleString $reference.Id))) {
                continue
            }
            $mapped.Add([pscustomobject]@{
                Framework = ConvertTo-CompatibleString $reference.Framework
                Id = ConvertTo-CompatibleString $reference.Id
                Name = ConvertTo-CompatibleString $reference.Name
                Url = ConvertTo-CompatibleString $reference.Url
                Relationship = ConvertTo-CompatibleString $reference.Relationship
                Note = ConvertTo-CompatibleString $reference.Note
                FindingId = ConvertTo-CompatibleString $finding.Id
                FindingTitle = ConvertTo-CompatibleString $finding.Title
                AffectedObject = ConvertTo-CompatibleString $finding.AffectedObject
            }) | Out-Null
        }
    }

    if ($mapped.Count -eq 0) {
        return '<p>Nema nalaza sa direktnim ili kontekstualnim MITRE ATT&amp;CK mapiranjem.</p>'
    }

    $sections = New-Object System.Collections.Generic.List[string]
    foreach ($group in @($mapped.ToArray() | Group-Object -Property Framework, Id, Name, Url | Sort-Object Name)) {
        $sample = $group.Group[0]
        $relationships = @($group.Group | Select-Object -ExpandProperty Relationship -Unique) -join ', '
        $notes = @($group.Group | Select-Object -ExpandProperty Note -Unique)
        $findingRows = New-Object System.Collections.Generic.List[string]
        foreach ($entry in @($group.Group | Sort-Object FindingId, AffectedObject -Unique)) {
            $findingRows.Add("<tr><td>$(ConvertTo-HtmlText $entry.FindingId)</td><td>$(ConvertTo-HtmlText $entry.FindingTitle)</td><td>$(ConvertTo-HtmlText $entry.AffectedObject)</td><td>$(ConvertTo-HtmlText $entry.Relationship)</td></tr>") | Out-Null
        }
        $noteHtml = @($notes | ForEach-Object { "<li>$(ConvertTo-HtmlText $_)</li>" }) -join ''
        $safeUrl = ConvertTo-HtmlText $sample.Url
        $sections.Add(@"
<details>
  <summary>$(ConvertTo-HtmlText $sample.Framework) $(ConvertTo-HtmlText $sample.Id) - $(ConvertTo-HtmlText $sample.Name) <span>$($group.Count) mapiranja</span></summary>
  <div style="padding:10px 12px">
    <p><strong>Veza:</strong> $(ConvertTo-HtmlText $relationships) | <a href="$safeUrl">$safeUrl</a></p>
    <ul>$noteHtml</ul>
    <table class="compact-table"><thead><tr><th>ID nalaza</th><th>Nalaz</th><th>Objekat</th><th>Tip veze</th></tr></thead><tbody>$($findingRows -join [Environment]::NewLine)</tbody></table>
  </div>
</details>
"@) | Out-Null
    }

    return @"
<section>
  <h2>MITRE ATT&amp;CK i sigurnosne reference</h2>
  <p>Mapiranje opisuje kako se nalaz moze povezati sa adversary tehnikom. Ne predstavlja dokaz da se napad dogodio. CVE se ne dodjeljuje konfiguracijskom nalazu bez provjere konkretne ranjive verzije ili patch stanja.</p>
  $($sections -join [Environment]::NewLine)
</section>
"@
}

function Get-BrowserExecutable {
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    return $null
}

function Convert-HtmlReportToPdf {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath,

        [Parameter(Mandatory = $true)]
        [string]$PdfPath
    )

    $browser = Get-BrowserExecutable
    if ([string]::IsNullOrWhiteSpace($browser)) {
        throw 'Nije pronadjen Microsoft Edge ili Google Chrome za headless PDF export.'
    }

    $resolvedHtml = (Resolve-Path -LiteralPath $HtmlPath).Path
    $htmlUri = ([System.Uri]$resolvedHtml).AbsoluteUri
    $arguments = @(
        '--headless',
        '--disable-gpu',
        '--no-pdf-header-footer',
        "--print-to-pdf=$PdfPath",
        $htmlUri
    )

    $process = Start-Process -FilePath $browser -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $PdfPath)) {
        throw "PDF export nije uspio. Browser exit code: $($process.ExitCode)."
    }
}

function Write-JsonFile {
    param(
        [object]$InputObject,
        [string]$Path
    )

    ConvertTo-CompatibleObject -InputObject $InputObject | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Write-HtmlReport {
    param(
        [object]$Summary,
        [object[]]$Findings,
        [object[]]$Warnings,
        [string]$Path
    )

    Add-Type -AssemblyName System.Web
    $reportFindings = ConvertTo-GuiFindingArray -InputObject $Findings

    $style = @'
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; padding-bottom: 32px; color: #1f2933; }
h1, h2 { color: #102a43; }
.meta { color: #52606d; margin-bottom: 22px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 18px 0; }
.card { border: 1px solid #d9e2ec; border-radius: 8px; padding: 12px 16px; min-width: 140px; background: #f8fafc; }
.label { color: #627d98; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
.value { font-size: 26px; font-weight: 700; margin-top: 4px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0 28px 0; font-size: 13px; }
th, td { border: 1px solid #d9e2ec; padding: 7px 9px; vertical-align: top; }
th { background: #e6f0fa; text-align: left; }
tr:nth-child(even) { background: #f8fafc; }
.Critical { color: #8a1c1c; font-weight: 700; }
.High { color: #b42318; font-weight: 700; }
.Medium { color: #b54708; font-weight: 700; }
.Low { color: #175cd3; font-weight: 700; }
.Info { color: #475467; font-weight: 700; }
.chart-row { display: grid; grid-template-columns: minmax(280px, 1fr) minmax(320px, 1.2fr); gap: 16px; margin: 18px 0 24px 0; }
.chart-card { border: 1px solid #d9e2ec; border-radius: 8px; padding: 16px; background: #ffffff; }
.chart-card h2 { font-size: 16px; margin: 0 0 12px 0; }
.donut-wrap { display: flex; gap: 18px; align-items: center; flex-wrap: wrap; }
.donut-segment { transform: rotate(-90deg); transform-origin: center; }
.donut-total { font-size: 7px; font-weight: 700; fill: #102a43; }
.donut-label { font-size: 3px; fill: #627d98; text-transform: uppercase; }
.legend { min-width: 170px; }
.legend-row { display: grid; grid-template-columns: 14px 1fr auto; gap: 8px; align-items: center; margin: 7px 0; }
.legend-swatch { width: 12px; height: 12px; border-radius: 3px; display: inline-block; }
.bar-row { display: grid; grid-template-columns: minmax(130px, 240px) 1fr 42px; gap: 10px; align-items: center; margin: 8px 0; }
.bar-label { overflow-wrap: anywhere; color: #344054; }
.bar-track { height: 10px; background: #eef2f6; border-radius: 99px; overflow: hidden; }
.bar-track span { display: block; height: 100%; background: #2563eb; border-radius: 99px; }
.empty-chart { color: #667085; padding: 12px; background: #f8fafc; border-radius: 6px; }
.baseline-card { border: 1px solid #d9e2ec; border-radius: 8px; padding: 16px; background: #fff; margin: 16px 0 24px 0; }
.baseline-grid { display: grid; grid-template-columns: minmax(300px, .9fr) minmax(360px, 1.1fr); gap: 18px; align-items: start; }
.baseline-headline { font-size: 16px; color: #102a43; }
.risk-scale { position: relative; height: 42px; margin: 4px 8px 0 8px; color: #52606d; font-size: 11px; }
.risk-scale span { position: absolute; transform: translateX(-50%); text-align: center; white-space: nowrap; }
.scale-track { position: relative; height: 14px; margin: 0 8px 18px 8px; border-radius: 99px; background: linear-gradient(90deg, #16a34a 0%, #16a34a 10%, #84cc16 10%, #84cc16 30%, #f59e0b 30%, #f59e0b 50%, #f97316 50%, #f97316 70%, #dc2626 70%, #dc2626 100%); }
.scale-marker { position: absolute; top: -5px; width: 4px; height: 24px; border-radius: 4px; background: #102a43; box-shadow: 0 0 0 2px #fff; transform: translateX(-50%); }
.compact-table { margin: 8px 0 14px 0; font-size: 12px; }
.compact-table th, .compact-table td { padding: 6px 8px; }
.risk-notes { color: #52606d; padding-left: 18px; }
details { border: 1px solid #d9e2ec; border-radius: 8px; margin: 10px 0; background: #fff; }
summary { cursor: pointer; padding: 10px 12px; font-weight: 700; color: #102a43; background: #f8fafc; }
summary span { color: #667085; font-weight: 600; margin-left: 6px; }
.company-footer { color: #667085; font-size: 11px; font-weight: 600; text-align: right; margin-top: 18px; }
@media print { .chart-row, .baseline-grid { grid-template-columns: 1fr; } details, .baseline-card { page-break-inside: avoid; } details:not([open]) > :not(summary) { display: block !important; } .company-footer { margin-top: 10px; } }
</style>
'@

    $safeClientName = ConvertTo-HtmlText $Summary.ClientName
    $safeDomain = ConvertTo-HtmlText $Summary.DomainDnsRoot
    $safeGenerated = ConvertTo-HtmlText $Summary.GeneratedAt
    $safeRiskScoreModel = if ($Summary.PSObject.Properties['RiskScoreModel']) { ConvertTo-HtmlText $Summary.RiskScoreModel } else { '' }
    $safeRiskScoreStatus = if ($Summary.PSObject.Properties['RiskScoreStatus'] -and $Summary.RiskScoreStatus -eq 'Complete') { 'Kompletna procjena' } else { 'Nepotpuna procjena' }

    $summaryCards = @"
<h1>AD sigurnosni izvjestaj rizika</h1>
<div class="meta">
Klijent: <strong>$safeClientName</strong><br />
Domena: <strong>$safeDomain</strong><br />
Generisano: <strong>$safeGenerated</strong><br />
Model ocjene: <strong>$safeRiskScoreModel</strong><br />
Status: <strong>$safeRiskScoreStatus</strong>
</div>
<div class="cards">
  <div class="card"><div class="label">Ocjena rizika</div><div class="value">$($Summary.RiskScore)</div></div>
  <div class="card"><div class="label">Kriticno</div><div class="value Critical">$($Summary.Critical)</div></div>
  <div class="card"><div class="label">Visoko</div><div class="value High">$($Summary.High)</div></div>
  <div class="card"><div class="label">Srednje</div><div class="value Medium">$($Summary.Medium)</div></div>
  <div class="card"><div class="label">Nisko</div><div class="value Low">$($Summary.Low)</div></div>
  <div class="card"><div class="label">Info</div><div class="value Info">$($Summary.Info)</div></div>
  <div class="card"><div class="label">Failed logins ($($Summary.FailedLoginLookbackHours)h)</div><div class="value">$($Summary.FailedLogins)</div></div>
</div>
"@

    $severityCounts = @{
        Critical = [int]$Summary.Critical
        High = [int]$Summary.High
        Medium = [int]$Summary.Medium
        Low = [int]$Summary.Low
        Info = [int]$Summary.Info
    }
    $severityColors = @{
        Critical = '#8a1c1c'
        High = '#b42318'
        Medium = '#b54708'
        Low = '#175cd3'
        Info = '#475467'
    }
    $categoryItems = Get-ReportGroupItems -Items $reportFindings -PropertyName 'Category' -First 12
    $objectItems = Get-ReportGroupItems -Items $reportFindings -PropertyName 'AffectedObject' -First 12
    $severityChart = New-DonutChartSvg -Counts $severityCounts -Colors $severityColors
    $categoryBars = New-BarListHtml -Items $categoryItems -EmptyText 'Nema kategorija.'
    $objectBars = New-BarListHtml -Items $objectItems -EmptyText 'Nema objekata.'
    $riskAreaItems = @()
    if ($Summary.PSObject.Properties['RiskScoreDetails'] -and $null -ne $Summary.RiskScoreDetails -and $Summary.RiskScoreDetails.PSObject.Properties['AreaScores']) {
        foreach ($area in @($Summary.RiskScoreDetails.AreaScores | Select-Object -First 12)) {
            $riskAreaItems += [pscustomobject]@{
                Name  = $area.Name
                Count = [int][math]::Round([double]$area.Score, 0)
            }
        }
    }
    $riskAreaBars = New-BarListHtml -Items $riskAreaItems -EmptyText 'Nema podataka o ocjeni po oblasti.'
    $riskBaselineSection = New-RiskBaselineHtml -Summary $Summary
    $severityGroupedFindings = New-SeverityGroupedFindingsHtml -Findings $reportFindings
    $groupedFindings = New-GroupedFindingsHtml -Findings $reportFindings

    $chartSection = @"
<div class="chart-row">
  <section class="chart-card">
    <h2>Nalazi po ozbiljnosti</h2>
    $severityChart
  </section>
  <section class="chart-card">
    <h2>Top kategorije</h2>
    $categoryBars
  </section>
</div>
<div class="chart-row">
  <section class="chart-card">
    <h2>Top objekti / uredjaji</h2>
    $objectBars
  </section>
  <section class="chart-card">
    <h2>Rizik po oblasti</h2>
    $riskAreaBars
  </section>
</div>
"@

    $warningFragment = New-WarningsHtml -Warnings $Warnings
    $frameworkReferenceSection = New-SecurityFrameworkReferencesHtml -Findings $reportFindings

    $body = $summaryCards + $riskBaselineSection + $chartSection + '<h2>Nalazi - grupisano po ozbiljnosti</h2>' + $severityGroupedFindings + '<h2>Grupisano po kategoriji</h2>' + $groupedFindings + $frameworkReferenceSection + $warningFragment + '<div class="company-footer">Kodeks d.o.o. Sarajevo | Created by: Adis Hadzovic</div>'
    $safeTitle = ConvertTo-HtmlText "AD sigurnosni izvjestaj rizika - $($Summary.ClientName)"
    $html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>$safeTitle</title>
$style
</head>
<body>
$body
<script>
  (function(){
    window.addEventListener('beforeprint',function(){
      document.querySelectorAll('details:not([open])').forEach(function(item){
        item.setAttribute('data-print-open','1');
        item.open=true;
      });
    });
    window.addEventListener('afterprint',function(){
      document.querySelectorAll('details[data-print-open]').forEach(function(item){
        item.open=false;
        item.removeAttribute('data-print-open');
      });
    });
  })();
</script>
</body>
</html>
"@
    $html | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Get-GuiAutoDefaults {
    $defaults = [ordered]@{
        Domain = ''
        Server = ''
        OutputPath = (Join-Path -Path $script:ScriptRoot -ChildPath 'reports')
        Status = ''
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domainInfo = Get-ADDomain -ErrorAction Stop
        $defaults.Domain = $domainInfo.DNSRoot

        try {
            $dc = Get-ADDomainController -Discover -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($dc.HostName)) {
                $defaults.Server = $dc.HostName
            }
        }
        catch {
            $defaults.Status = "Domena je pronadjena, ali DC autodetect nije uspio: $($_.Exception.Message)"
        }

        if ([string]::IsNullOrWhiteSpace($defaults.Status)) {
            $defaults.Status = 'Domena i DC su automatski pronadjeni.'
        }
    }
    catch {
        $defaults.Status = "AD autodetect nije uspio: $($_.Exception.Message)"
    }

    return [pscustomobject]$defaults
}

function Quote-PowerShellLiteral {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return "''"
    }

    return "'" + ($Value -replace "'", "''") + "'"
}

function Quote-NativeArgument {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return '""'
    }

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    return '"' + ($Value -replace '"', '\"') + '"'
}

function Start-GuiAnalyzerProcess {
    param(
        [hashtable]$Settings
    )

    $scanType = if ($Settings.ContainsKey('ScanType') -and $Settings.ScanType -eq 'Health') { 'Health' } else { 'Security' }
    $scriptPath = Get-SelfScriptPath

    if ([string]::IsNullOrWhiteSpace($scriptPath) -or -not (Test-Path -LiteralPath $scriptPath)) {
        throw 'Nije moguce odrediti path skripte.'
    }

    if (-not (Test-Path -LiteralPath $Settings.OutputPath)) {
        New-Item -ItemType Directory -Path $Settings.OutputPath -Force | Out-Null
    }

    $startTime = Get-Date
    $logRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ad-analyzer-gui-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $stdoutPath = Join-Path $logRoot 'stdout.log'
    $stderrPath = Join-Path $logRoot 'stderr.log'

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($part in @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath, '-NoGui', '-GuiChild', '-AssessmentType', $scanType, '-ClientName', $Settings.ClientName, '-OutputPath', $Settings.OutputPath)) {
        $parts.Add((Quote-NativeArgument ([string]$part))) | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($Settings.Server)) {
        $parts.Add('-Server') | Out-Null
        $parts.Add((Quote-NativeArgument $Settings.Server)) | Out-Null
    }

    if ($scanType -eq 'Security' -and -not [string]::IsNullOrWhiteSpace($Settings.ConfigPath)) {
        $parts.Add('-ConfigPath') | Out-Null
        $parts.Add((Quote-NativeArgument $Settings.ConfigPath)) | Out-Null
    }

    if ($scanType -eq 'Security') {
        foreach ($name in @('StaleUserDays', 'StaleComputerDays', 'PrivilegedStaleDays', 'MaxPasswordAgeDays', 'ServiceAccountPasswordAgeDays', 'KrbtgtMaxPasswordAgeDays', 'MinPasswordLength', 'MinPasswordHistory', 'MaxDomainAdmins', 'MaxEnterpriseAdmins', 'FailedLoginLookbackHours', 'FailedLoginMediumThreshold', 'FailedLoginHighThreshold', 'FailedLoginAccountThreshold', 'FailedLoginMaxEventsPerDc', 'FailedLoginQueryTimeoutSeconds')) {
            $parts.Add("-$name") | Out-Null
            $parts.Add([string]$Settings[$name]) | Out-Null
        }

        if ($Settings.AuditPasswordExpiration) {
            $parts.Add('-AuditPasswordExpiration') | Out-Null
        }

        if ($Settings.SkipFailedLoginAudit) {
            $parts.Add('-SkipFailedLoginAudit') | Out-Null
        }
    }

    if ($Settings.NoCsv) {
        $parts.Add('-NoCsv') | Out-Null
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = ($parts -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()

    return [pscustomobject]@{
        Process = $process
        StartTime = $startTime
        Settings = $Settings
        StdOutPath = $stdoutPath
        StdErrPath = $stderrPath
        LogRoot = $logRoot
        ScanType = $scanType
    }
}

function Read-GuiAnalyzerResult {
    param(
        [hashtable]$Settings,
        [datetime]$StartTime,
        [string]$StdOutPath,
        [string]$StdErrPath
    )

    $isHealthScan = $Settings.ContainsKey('ScanType') -and $Settings.ScanType -eq 'Health'
    $reportDir = Get-ChildItem -LiteralPath $Settings.OutputPath -Directory |
        Where-Object {
            $_.LastWriteTime -ge $StartTime.AddSeconds(-10) -and
            $_.Name -ne '_gui-child-logs' -and
            (($isHealthScan -and $_.Name -match '-health-\d{8}-\d{6}$') -or
             (-not $isHealthScan -and $_.Name -notmatch '-health-\d{8}-\d{6}$')) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'summary.json')) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'findings.json'))
        } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $reportDir) {
        throw 'Analyzer je zavrsio, ali report folder nije pronadjen.'
    }

    $summaryPath = Join-Path $reportDir.FullName 'summary.json'
    $findingsPath = Join-Path $reportDir.FullName 'findings.json'
    $warningsPath = Join-Path $reportDir.FullName 'collection-warnings.json'

    if (-not (Test-Path -LiteralPath $summaryPath) -or -not (Test-Path -LiteralPath $findingsPath)) {
        throw "Report folder je pronadjen, ali summary/findings JSON nedostaje: $($reportDir.FullName)"
    }

    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    $findings = ConvertTo-GuiFindingArray -InputObject (Get-Content -LiteralPath $findingsPath -Raw | ConvertFrom-Json)
    $warnings = @()
    if (Test-Path -LiteralPath $warningsPath) {
        $warnings = @(Get-Content -LiteralPath $warningsPath -Raw | ConvertFrom-Json)
    }

    return [pscustomobject]@{
        Summary = $summary
        Findings = $findings
        Warnings = $warnings
        ReportPath = $reportDir.FullName
        HtmlReport = Join-Path $reportDir.FullName 'report.html'
        JsonReport = $findingsPath
        WarningPath = $warningsPath
        StdOut = if (Test-Path -LiteralPath $StdOutPath) { Get-Content -LiteralPath $StdOutPath -Raw } else { '' }
        StdErr = if (Test-Path -LiteralPath $StdErrPath) { Get-Content -LiteralPath $StdErrPath -Raw } else { '' }
    }
}

function ConvertTo-GuiFindingArray {
    param(
        [AllowNull()]
        [object]$InputObject
    )

    $items = New-Object System.Collections.Generic.List[object]
    $collectionPropertyNames = @('Findings', 'Items', 'Results', 'Data', 'Value', 'Values')

    function Test-GuiFindingItem {
        param(
            [AllowNull()]
            [object]$Item
        )

        if ($null -eq $Item -or $null -eq $Item.PSObject) {
            return $false
        }

        if ($Item -is [System.Collections.IDictionary]) {
            return ($Item.Contains('Id') -and $Item.Contains('Severity'))
        }

        return ($null -ne $Item.PSObject.Properties['Id'] -and $null -ne $Item.PSObject.Properties['Severity'])
    }

    function Add-GuiFindingItem {
        param(
            [AllowNull()]
            [object]$Item
        )

        if ($null -eq $Item) {
            return
        }

        if (Test-GuiFindingItem -Item $Item) {
            $items.Add($Item) | Out-Null
            return
        }

        if ($Item -is [System.Collections.IDictionary]) {
            foreach ($key in $Item.Keys) {
                Add-GuiFindingItem -Item $Item[$key]
            }
            return
        }

        if ($Item -is [System.Array]) {
            foreach ($child in $Item) {
                Add-GuiFindingItem -Item $child
            }
            return
        }

        if ($Item -is [System.Collections.IEnumerable] -and -not ($Item -is [string])) {
            foreach ($child in $Item) {
                Add-GuiFindingItem -Item $child
            }
            return
        }

        if ($null -eq $Item.PSObject -or $Item.PSObject.Properties.Count -eq 0) {
            return
        }

        foreach ($propertyName in $collectionPropertyNames) {
            $property = $Item.PSObject.Properties[$propertyName]
            if ($null -ne $property) {
                Add-GuiFindingItem -Item $property.Value
            }
        }

        foreach ($property in $Item.PSObject.Properties) {
            if ($collectionPropertyNames -contains $property.Name) {
                continue
            }

            $value = $property.Value
            if ($null -eq $value -or $value -is [string]) {
                continue
            }

            if ($value -is [System.Array] -or $value -is [System.Collections.IEnumerable] -or $value -is [System.Collections.IDictionary]) {
                Add-GuiFindingItem -Item $value
            }
        }
    }

    Add-GuiFindingItem -Item $InputObject
    return @($items.ToArray())
}

function Get-GuiSeverityKey {
    param(
        [AllowNull()]
        [object]$Value
    )

    $text = (ConvertTo-CompatibleString $Value).Trim()
    switch -Regex ($text) {
        '^(Critical|Kriticno)$' { return 'Critical' }
        '^(High|Visoko)$' { return 'High' }
        '^(Medium|Srednje)$' { return 'Medium' }
        '^(Low|Nisko)$' { return 'Low' }
        '^(Info)$' { return 'Info' }
        default { return $text }
    }
}

function Select-GuiFindings {
    param(
        [object[]]$Findings,
        [string]$Mode,
        [string]$Value
    )

    $allFindings = ConvertTo-GuiFindingArray -InputObject $Findings

    if ([string]::IsNullOrWhiteSpace($Mode) -or $Mode -eq 'All' -or [string]::IsNullOrWhiteSpace($Value)) {
        return @($allFindings)
    }

    $target = (ConvertTo-CompatibleString $Value).Trim()

    switch ($Mode) {
        'Severity' {
            $targetSeverity = Get-GuiSeverityKey -Value $target
            return @($allFindings | Where-Object {
                (Get-GuiSeverityKey -Value $_.Severity) -eq $targetSeverity -or
                (Get-GuiSeverityKey -Value (Get-SeverityLabel -Severity $_.Severity)) -eq $targetSeverity
            })
        }
        'HealthStatus' {
            return @($allFindings | Where-Object {
                (ConvertTo-CompatibleString $_.Status).Trim() -ieq $target -or
                (ConvertTo-CompatibleString $_.StatusLabel).Trim() -ieq $target
            })
        }
        'Category' {
            return @($allFindings | Where-Object { (ConvertTo-CompatibleString $_.Category).Trim() -ieq $target })
        }
        'ObjectType' {
            return @($allFindings | Where-Object { (ConvertTo-CompatibleString $_.ObjectType).Trim() -ieq $target })
        }
        'AffectedObject' {
            return @($allFindings | Where-Object { (ConvertTo-CompatibleString $_.AffectedObject).Trim() -ieq $target })
        }
        default {
            return @($allFindings)
        }
    }
}

function Add-GuiLog {
    param(
        [System.Windows.Forms.TextBox]$TextBox,
        [string]$Message
    )

    $TextBox.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $Message" + [Environment]::NewLine)
}

function Get-SelfScriptPath {
    if (-not [string]::IsNullOrWhiteSpace($script:SelfScriptPath)) {
        return $script:SelfScriptPath
    }

    if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        return $PSCommandPath
    }

    if ($MyInvocation -and $MyInvocation.MyCommand -and -not [string]::IsNullOrWhiteSpace($MyInvocation.MyCommand.Path)) {
        return $MyInvocation.MyCommand.Path
    }

    if (-not [string]::IsNullOrWhiteSpace($script:MyInvocation.MyCommand.Path)) {
        return $script:MyInvocation.MyCommand.Path
    }

    return $null
}

function Show-GuiStartupError {
    param(
        [object]$ErrorRecord
    )

    $message = if ($ErrorRecord.Exception) { $ErrorRecord.Exception.Message } else { [string]$ErrorRecord }
    $details = [string]$ErrorRecord
    $logPath = Join-Path -Path $script:ScriptRoot -ChildPath 'gui-crash.log'
    $content = @(
        "Time: $((Get-Date).ToString('s'))",
        "Message: $message",
        "Details:",
        $details
    ) -join [Environment]::NewLine

    try {
        $content | Set-Content -LiteralPath $logPath -Encoding ASCII
    }
    catch {
        $logPath = ''
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $display = if ([string]::IsNullOrWhiteSpace($logPath)) {
            $message
        }
        else {
            "$message`r`n`r`nLog: $logPath"
        }
        [System.Windows.Forms.MessageBox]::Show($display, 'AD Security Risk Analyzer pokretanje nije uspjelo', 'OK', 'Error') | Out-Null
    }
    catch {
        Write-Error $content
    }
}

function Set-SummaryCardValue {
    param(
        [hashtable]$Cards,
        [string]$Key,
        [object]$Value
    )

    if ($Cards.ContainsKey($Key)) {
        $Cards[$Key].Text = [string]$Value
    }
}

function Update-GuiSummary {
    param(
        [object]$Summary,
        [hashtable]$Cards,
        [hashtable]$CardLabels = @{},
        [System.Windows.Forms.Label]$BaselineLabel = $null
    )

    $isHealth = $Summary.PSObject.Properties['AssessmentType'] -and $Summary.AssessmentType -eq 'Health'
    if ($isHealth) {
        $healthScoreDisplay = if ($Summary.PSObject.Properties['HealthScoreDisplay']) { $Summary.HealthScoreDisplay } elseif ($null -eq $Summary.HealthScore) { 'N/A' } else { [string]$Summary.HealthScore }
        Set-SummaryCardValue -Cards $Cards -Key 'Risk' -Value $healthScoreDisplay
        Set-SummaryCardValue -Cards $Cards -Key 'Total' -Value $Summary.TotalChecks
        Set-SummaryCardValue -Cards $Cards -Key 'Critical' -Value $Summary.Failed
        Set-SummaryCardValue -Cards $Cards -Key 'High' -Value $Summary.Warnings
        Set-SummaryCardValue -Cards $Cards -Key 'Medium' -Value $Summary.Passed
        Set-SummaryCardValue -Cards $Cards -Key 'Low' -Value $Summary.NotAssessed
        Set-SummaryCardValue -Cards $Cards -Key 'Info' -Value "$($Summary.HealthCoveragePercent)%"
        Set-SummaryCardValue -Cards $Cards -Key 'Users' -Value $Summary.CategoriesHealthy
        Set-SummaryCardValue -Cards $Cards -Key 'Computers' -Value $Summary.CategoriesTotal
        Set-SummaryCardValue -Cards $Cards -Key 'DCs' -Value $Summary.DomainControllers

        $healthLabels = @{
            Risk = 'Health'; Total = 'Provjere'; Critical = 'Fail'; High = 'Warning'; Medium = 'Proslo'
            Low = 'Nije proc.'; Info = 'Coverage'; Users = 'Zdrave'; Computers = 'Oblasti'; DCs = 'DCs'
        }
        foreach ($key in $healthLabels.Keys) {
            if ($CardLabels.ContainsKey($key)) { $CardLabels[$key].Text = $healthLabels[$key] }
        }
        if ($null -ne $BaselineLabel) {
            $BaselineLabel.Text = "Health score: $healthScoreDisplay$(if ($healthScoreDisplay -ne 'N/A') { '/100' }) - $($Summary.HealthStatus). 100 je najbolje. Coverage: $($Summary.HealthCoveragePercent)%."
        }
        return
    }

    Set-SummaryCardValue -Cards $Cards -Key 'Risk' -Value $Summary.RiskScore
    Set-SummaryCardValue -Cards $Cards -Key 'Total' -Value $Summary.TotalFindings
    Set-SummaryCardValue -Cards $Cards -Key 'Critical' -Value $Summary.Critical
    Set-SummaryCardValue -Cards $Cards -Key 'High' -Value $Summary.High
    Set-SummaryCardValue -Cards $Cards -Key 'Medium' -Value $Summary.Medium
    Set-SummaryCardValue -Cards $Cards -Key 'Low' -Value $Summary.Low
    Set-SummaryCardValue -Cards $Cards -Key 'Info' -Value $Summary.Info
    Set-SummaryCardValue -Cards $Cards -Key 'Users' -Value $Summary.Users
    Set-SummaryCardValue -Cards $Cards -Key 'Computers' -Value $Summary.Computers
    Set-SummaryCardValue -Cards $Cards -Key 'DCs' -Value $Summary.DomainControllers
    $securityLabels = @{
        Risk = 'Rizik'; Total = 'Ukupno'; Critical = 'Kriticno'; High = 'Visoko'; Medium = 'Srednje'
        Low = 'Nisko'; Info = 'Info'; Users = 'Useri'; Computers = 'PCs'; DCs = 'DCs'
    }
    foreach ($key in $securityLabels.Keys) {
        if ($CardLabels.ContainsKey($key)) { $CardLabels[$key].Text = $securityLabels[$key] }
    }

    if ($null -ne $BaselineLabel) {
        if ($Summary.PSObject.Properties['RiskBaseline'] -and $null -ne $Summary.RiskBaseline) {
            $BaselineLabel.Text = "Ocjena rizika: $($Summary.RiskScore) - $($Summary.RiskBaseline.BandLabel). $($Summary.RiskBaseline.BaselineComparison) 0 je najbolje, 100 je najgore."
        }
        else {
            $BaselineLabel.Text = 'Ocjena rizika: 0 je najbolje, 100 je najgore.'
        }
    }
}

function Update-GuiFindingsGrid {
    param(
        [System.Windows.Forms.DataGridView]$Grid,
        [System.Windows.Forms.TextBox]$DetailBox,
        [object[]]$Findings,
        [string]$Mode,
        [string]$Value
    )

    $Grid.Rows.Clear()
    $filtered = Select-GuiFindings -Findings $Findings -Mode $Mode -Value $Value
    $isHealth = @($Findings | Where-Object {
        $_.PSObject.Properties['AssessmentType'] -and
        (ConvertTo-CompatibleString $_.AssessmentType) -eq 'Health'
    }).Count -gt 0

    foreach ($finding in @($filtered | Sort-Object -Property Score -Descending)) {
        $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
        $statusLabel = if ($isHealth -and $finding.PSObject.Properties['StatusLabel']) {
            $finding.StatusLabel
        }
        else {
            Get-SeverityLabel -Severity $finding.Severity
        }
        $rowIndex = $Grid.Rows.Add(
            $finding.Id,
            $metadata.RuleWeight,
            $metadata.RiskAreaName,
            $statusLabel,
            $finding.Category,
            $finding.Title,
            $finding.AffectedObject,
            $finding.ObjectType
        )
        $Grid.Rows[$rowIndex].Tag = $finding

        if ($isHealth) {
            switch ($finding.Status) {
                'Fail' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(69, 10, 10) }
                'Warning' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(63, 48, 11) }
                'Pass' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(6, 55, 48) }
                'NotAssessed' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59) }
                'NotApplicable' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(17, 24, 39) }
            }
        }
        else {
            switch ($finding.Severity) {
                'Critical' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(69, 10, 10) }
                'High' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(67, 20, 7) }
                'Medium' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(63, 48, 11) }
                'Low' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(23, 37, 84) }
            }
        }
        $Grid.Rows[$rowIndex].DefaultCellStyle.ForeColor = $script:GuiColors.Text
        $Grid.Rows[$rowIndex].DefaultCellStyle.SelectionBackColor = $script:GuiColors.Accent
        $Grid.Rows[$rowIndex].DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    }

    $itemName = if ($isHealth) { 'provjera' } else { 'nalaza' }
    $DetailBox.Text = "Prikazano $itemName`: $($Grid.Rows.Count)"
}

function Update-GuiFilterTree {
    param(
        [System.Windows.Forms.TreeView]$Tree,
        [object[]]$Findings
    )

    $Tree.Nodes.Clear()
    $isHealth = @($Findings | Where-Object {
        $_.PSObject.Properties['AssessmentType'] -and
        (ConvertTo-CompatibleString $_.AssessmentType) -eq 'Health'
    }).Count -gt 0
    $allLabel = if ($isHealth) { 'Sve provjere' } else { 'Svi nalazi' }
    $allNode = $Tree.Nodes.Add("$allLabel ($($Findings.Count))")
    $allNode.Tag = @{ Mode = 'All'; Value = '' }

    if ($isHealth) {
        $severityRoot = $Tree.Nodes.Add('Health status')
        foreach ($statusDefinition in @(
                @{ Value = 'Fail'; Label = 'Neispravno' },
                @{ Value = 'Warning'; Label = 'Upozorenje' },
                @{ Value = 'Pass'; Label = 'Proslo' },
                @{ Value = 'NotAssessed'; Label = 'Nije procijenjeno' },
                @{ Value = 'NotApplicable'; Label = 'Nije primjenjivo' }
            )) {
            $count = @($Findings | Where-Object { $_.Status -eq $statusDefinition.Value }).Count
            $node = $severityRoot.Nodes.Add("$($statusDefinition.Label) ($count)")
            $node.Tag = @{ Mode = 'HealthStatus'; Value = $statusDefinition.Value }
        }
    }
    else {
        $severityRoot = $Tree.Nodes.Add('Ozbiljnost')
        foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            $count = @($Findings | Where-Object { $_.Severity -eq $severity }).Count
            $node = $severityRoot.Nodes.Add("$((Get-SeverityLabel -Severity $severity)) ($count)")
            $node.Tag = @{ Mode = 'Severity'; Value = $severity }
        }
    }

    $categoryRoot = $Tree.Nodes.Add('Kategorija')
    foreach ($group in @($Findings | Group-Object Category | Sort-Object Count -Descending)) {
        $node = $categoryRoot.Nodes.Add("$($group.Name) ($($group.Count))")
        $node.Tag = @{ Mode = 'Category'; Value = $group.Name }
    }

    $typeRoot = $Tree.Nodes.Add('Tip objekta')
    foreach ($group in @($Findings | Group-Object ObjectType | Sort-Object Count -Descending)) {
        if ([string]::IsNullOrWhiteSpace($group.Name)) { continue }
        $node = $typeRoot.Nodes.Add("$($group.Name) ($($group.Count))")
        $node.Tag = @{ Mode = 'ObjectType'; Value = $group.Name }
    }

    $objectRoot = $Tree.Nodes.Add('Objekti / uredjaji')
    foreach ($group in @($Findings | Where-Object { -not [string]::IsNullOrWhiteSpace($_.AffectedObject) } | Group-Object AffectedObject | Sort-Object Count -Descending | Select-Object -First 80)) {
        $node = $objectRoot.Nodes.Add("$($group.Name) ($($group.Count))")
        $node.Tag = @{ Mode = 'AffectedObject'; Value = $group.Name }
    }

    $Tree.ExpandAll()
}

function Show-ADSecurityRiskAnalyzerGui {
    param(
        [string]$InitialClientName,
        [string]$InitialServer,
        [string]$InitialOutputPath,
        [string]$InitialConfigPath
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $script:GuiColors = @{
        Background = [System.Drawing.Color]::FromArgb(15, 23, 42)
        Header = [System.Drawing.Color]::FromArgb(2, 6, 23)
        Panel = [System.Drawing.Color]::FromArgb(30, 41, 59)
        PanelAlt = [System.Drawing.Color]::FromArgb(17, 24, 39)
        Input = [System.Drawing.Color]::FromArgb(15, 23, 42)
        Text = [System.Drawing.Color]::FromArgb(226, 232, 240)
        Muted = [System.Drawing.Color]::FromArgb(148, 163, 184)
        Border = [System.Drawing.Color]::FromArgb(51, 65, 85)
        Accent = [System.Drawing.Color]::FromArgb(37, 99, 235)
        AccentHover = [System.Drawing.Color]::FromArgb(29, 78, 216)
        Danger = [System.Drawing.Color]::FromArgb(248, 113, 113)
        Warning = [System.Drawing.Color]::FromArgb(251, 191, 36)
        Success = [System.Drawing.Color]::FromArgb(34, 197, 94)
    }

    function Set-GuiButtonStyle {
        param(
            [System.Windows.Forms.Button]$Button,
            [switch]$Primary
        )

        $Button.FlatStyle = 'Flat'
        $Button.UseVisualStyleBackColor = $false
        $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
        $Button.FlatAppearance.BorderSize = 0
        if ($Primary) {
            $Button.BackColor = $script:GuiColors.Accent
            $Button.ForeColor = [System.Drawing.Color]::White
        }
        else {
            $Button.BackColor = $script:GuiColors.Panel
            $Button.ForeColor = $script:GuiColors.Text
        }
    }

    function Set-GuiInputStyle {
        param(
            [System.Windows.Forms.Control]$Control
        )

        $Control.BackColor = $script:GuiColors.Input
        $Control.ForeColor = $script:GuiColors.Text
        if ($Control.PSObject.Properties.Name -contains 'BorderStyle') {
            $Control.BorderStyle = 'FixedSingle'
        }
    }

    $defaults = Get-GuiAutoDefaults
    $script:GuiState = [ordered]@{
        Summary = $null
        Findings = @()
        Warnings = @()
        ReportPath = ''
        ActiveRun = $null
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'AD Security / Health Analyzer'
    $form.Size = New-Object System.Drawing.Size(1320, 860)
    $form.MinimumSize = New-Object System.Drawing.Size(1160, 760)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = $script:GuiColors.Background

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = 'Top'
    $header.Height = 72
    $header.BackColor = $script:GuiColors.Header
    $form.Controls.Add($header)

    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'AD Security / Health Analyzer'
    $title.ForeColor = [System.Drawing.Color]::White
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 20, [System.Drawing.FontStyle]::Bold)
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(18, 14)
    $header.Controls.Add($title)

    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = 'Read-only AD security i health provjera, izvjestaji i export'
    $subtitle.ForeColor = $script:GuiColors.Muted
    $subtitle.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $subtitle.AutoSize = $true
    $subtitle.Location = New-Object System.Drawing.Point(22, 46)
    $header.Controls.Add($subtitle)

    $author = New-Object System.Windows.Forms.Label
    $author.Text = 'Created by: Adis Hadzovic'
    $author.ForeColor = $script:GuiColors.Text
    $author.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $author.AutoSize = $true
    $author.Anchor = 'Top,Right'
    $author.Location = New-Object System.Drawing.Point(1110, 24)
    $header.Controls.Add($author)

    $configGroup = New-Object System.Windows.Forms.GroupBox
    $configGroup.Text = 'Postavke skena / standardni baseline'
    $configGroup.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $configGroup.Location = New-Object System.Drawing.Point(16, 86)
    $configGroup.Size = New-Object System.Drawing.Size(398, 460)
    $configGroup.Anchor = 'Top,Left'
    $configGroup.BackColor = $script:GuiColors.Background
    $configGroup.ForeColor = $script:GuiColors.Text
    $form.Controls.Add($configGroup)

    function New-GuiLabel([string]$text, [int]$x, [int]$y) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $text
        $label.Location = New-Object System.Drawing.Point($x, $y)
        $label.Size = New-Object System.Drawing.Size(130, 20)
        $label.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $label.ForeColor = $script:GuiColors.Muted
        $label.BackColor = [System.Drawing.Color]::Transparent
        return $label
    }

    function New-GuiTextBox([string]$text, [int]$x, [int]$y, [int]$width) {
        $box = New-Object System.Windows.Forms.TextBox
        $box.Text = $text
        $box.Location = New-Object System.Drawing.Point($x, $y)
        $box.Size = New-Object System.Drawing.Size($width, 24)
        $box.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        Set-GuiInputStyle -Control $box
        return $box
    }

    $clientText = if ([string]::IsNullOrWhiteSpace($InitialClientName)) { $defaults.Domain } else { $InitialClientName }
    $serverText = if ([string]::IsNullOrWhiteSpace($InitialServer)) { $defaults.Server } else { $InitialServer }
    $outputText = if ([string]::IsNullOrWhiteSpace($InitialOutputPath)) { $defaults.OutputPath } else { $InitialOutputPath }

    $configGroup.Controls.Add((New-GuiLabel 'Domena / klijent' 14 28))
    $txtClient = New-GuiTextBox $clientText 142 25 230
    $configGroup.Controls.Add($txtClient)

    $configGroup.Controls.Add((New-GuiLabel 'Domenski kontroler' 14 64))
    $txtServer = New-GuiTextBox $serverText 142 61 230
    $configGroup.Controls.Add($txtServer)

    $configGroup.Controls.Add((New-GuiLabel 'Report folder' 14 100))
    $txtOutput = New-GuiTextBox $outputText 142 97 185
    $configGroup.Controls.Add($txtOutput)
    $btnBrowseOutput = New-Object System.Windows.Forms.Button
    $btnBrowseOutput.Text = '...'
    $btnBrowseOutput.Location = New-Object System.Drawing.Point(334, 96)
    $btnBrowseOutput.Size = New-Object System.Drawing.Size(38, 26)
    Set-GuiButtonStyle -Button $btnBrowseOutput
    $configGroup.Controls.Add($btnBrowseOutput)

    $configGroup.Controls.Add((New-GuiLabel 'Config fajl' 14 136))
    $txtConfig = New-GuiTextBox $InitialConfigPath 142 133 185
    $configGroup.Controls.Add($txtConfig)
    $btnBrowseConfig = New-Object System.Windows.Forms.Button
    $btnBrowseConfig.Text = '...'
    $btnBrowseConfig.Location = New-Object System.Drawing.Point(334, 132)
    $btnBrowseConfig.Size = New-Object System.Drawing.Size(38, 26)
    Set-GuiButtonStyle -Button $btnBrowseConfig
    $configGroup.Controls.Add($btnBrowseConfig)

    $chkAuditExpiration = New-Object System.Windows.Forms.CheckBox
    $chkAuditExpiration.Text = 'Audit isteka lozinki'
    $chkAuditExpiration.Location = New-Object System.Drawing.Point(142, 166)
    $chkAuditExpiration.Size = New-Object System.Drawing.Size(200, 22)
    $chkAuditExpiration.BackColor = $script:GuiColors.Background
    $chkAuditExpiration.ForeColor = $script:GuiColors.Text
    $configGroup.Controls.Add($chkAuditExpiration)

    $chkNoCsv = New-Object System.Windows.Forms.CheckBox
    $chkNoCsv.Text = 'Preskoci CSV export'
    $chkNoCsv.Location = New-Object System.Drawing.Point(142, 190)
    $chkNoCsv.Size = New-Object System.Drawing.Size(160, 22)
    $chkNoCsv.BackColor = $script:GuiColors.Background
    $chkNoCsv.ForeColor = $script:GuiColors.Text
    $configGroup.Controls.Add($chkNoCsv)

    $numericSettings = @(
        @{Label='Neaktivni useri (90d)'; Name='StaleUserDays'; Value=$StaleUserDays; Y=224; Max=3650},
        @{Label='Neaktivni PC-evi (45d)'; Name='StaleComputerDays'; Value=$StaleComputerDays; Y=254; Max=3650},
        @{Label='Priv. nalozi (180d)'; Name='PrivilegedStaleDays'; Value=$PrivilegedStaleDays; Y=284; Max=3650},
        @{Label='Min lozinka (15)'; Name='MinPasswordLength'; Value=$MinPasswordLength; Y=314; Max=128},
        @{Label='krbtgt starost (180d)'; Name='KrbtgtMaxPasswordAgeDays'; Value=$KrbtgtMaxPasswordAgeDays; Y=344; Max=3650}
    )
    $numericBoxes = @{}
    foreach ($item in $numericSettings) {
        $configGroup.Controls.Add((New-GuiLabel $item.Label 14 $item.Y))
        $num = New-Object System.Windows.Forms.NumericUpDown
        $num.Location = New-Object System.Drawing.Point(142, ($item.Y - 3))
        $num.Size = New-Object System.Drawing.Size(84, 24)
        $num.Minimum = 0
        $num.Maximum = $item.Max
        $num.Value = $item.Value
        Set-GuiInputStyle -Control $num
        $configGroup.Controls.Add($num)
        $numericBoxes[$item.Name] = $num
    }

    $btnStart = New-Object System.Windows.Forms.Button
    $btnStart.Text = 'Pokreni AD Security Test'
    $btnStart.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $btnStart.Location = New-Object System.Drawing.Point(14, 380)
    $btnStart.Size = New-Object System.Drawing.Size(176, 38)
    Set-GuiButtonStyle -Button $btnStart -Primary
    $configGroup.Controls.Add($btnStart)

    $btnHealthStart = New-Object System.Windows.Forms.Button
    $btnHealthStart.Text = 'Pokreni AD Health Test'
    $btnHealthStart.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $btnHealthStart.Location = New-Object System.Drawing.Point(196, 380)
    $btnHealthStart.Size = New-Object System.Drawing.Size(176, 38)
    Set-GuiButtonStyle -Button $btnHealthStart -Primary
    $btnHealthStart.BackColor = [System.Drawing.Color]::FromArgb(15, 118, 110)
    $configGroup.Controls.Add($btnHealthStart)

    $baselineNote = New-Object System.Windows.Forms.Label
    $baselineNote.Text = 'Default pragovi prate NIST/Microsoft/CIS. Mijenjati samo za odobrenu politiku.'
    $baselineNote.Location = New-Object System.Drawing.Point(14, 426)
    $baselineNote.Size = New-Object System.Drawing.Size(360, 24)
    $baselineNote.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $baselineNote.ForeColor = $script:GuiColors.Muted
    $configGroup.Controls.Add($baselineNote)

    $summaryGroup = New-Object System.Windows.Forms.GroupBox
    $summaryGroup.Text = 'Pregled'
    $summaryGroup.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $summaryGroup.Location = New-Object System.Drawing.Point(430, 86)
    $summaryGroup.Size = New-Object System.Drawing.Size(862, 134)
    $summaryGroup.Anchor = 'Top,Left,Right'
    $summaryGroup.BackColor = $script:GuiColors.Background
    $summaryGroup.ForeColor = $script:GuiColors.Text
    $form.Controls.Add($summaryGroup)

    $cards = @{}
    $cardLabels = @{}
    $cardDefinitions = @(
        @{Key='Risk'; Label='Rizik'; X=12; Color=$script:GuiColors.Text},
        @{Key='Total'; Label='Ukupno'; X=95; Color=$script:GuiColors.Text},
        @{Key='Critical'; Label='Kriticno'; X=178; Color=$script:GuiColors.Danger},
        @{Key='High'; Label='Visoko'; X=261; Color=$script:GuiColors.Danger},
        @{Key='Medium'; Label='Srednje'; X=344; Color=$script:GuiColors.Warning},
        @{Key='Low'; Label='Nisko'; X=427; Color=$script:GuiColors.Accent},
        @{Key='Info'; Label='Info'; X=510; Color=[System.Drawing.Color]::FromArgb(71, 84, 103)},
        @{Key='Users'; Label='Useri'; X=593; Color=$script:GuiColors.Text},
        @{Key='Computers'; Label='PCs'; X=676; Color=$script:GuiColors.Text},
        @{Key='DCs'; Label='DCs'; X=759; Color=$script:GuiColors.Text}
    )
    foreach ($def in $cardDefinitions) {
        $panel = New-Object System.Windows.Forms.Panel
        $panel.Location = New-Object System.Drawing.Point($def.X, 26)
        $panel.Size = New-Object System.Drawing.Size(76, 86)
        $panel.BackColor = $script:GuiColors.PanelAlt
        $panel.BorderStyle = 'None'
        $summaryGroup.Controls.Add($panel)

        $valueLabel = New-Object System.Windows.Forms.Label
        $valueLabel.Text = '-'
        $valueLabel.Font = New-Object System.Drawing.Font('Segoe UI', 20, [System.Drawing.FontStyle]::Bold)
        $valueLabel.ForeColor = $def.Color
        $valueLabel.TextAlign = 'MiddleCenter'
        $valueLabel.Location = New-Object System.Drawing.Point(0, 8)
        $valueLabel.Size = New-Object System.Drawing.Size(74, 42)
        $panel.Controls.Add($valueLabel)

        $nameLabel = New-Object System.Windows.Forms.Label
        $nameLabel.Text = $def.Label
        $nameLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8)
        $nameLabel.ForeColor = $script:GuiColors.Muted
        $nameLabel.TextAlign = 'MiddleCenter'
        $nameLabel.Location = New-Object System.Drawing.Point(0, 54)
        $nameLabel.Size = New-Object System.Drawing.Size(74, 22)
        $panel.Controls.Add($nameLabel)
        $cards[$def.Key] = $valueLabel
        $cardLabels[$def.Key] = $nameLabel
    }

    $riskBaselineLabel = New-Object System.Windows.Forms.Label
    $riskBaselineLabel.Text = 'Ocjena rizika: 0 je najbolje, 100 je najgore.'
    $riskBaselineLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $riskBaselineLabel.ForeColor = $script:GuiColors.Muted
    $riskBaselineLabel.TextAlign = 'MiddleLeft'
    $riskBaselineLabel.Location = New-Object System.Drawing.Point(12, 112)
    $riskBaselineLabel.Size = New-Object System.Drawing.Size(830, 18)
    $riskBaselineLabel.Anchor = 'Left,Right,Bottom'
    $summaryGroup.Controls.Add($riskBaselineLabel)

    $btnSaveHtml = New-Object System.Windows.Forms.Button
    $btnSaveHtml.Text = 'Sacuvaj HTML'
    $btnSaveHtml.Enabled = $false
    $btnSaveHtml.Location = New-Object System.Drawing.Point(430, 230)
    $btnSaveHtml.Size = New-Object System.Drawing.Size(130, 32)
    Set-GuiButtonStyle -Button $btnSaveHtml
    $form.Controls.Add($btnSaveHtml)

    $btnSavePdf = New-Object System.Windows.Forms.Button
    $btnSavePdf.Text = 'Sacuvaj PDF'
    $btnSavePdf.Enabled = $false
    $btnSavePdf.Location = New-Object System.Drawing.Point(570, 230)
    $btnSavePdf.Size = New-Object System.Drawing.Size(130, 32)
    Set-GuiButtonStyle -Button $btnSavePdf
    $form.Controls.Add($btnSavePdf)

    $btnOpenFolder = New-Object System.Windows.Forms.Button
    $btnOpenFolder.Text = 'Otvori report folder'
    $btnOpenFolder.Enabled = $false
    $btnOpenFolder.Location = New-Object System.Drawing.Point(710, 230)
    $btnOpenFolder.Size = New-Object System.Drawing.Size(150, 32)
    Set-GuiButtonStyle -Button $btnOpenFolder
    $form.Controls.Add($btnOpenFolder)

    $btnClearFilter = New-Object System.Windows.Forms.Button
    $btnClearFilter.Text = 'Ocisti filter'
    $btnClearFilter.Enabled = $false
    $btnClearFilter.Location = New-Object System.Drawing.Point(870, 230)
    $btnClearFilter.Size = New-Object System.Drawing.Size(120, 32)
    Set-GuiButtonStyle -Button $btnClearFilter
    $form.Controls.Add($btnClearFilter)

    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Location = New-Object System.Drawing.Point(16, 558)
    $tree.Size = New-Object System.Drawing.Size(398, 221)
    $tree.Anchor = 'Top,Bottom,Left'
    $tree.HideSelection = $false
    $tree.BackColor = $script:GuiColors.PanelAlt
    $tree.ForeColor = $script:GuiColors.Text
    $tree.BorderStyle = 'None'
    $form.Controls.Add($tree)

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Location = New-Object System.Drawing.Point(430, 272)
    $grid.Size = New-Object System.Drawing.Size(862, 342)
    $grid.Anchor = 'Top,Bottom,Left,Right'
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.ReadOnly = $true
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $false
    $grid.AutoSizeColumnsMode = 'Fill'
    $grid.RowHeadersVisible = $false
    $grid.BackgroundColor = $script:GuiColors.PanelAlt
    $grid.BorderStyle = 'None'
    $grid.GridColor = $script:GuiColors.Border
    $grid.EnableHeadersVisualStyles = $false
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $script:GuiColors.Panel
    $grid.ColumnHeadersDefaultCellStyle.ForeColor = $script:GuiColors.Text
    $grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $script:GuiColors.Panel
    $grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = $script:GuiColors.Text
    $grid.DefaultCellStyle.BackColor = $script:GuiColors.PanelAlt
    $grid.DefaultCellStyle.ForeColor = $script:GuiColors.Text
    $grid.DefaultCellStyle.SelectionBackColor = $script:GuiColors.Accent
    $grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $grid.AlternatingRowsDefaultCellStyle.BackColor = $script:GuiColors.Panel
    [void]$grid.Columns.Add('Id', 'ID')
    [void]$grid.Columns.Add('Score', 'Maks. bodovi')
    [void]$grid.Columns.Add('RiskAreaName', 'Oblast')
    [void]$grid.Columns.Add('Severity', 'Ozbiljnost')
    [void]$grid.Columns.Add('Category', 'Kategorija')
    [void]$grid.Columns.Add('Title', 'Nalaz')
    [void]$grid.Columns.Add('AffectedObject', 'Objekat / uredjaj')
    [void]$grid.Columns.Add('ObjectType', 'Tip')
    $grid.Columns['Severity'].FillWeight = 55
    $grid.Columns['Category'].FillWeight = 95
    $grid.Columns['Title'].FillWeight = 190
    $grid.Columns['AffectedObject'].FillWeight = 140
    $grid.Columns['ObjectType'].FillWeight = 70
    $form.Controls.Add($grid)

    $detailBox = New-Object System.Windows.Forms.TextBox
    $detailBox.Location = New-Object System.Drawing.Point(430, 626)
    $detailBox.Size = New-Object System.Drawing.Size(862, 153)
    $detailBox.Anchor = 'Bottom,Left,Right'
    $detailBox.Multiline = $true
    $detailBox.ScrollBars = 'Vertical'
    $detailBox.ReadOnly = $true
    $detailBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    Set-GuiInputStyle -Control $detailBox
    $form.Controls.Add($detailBox)

    $logBox = New-Object System.Windows.Forms.TextBox
    $logBox.Location = New-Object System.Drawing.Point(16, 786)
    $logBox.Size = New-Object System.Drawing.Size(1276, 28)
    $logBox.Anchor = 'Bottom,Left,Right'
    $logBox.Multiline = $true
    $logBox.ReadOnly = $true
    $logBox.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    Set-GuiInputStyle -Control $logBox
    $form.Controls.Add($logBox)
    Add-GuiLog -TextBox $logBox -Message $defaults.Status

    $btnBrowseOutput.Add_Click({
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderDialog.SelectedPath = $txtOutput.Text
        if ($folderDialog.ShowDialog() -eq 'OK') {
            $txtOutput.Text = $folderDialog.SelectedPath
        }
    })

    $btnBrowseConfig.Add_Click({
        $openDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openDialog.Filter = 'JSON config (*.json)|*.json|Svi fajlovi (*.*)|*.*'
        if ($openDialog.ShowDialog() -eq 'OK') {
            $txtConfig.Text = $openDialog.FileName
        }
    })

    $grid.Add_SelectionChanged({
        if ($grid.SelectedRows.Count -eq 0) {
            return
        }

        $finding = $grid.SelectedRows[0].Tag
        if ($null -eq $finding) {
            return
        }
        $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding

        if ((ConvertTo-CompatibleString $finding.AssessmentType) -eq 'Health') {
            $detailBox.Text = @"
ID: $($finding.Id)
Status: $($finding.StatusLabel)
Oblast: $($finding.Category)
Tezina provjere: $($metadata.RuleWeight)
Objekat: $($finding.AffectedObject)
Tip: $($finding.ObjectType)
Izvor: $($finding.Source)

Provjera:
$($finding.Title)

Dokaz:
$($finding.EvidenceText)

Preporuka:
$($finding.Recommendation)
"@
            return
        }
        $frameworkReferenceText = if ($finding.PSObject.Properties['FrameworkReferences'] -and @($finding.FrameworkReferences).Count -gt 0) {
            @($finding.FrameworkReferences | ForEach-Object {
                "$($_.Framework) $($_.Id) - $($_.Name) [$($_.Relationship)]`r`n$($_.Url)"
            }) -join "`r`n`r`n"
        }
        else {
            'Nema direktnog ili kontekstualnog ATT&CK mapiranja.'
        }
        $detailBox.Text = @"
ID: $($finding.Id)
Maks. bodovi pravila: $($metadata.RuleMaxPoints)
Oblast ocjene: $($metadata.RiskAreaName)
Model pravila: $($metadata.RuleModel)
Metod bodovanja: $($metadata.ScoringMethod)
Ozbiljnost: $(Get-SeverityLabel -Severity $finding.Severity)
Kategorija: $($finding.Category)
Objekat: $($finding.AffectedObject)
Tip: $($finding.ObjectType)

Nalaz:
$($finding.Title)

Evidence:
$($finding.EvidenceText)

Preporuka:
$($finding.Recommendation)

MITRE ATT&CK i reference:
$frameworkReferenceText
"@
    })

    $tree.Add_AfterSelect({
        if ($null -eq $tree.SelectedNode -or $null -eq $tree.SelectedNode.Tag) {
            return
        }
        $tag = $tree.SelectedNode.Tag
        Update-GuiFindingsGrid -Grid $grid -DetailBox $detailBox -Findings $script:GuiState.Findings -Mode $tag.Mode -Value $tag.Value
        Add-GuiLog -TextBox $logBox -Message "Filter: $($tree.SelectedNode.Text)"
    })

    $btnClearFilter.Add_Click({
        Update-GuiFindingsGrid -Grid $grid -DetailBox $detailBox -Findings $script:GuiState.Findings -Mode 'All' -Value ''
        Add-GuiLog -TextBox $logBox -Message 'Filter ociscen.'
    })

    $btnOpenFolder.Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($script:GuiState.ReportPath) -and (Test-Path -LiteralPath $script:GuiState.ReportPath)) {
            Invoke-Item -LiteralPath $script:GuiState.ReportPath
        }
    })

    $btnSaveHtml.Add_Click({
        if ($null -eq $script:GuiState.Summary) {
            [System.Windows.Forms.MessageBox]::Show('Nema rezultata za export.', 'Export', 'OK', 'Information') | Out-Null
            return
        }

        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = 'HTML izvjestaj (*.html)|*.html'
        $assessmentName = if ($script:GuiState.Summary.PSObject.Properties['AssessmentType'] -and $script:GuiState.Summary.AssessmentType -eq 'Health') { 'AD-Health' } else { 'AD-Security' }
        $saveDialog.FileName = "$assessmentName-$($script:GuiState.Summary.ClientName).html"
        if ($saveDialog.ShowDialog() -eq 'OK') {
            $sourceHtml = Join-Path $script:GuiState.ReportPath 'report.html'
            if (-not (Test-Path -LiteralPath $sourceHtml)) {
                throw "Generisani HTML report nije pronadjen: $sourceHtml"
            }
            Copy-Item -LiteralPath $sourceHtml -Destination $saveDialog.FileName -Force
            Add-GuiLog -TextBox $logBox -Message "HTML sacuvan: $($saveDialog.FileName)"
        }
    })

    $btnSavePdf.Add_Click({
        if ($null -eq $script:GuiState.Summary) {
            [System.Windows.Forms.MessageBox]::Show('Nema rezultata za export.', 'Export', 'OK', 'Information') | Out-Null
            return
        }

        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = 'PDF izvjestaj (*.pdf)|*.pdf'
        $assessmentName = if ($script:GuiState.Summary.PSObject.Properties['AssessmentType'] -and $script:GuiState.Summary.AssessmentType -eq 'Health') { 'AD-Health' } else { 'AD-Security' }
        $saveDialog.FileName = "$assessmentName-$($script:GuiState.Summary.ClientName).pdf"
        if ($saveDialog.ShowDialog() -eq 'OK') {
            try {
                $sourceHtml = Join-Path $script:GuiState.ReportPath 'report.html'
                if (-not (Test-Path -LiteralPath $sourceHtml)) {
                    throw "Generisani HTML report nije pronadjen: $sourceHtml"
                }
                Convert-HtmlReportToPdf -HtmlPath $sourceHtml -PdfPath $saveDialog.FileName
                Add-GuiLog -TextBox $logBox -Message "PDF sacuvan: $($saveDialog.FileName)"
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'PDF export nije uspio', 'OK', 'Error') | Out-Null
            }
        }
    })

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    $timer.Add_Tick({
        $run = $script:GuiState.ActiveRun
        if ($null -eq $run -or $null -eq $run.Process) {
            return
        }

        if (-not $run.Process.HasExited) {
            return
        }

        $timer.Stop()
        $exitCode = $run.Process.ExitCode
        try {
            $stdoutText = $run.Process.StandardOutput.ReadToEnd()
            $stderrText = $run.Process.StandardError.ReadToEnd()
            $stdoutText | Set-Content -LiteralPath $run.StdOutPath -Encoding ASCII
            $stderrText | Set-Content -LiteralPath $run.StdErrPath -Encoding ASCII
        }
        catch {
        }
        $run.Process.Dispose()

        $btnStart.Enabled = $true
        $btnHealthStart.Enabled = $true
        $btnSaveHtml.Enabled = $false
        $btnSavePdf.Enabled = $false
        $btnOpenFolder.Enabled = $false
        $btnClearFilter.Enabled = $false

        if ($exitCode -ne 0) {
            $stdErr = if (Test-Path -LiteralPath $run.StdErrPath) { Get-Content -LiteralPath $run.StdErrPath -Raw } else { '' }
            $stdOut = if (Test-Path -LiteralPath $run.StdOutPath) { Get-Content -LiteralPath $run.StdOutPath -Raw } else { '' }
            $message = "Analyzer nije uspio. Exit code $exitCode."
            $details = (($stdErr, $stdOut) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
            if (-not [string]::IsNullOrWhiteSpace($details)) {
                $message = "$message`r`n`r`n$details"
            }

            Add-GuiLog -TextBox $logBox -Message "Greska: analyzer proces je zavrsio sa code $exitCode."
            [System.Windows.Forms.MessageBox]::Show($message, 'Analyzer nije uspio', 'OK', 'Error') | Out-Null
            $script:GuiState.ActiveRun = $null
            return
        }

        try {
            Add-GuiLog -TextBox $logBox -Message 'Ucitavam generisane rezultate...'
            $result = Read-GuiAnalyzerResult -Settings $run.Settings -StartTime $run.StartTime -StdOutPath $run.StdOutPath -StdErrPath $run.StdErrPath
        }
        catch {
            Add-GuiLog -TextBox $logBox -Message "Greska: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Analyzer nije uspio', 'OK', 'Error') | Out-Null
            $script:GuiState.ActiveRun = $null
            return
        }

        $script:GuiState.Summary = $result.Summary
        $script:GuiState.Findings = @($result.Findings)
        $script:GuiState.Warnings = @($result.Warnings)
        $script:GuiState.ReportPath = $result.ReportPath

        Update-GuiSummary -Summary $result.Summary -Cards $cards -CardLabels $cardLabels -BaselineLabel $riskBaselineLabel
        $isHealthResult = $result.Summary.PSObject.Properties['AssessmentType'] -and $result.Summary.AssessmentType -eq 'Health'
        $grid.Columns['Score'].HeaderText = if ($isHealthResult) { 'Tezina' } else { 'Maks. bodovi' }
        $grid.Columns['Severity'].HeaderText = if ($isHealthResult) { 'Health status' } else { 'Ozbiljnost' }
        Update-GuiFindingsGrid -Grid $grid -DetailBox $detailBox -Findings $script:GuiState.Findings -Mode 'All' -Value ''
        Update-GuiFilterTree -Tree $tree -Findings $script:GuiState.Findings

        $hasHtmlReport = Test-Path -LiteralPath $result.HtmlReport
        $btnSaveHtml.Enabled = $hasHtmlReport
        $btnSavePdf.Enabled = $hasHtmlReport
        $btnOpenFolder.Enabled = $true
        $btnClearFilter.Enabled = $true
        if (-not $hasHtmlReport) {
            Add-GuiLog -TextBox $logBox -Message 'HTML report nije generisan; JSON rezultati i report folder su dostupni.'
        }
        Add-GuiLog -TextBox $logBox -Message "Gotovo. Report folder: $($result.ReportPath)"
        $script:GuiState.ActiveRun = $null
    })

    function Start-WinFormsAssessment {
        param(
            [ValidateSet('Security', 'Health')]
            [string]$ScanType
        )

        if ($null -ne $script:GuiState.ActiveRun -and $null -ne $script:GuiState.ActiveRun.Process -and -not $script:GuiState.ActiveRun.Process.HasExited) {
            return
        }

        if ([string]::IsNullOrWhiteSpace($txtClient.Text)) {
            [System.Windows.Forms.MessageBox]::Show('Polje Domena / klijent je obavezno.', 'Nedostaje vrijednost', 'OK', 'Warning') | Out-Null
            return
        }

        $settings = @{
            ScanType = $ScanType
            ClientName = $txtClient.Text.Trim()
            Server = $txtServer.Text.Trim()
            OutputPath = $txtOutput.Text.Trim()
            ConfigPath = $txtConfig.Text.Trim()
            NoCsv = [bool]$chkNoCsv.Checked
        }

        if ($ScanType -eq 'Security') {
            $settings.StaleUserDays = [int]$numericBoxes['StaleUserDays'].Value
            $settings.StaleComputerDays = [int]$numericBoxes['StaleComputerDays'].Value
            $settings.PrivilegedStaleDays = [int]$numericBoxes['PrivilegedStaleDays'].Value
            $settings.MaxPasswordAgeDays = $MaxPasswordAgeDays
            $settings.ServiceAccountPasswordAgeDays = $ServiceAccountPasswordAgeDays
            $settings.KrbtgtMaxPasswordAgeDays = [int]$numericBoxes['KrbtgtMaxPasswordAgeDays'].Value
            $settings.MinPasswordLength = [int]$numericBoxes['MinPasswordLength'].Value
            $settings.MinPasswordHistory = $MinPasswordHistory
            $settings.MaxDomainAdmins = $MaxDomainAdmins
            $settings.MaxEnterpriseAdmins = $MaxEnterpriseAdmins
            $settings.FailedLoginLookbackHours = $FailedLoginLookbackHours
            $settings.FailedLoginMediumThreshold = $FailedLoginMediumThreshold
            $settings.FailedLoginHighThreshold = $FailedLoginHighThreshold
            $settings.FailedLoginAccountThreshold = $FailedLoginAccountThreshold
            $settings.FailedLoginMaxEventsPerDc = $FailedLoginMaxEventsPerDc
            $settings.FailedLoginQueryTimeoutSeconds = $FailedLoginQueryTimeoutSeconds
            $settings.SkipFailedLoginAudit = [bool]$SkipFailedLoginAudit
            $settings.AuditPasswordExpiration = [bool]$chkAuditExpiration.Checked
        }

        $btnStart.Enabled = $false
        $btnHealthStart.Enabled = $false
        $btnSaveHtml.Enabled = $false
        $btnSavePdf.Enabled = $false
        $btnOpenFolder.Enabled = $false
        $btnClearFilter.Enabled = $false
        $grid.Rows.Clear()
        $tree.Nodes.Clear()
        $detailBox.Text = ''
        $scanLabel = if ($ScanType -eq 'Health') { 'AD Health Test' } else { 'AD Security Test' }
        Add-GuiLog -TextBox $logBox -Message "Pokrecem $scanLabel za $($settings.ClientName)..."
        try {
            $script:GuiState.ActiveRun = Start-GuiAnalyzerProcess -Settings $settings
            Add-GuiLog -TextBox $logBox -Message "$scanLabel proces pokrenut. PID: $($script:GuiState.ActiveRun.Process.Id)"
            $timer.Start()
        }
        catch {
            $btnStart.Enabled = $true
            $btnHealthStart.Enabled = $true
            Add-GuiLog -TextBox $logBox -Message "Greska: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Analyzer nije uspio', 'OK', 'Error') | Out-Null
        }
    }

    $btnStart.Add_Click({
        Start-WinFormsAssessment -ScanType 'Security'
    })

    $btnHealthStart.Add_Click({
        Start-WinFormsAssessment -ScanType 'Health'
    })

    $form.Add_FormClosing({
        $run = $script:GuiState.ActiveRun
        if ($null -ne $run -and $null -ne $run.Process -and -not $run.Process.HasExited) {
            try {
                $run.Process.Kill()
            }
            catch {
            }
        }
    })

    [void]$form.ShowDialog()
}

function Show-ADSecurityRiskAnalyzerWpfGui {
    param(
        [string]$InitialClientName,
        [string]$InitialServer,
        [string]$InitialOutputPath,
        [string]$InitialConfigPath
    )

    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Xaml
    Add-Type -AssemblyName System.Windows.Forms

    if (-not ('ADRiskWindowStyle' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class ADRiskWindowStyle {
    private const int GWL_STYLE = -16;
    private const UInt32 WS_CAPTION = 0x00C00000;
    private const UInt32 WS_SYSMENU = 0x00080000;
    private const UInt32 WS_THICKFRAME = 0x00040000;
    private const UInt32 WS_MINIMIZEBOX = 0x00020000;
    private const UInt32 WS_MAXIMIZEBOX = 0x00010000;
    private const UInt32 SWP_NOSIZE = 0x0001;
    private const UInt32 SWP_NOMOVE = 0x0002;
    private const UInt32 SWP_NOZORDER = 0x0004;
    private const UInt32 SWP_FRAMECHANGED = 0x0020;

    [DllImport("user32.dll", EntryPoint = "GetWindowLong")]
    private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtr")]
    private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "SetWindowLong")]
    private static extern int SetWindowLong32(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtr")]
    private static extern IntPtr SetWindowLongPtr64(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

    [DllImport("user32.dll")]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, UInt32 uFlags);

    private static IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex) {
        if (IntPtr.Size == 8) {
            return GetWindowLongPtr64(hWnd, nIndex);
        }
        return new IntPtr(GetWindowLong32(hWnd, nIndex));
    }

    private static IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong) {
        if (IntPtr.Size == 8) {
            return SetWindowLongPtr64(hWnd, nIndex, dwNewLong);
        }
        return new IntPtr(SetWindowLong32(hWnd, nIndex, dwNewLong.ToInt32()));
    }

    public static void Apply(IntPtr hWnd) {
        long style = GetWindowLongPtr(hWnd, GWL_STYLE).ToInt64();
        style |= WS_CAPTION;
        style |= WS_SYSMENU;
        style |= WS_THICKFRAME;
        style |= WS_MINIMIZEBOX;
        style |= WS_MAXIMIZEBOX;
        SetWindowLongPtr(hWnd, GWL_STYLE, new IntPtr(style));
        SetWindowPos(hWnd, IntPtr.Zero, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }
}
'@
    }

    $defaults = Get-GuiAutoDefaults
    $script:GuiState = [ordered]@{
        Summary = $null
        Findings = @()
        Warnings = @()
        ReportPath = ''
        ActiveRun = $null
    }

    [xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AD Security / Health Analyzer"
        Width="1180" Height="740" MinWidth="820" MinHeight="650"
        WindowStartupLocation="CenterScreen"
        WindowStyle="SingleBorderWindow"
        ResizeMode="CanResizeWithGrip"
        ShowInTaskbar="True"
        SizeToContent="Manual"
        Background="#0F172A"
        Foreground="#E2E8F0"
        FontFamily="Segoe UI"
        FontSize="13"
        UseLayoutRounding="True"
        SnapsToDevicePixels="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Bg" Color="#0F172A"/>
    <SolidColorBrush x:Key="Panel" Color="#111827"/>
    <SolidColorBrush x:Key="Panel2" Color="#1E293B"/>
    <SolidColorBrush x:Key="Text" Color="#E2E8F0"/>
    <SolidColorBrush x:Key="Muted" Color="#94A3B8"/>
    <SolidColorBrush x:Key="Border" Color="#334155"/>
    <SolidColorBrush x:Key="Accent" Color="#2563EB"/>

    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
    </Style>

    <Style TargetType="Label">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="Padding" Value="0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#0B1220"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="9,5"/>
      <Setter Property="CaretBrush" Value="{StaticResource Text}"/>
      <Setter Property="MinHeight" Value="30"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8">
              <ScrollViewer x:Name="PART_ContentHost" Margin="2"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Panel2}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="14,8"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="MinHeight" Value="34"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Root" Background="{TemplateBinding Background}" CornerRadius="9">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Root" Property="Opacity" Value="0.86"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Root" Property="Opacity" Value="0.35"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>

    <Style TargetType="TreeView">
      <Setter Property="Background" Value="{StaticResource Panel}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="6"/>
    </Style>

    <Style TargetType="TreeViewItem">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="Margin" Value="0,2"/>
    </Style>

    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="{StaticResource Panel}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="GridLinesVisibility" Value="None"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="RowBackground" Value="#111827"/>
      <Setter Property="AlternatingRowBackground" Value="#172033"/>
      <Setter Property="SelectionUnit" Value="FullRow"/>
      <Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
    </Style>

    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#1E293B"/>
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,5"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#2563EB"/>
          <Setter Property="Foreground" Value="White"/>
        </Trigger>
      </Style.Triggers>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <Border x:Name="HeaderBar" Grid.Row="0" Background="#020617" Padding="18,14">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock Text="AD Security / Health Analyzer" FontSize="28" FontWeight="SemiBold"/>
          <TextBlock Text="Read-only AD security i health provjera, izvjestaji i export" Foreground="{StaticResource Muted}" Margin="1,3,0,0"/>
        </StackPanel>
        <TextBlock Grid.Column="1" Text="Created by: Adis Hadzovic" FontWeight="SemiBold" Foreground="{StaticResource Text}" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="24,0,0,0"/>
      </Grid>
    </Border>

    <Grid Grid.Row="1" Margin="16">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="300" MinWidth="260"/>
        <ColumnDefinition Width="12"/>
        <ColumnDefinition Width="*" MinWidth="420"/>
      </Grid.ColumnDefinitions>

      <Border Grid.Column="0" Background="{StaticResource Panel}" CornerRadius="16" Padding="16">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <ScrollViewer Grid.Row="0" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel>
            <TextBlock Text="Postavke skena" FontSize="16" FontWeight="SemiBold"/>
            <TextBlock Text="Standardni baseline je vec upisan. Mijenjati samo za odobrenu politiku." TextWrapping="Wrap" Foreground="{StaticResource Muted}" Margin="0,4,0,14"/>

            <Label Content="Domena / klijent"/>
            <TextBox x:Name="ClientText" Margin="0,4,0,10"/>

            <Label Content="Domenski kontroler"/>
            <TextBox x:Name="ServerText" Margin="0,4,0,10"/>

            <Label Content="Report folder"/>
            <Grid Margin="0,4,0,10">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="8"/>
                <ColumnDefinition Width="42"/>
              </Grid.ColumnDefinitions>
              <TextBox x:Name="OutputText"/>
              <Button x:Name="BrowseOutputButton" Grid.Column="2" Content="..."/>
            </Grid>

            <Label Content="Config fajl"/>
            <Grid Margin="0,4,0,12">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="8"/>
                <ColumnDefinition Width="42"/>
              </Grid.ColumnDefinitions>
              <TextBox x:Name="ConfigText"/>
              <Button x:Name="BrowseConfigButton" Grid.Column="2" Content="..."/>
            </Grid>

            <CheckBox x:Name="AuditCheck" Content="Audit isteka lozinki"/>
            <CheckBox x:Name="NoCsvCheck" Content="Preskoci CSV export" Margin="0,4,0,14"/>

            <Grid>
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="86"/>
              </Grid.ColumnDefinitions>
              <Grid.RowDefinitions>
                <RowDefinition Height="38"/>
                <RowDefinition Height="38"/>
                <RowDefinition Height="38"/>
                <RowDefinition Height="38"/>
                <RowDefinition Height="38"/>
              </Grid.RowDefinitions>
              <Label Grid.Row="0" Content="Neaktivni useri (90d)"/>
              <TextBox x:Name="StaleUsersText" Grid.Row="0" Grid.Column="1"/>
              <Label Grid.Row="1" Content="Neaktivni PC-evi (45d)"/>
              <TextBox x:Name="StaleComputersText" Grid.Row="1" Grid.Column="1"/>
              <Label Grid.Row="2" Content="Priv. nalozi (180d)"/>
              <TextBox x:Name="PrivStaleText" Grid.Row="2" Grid.Column="1"/>
              <Label Grid.Row="3" Content="Min lozinka (15)"/>
              <TextBox x:Name="MinPasswordText" Grid.Row="3" Grid.Column="1"/>
              <Label Grid.Row="4" Content="krbtgt starost (180d)"/>
              <TextBox x:Name="KrbtgtAgeText" Grid.Row="4" Grid.Column="1"/>
            </Grid>

            </StackPanel>
          </ScrollViewer>
          <Grid Grid.Row="1" Margin="0,14,0,0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="8"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Button x:Name="SecurityStartButton" Background="{StaticResource Accent}" FontWeight="SemiBold" FontSize="12" MinHeight="48">
              <TextBlock Text="Pokreni AD Security Test" TextWrapping="Wrap" TextAlignment="Center"/>
            </Button>
            <Button x:Name="HealthStartButton" Grid.Column="2" Background="#0F766E" FontWeight="SemiBold" FontSize="12" MinHeight="48">
              <TextBlock Text="Pokreni AD Health Test" TextWrapping="Wrap" TextAlignment="Center"/>
            </Button>
          </Grid>
        </Grid>
      </Border>

      <GridSplitter Grid.Column="1" Width="4" HorizontalAlignment="Center" Background="#1E293B" ShowsPreview="True"/>

      <Grid Grid.Column="2">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="96"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="{StaticResource Panel}" CornerRadius="16" Padding="14">
          <StackPanel>
            <TextBlock Text="Pregled" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,10"/>
            <UniformGrid Columns="5" Rows="2">
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="RiskValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock x:Name="RiskLabel" Text="Rizik" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="TotalValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock x:Name="TotalLabel" Text="Ukupno" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="CriticalValue" Text="-" FontSize="22" FontWeight="SemiBold" Foreground="#F87171"/><TextBlock x:Name="CriticalLabel" Text="Kriticno" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="HighValue" Text="-" FontSize="22" FontWeight="SemiBold" Foreground="#FB7185"/><TextBlock x:Name="HighLabel" Text="Visoko" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="MediumValue" Text="-" FontSize="22" FontWeight="SemiBold" Foreground="#FBBF24"/><TextBlock x:Name="MediumLabel" Text="Srednje" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="LowValue" Text="-" FontSize="22" FontWeight="SemiBold" Foreground="#60A5FA"/><TextBlock x:Name="LowLabel" Text="Nisko" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="InfoValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock x:Name="InfoLabel" Text="Info" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="UsersValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock x:Name="UsersLabel" Text="Useri" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="PcsValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock x:Name="PcsLabel" Text="PCs" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="DcsValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock x:Name="DcsLabel" Text="DCs" Foreground="{StaticResource Muted}"/></StackPanel></Border>
            </UniformGrid>
            <TextBlock x:Name="RiskBaselineText" Text="Ocjena rizika: 0 je najbolje, 100 je najgore." Foreground="{StaticResource Muted}" FontSize="12" Margin="6,8,6,0" TextWrapping="Wrap"/>
          </StackPanel>
        </Border>

        <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,12,0,12">
          <Button x:Name="SaveHtmlButton" Content="Sacuvaj HTML" IsEnabled="False" Margin="0,0,8,0"/>
          <Button x:Name="SavePdfButton" Content="Sacuvaj PDF" IsEnabled="False" Margin="0,0,8,0"/>
          <Button x:Name="OpenFolderButton" Content="Otvori report folder" IsEnabled="False" Margin="0,0,8,0"/>
          <Button x:Name="ClearFilterButton" Content="Ocisti filter" IsEnabled="False"/>
        </StackPanel>

        <Grid Grid.Row="2">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="215" MinWidth="170"/>
            <ColumnDefinition Width="12"/>
            <ColumnDefinition Width="*" MinWidth="280"/>
          </Grid.ColumnDefinitions>
          <Border Background="{StaticResource Panel}" CornerRadius="16" Padding="8">
            <TreeView x:Name="FilterTree"/>
          </Border>
          <GridSplitter Grid.Column="1" Width="4" HorizontalAlignment="Center" Background="#1E293B" ShowsPreview="True"/>
          <Border Grid.Column="2" Background="{StaticResource Panel}" CornerRadius="16" Padding="8">
            <DataGrid x:Name="FindingsGrid">
              <DataGrid.Columns>
                <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="108"/>
                <DataGridTextColumn x:Name="ScoreColumn" Header="Maks. bodovi" Binding="{Binding Score}" Width="86"/>
                <DataGridTextColumn Header="Oblast" Binding="{Binding RiskAreaName}" Width="135"/>
                <DataGridTextColumn x:Name="SeverityColumn" Header="Ozbiljnost" Binding="{Binding SeverityLabel}" Width="92"/>
                <DataGridTextColumn Header="Kategorija" Binding="{Binding Category}" Width="150"/>
                <DataGridTextColumn Header="Nalaz" Binding="{Binding Title}" Width="*"/>
                <DataGridTextColumn Header="Objekat / uredjaj" Binding="{Binding AffectedObject}" Width="165"/>
                <DataGridTextColumn Header="Tip" Binding="{Binding ObjectType}" Width="95"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
        </Grid>

        <Border Grid.Row="3" Background="{StaticResource Panel}" CornerRadius="16" Padding="10" Margin="0,12,0,0">
          <TextBox x:Name="DetailText" Text="Prikazano nalaza: 0" TextWrapping="Wrap" AcceptsReturn="True" VerticalScrollBarVisibility="Auto" IsReadOnly="True" BorderThickness="0" Background="{StaticResource Panel}"/>
        </Border>
      </Grid>
    </Grid>

    <Border Grid.Row="2" Background="#020617" Padding="16,8">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="LogText" Grid.Column="0" Text="Spremno." Foreground="{StaticResource Muted}" TextWrapping="NoWrap" TextTrimming="CharacterEllipsis"/>
        <TextBlock Grid.Column="1" Text="Kodeks d.o.o. Sarajevo" Foreground="{StaticResource Muted}" FontWeight="SemiBold" Margin="16,0,0,0" HorizontalAlignment="Right"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $window.ResizeMode = [System.Windows.ResizeMode]::CanResizeWithGrip
    $window.WindowStyle = [System.Windows.WindowStyle]::SingleBorderWindow
    $window.ShowInTaskbar = $true
    $window.WindowState = [System.Windows.WindowState]::Normal
    $window.Add_SourceInitialized({
        try {
            $helper = New-Object System.Windows.Interop.WindowInteropHelper($window)
            [ADRiskWindowStyle]::Apply($helper.Handle)
        }
        catch {
        }
    })

    function Get-WpfControl {
        param([string]$Name)
        return $window.FindName($Name)
    }

    $headerBar = Get-WpfControl 'HeaderBar'
    $clientText = Get-WpfControl 'ClientText'
    $serverText = Get-WpfControl 'ServerText'
    $outputText = Get-WpfControl 'OutputText'
    $configText = Get-WpfControl 'ConfigText'
    $auditCheck = Get-WpfControl 'AuditCheck'
    $noCsvCheck = Get-WpfControl 'NoCsvCheck'
    $staleUsersText = Get-WpfControl 'StaleUsersText'
    $staleComputersText = Get-WpfControl 'StaleComputersText'
    $privStaleText = Get-WpfControl 'PrivStaleText'
    $minPasswordText = Get-WpfControl 'MinPasswordText'
    $krbtgtAgeText = Get-WpfControl 'KrbtgtAgeText'
    $browseOutputButton = Get-WpfControl 'BrowseOutputButton'
    $browseConfigButton = Get-WpfControl 'BrowseConfigButton'
    $securityStartButton = Get-WpfControl 'SecurityStartButton'
    $healthStartButton = Get-WpfControl 'HealthStartButton'
    $saveHtmlButton = Get-WpfControl 'SaveHtmlButton'
    $savePdfButton = Get-WpfControl 'SavePdfButton'
    $openFolderButton = Get-WpfControl 'OpenFolderButton'
    $clearFilterButton = Get-WpfControl 'ClearFilterButton'
    $filterTree = Get-WpfControl 'FilterTree'
    $findingsGrid = Get-WpfControl 'FindingsGrid'
    $detailText = Get-WpfControl 'DetailText'
    $logText = Get-WpfControl 'LogText'
    $riskBaselineText = Get-WpfControl 'RiskBaselineText'
    $scoreColumn = Get-WpfControl 'ScoreColumn'
    $severityColumn = Get-WpfControl 'SeverityColumn'

    $valueControls = @{
        Risk = Get-WpfControl 'RiskValue'
        Total = Get-WpfControl 'TotalValue'
        Critical = Get-WpfControl 'CriticalValue'
        High = Get-WpfControl 'HighValue'
        Medium = Get-WpfControl 'MediumValue'
        Low = Get-WpfControl 'LowValue'
        Info = Get-WpfControl 'InfoValue'
        Users = Get-WpfControl 'UsersValue'
        Computers = Get-WpfControl 'PcsValue'
        DCs = Get-WpfControl 'DcsValue'
    }
    $labelControls = @{
        Risk = Get-WpfControl 'RiskLabel'
        Total = Get-WpfControl 'TotalLabel'
        Critical = Get-WpfControl 'CriticalLabel'
        High = Get-WpfControl 'HighLabel'
        Medium = Get-WpfControl 'MediumLabel'
        Low = Get-WpfControl 'LowLabel'
        Info = Get-WpfControl 'InfoLabel'
        Users = Get-WpfControl 'UsersLabel'
        Computers = Get-WpfControl 'PcsLabel'
        DCs = Get-WpfControl 'DcsLabel'
    }

    $clientText.Text = if ([string]::IsNullOrWhiteSpace($InitialClientName)) { $defaults.Domain } else { $InitialClientName }
    $serverText.Text = if ([string]::IsNullOrWhiteSpace($InitialServer)) { $defaults.Server } else { $InitialServer }
    $outputText.Text = if ([string]::IsNullOrWhiteSpace($InitialOutputPath)) { $defaults.OutputPath } else { $InitialOutputPath }
    $configText.Text = $InitialConfigPath
    $staleUsersText.Text = [string]$StaleUserDays
    $staleComputersText.Text = [string]$StaleComputerDays
    $privStaleText.Text = [string]$PrivilegedStaleDays
    $minPasswordText.Text = [string]$MinPasswordLength
    $krbtgtAgeText.Text = [string]$KrbtgtMaxPasswordAgeDays

    $logMessages = New-Object System.Collections.Generic.List[string]

    function Add-WpfLog {
        param([string]$Message)
        if ([string]::IsNullOrWhiteSpace($Message)) {
            return
        }
        $logMessages.Add("[$((Get-Date).ToString('HH:mm:ss'))] $Message") | Out-Null
        while ($logMessages.Count -gt 3) {
            $logMessages.RemoveAt(0)
        }
        $logText.Text = ($logMessages -join '    ')
    }

    $headerBar.Add_MouseLeftButtonDown({
        param($sender, $eventArgs)
        if ($eventArgs.ClickCount -ge 2) {
            if ($window.WindowState -eq [System.Windows.WindowState]::Maximized) {
                $window.WindowState = [System.Windows.WindowState]::Normal
            }
            else {
                $window.WindowState = [System.Windows.WindowState]::Maximized
            }
            return
        }

        try {
            $window.DragMove()
        }
        catch {
        }
    })

    function Set-WpfActionsEnabled {
        param(
            [bool]$Enabled,
            [bool]$HtmlAvailable = $Enabled
        )
        $saveHtmlButton.IsEnabled = ($Enabled -and $HtmlAvailable)
        $savePdfButton.IsEnabled = ($Enabled -and $HtmlAvailable)
        $openFolderButton.IsEnabled = $Enabled
        $clearFilterButton.IsEnabled = $Enabled
    }

    function Set-WpfRunButtonsEnabled {
        param([bool]$Enabled)
        $securityStartButton.IsEnabled = $Enabled
        $healthStartButton.IsEnabled = $Enabled
    }

    function Get-WpfIntValue {
        param(
            [System.Windows.Controls.TextBox]$TextBox,
            [string]$Name
        )
        $value = 0
        if (-not [int]::TryParse($TextBox.Text.Trim(), [ref]$value) -or $value -lt 0) {
            throw "Vrijednost mora biti pozitivan broj: $Name"
        }
        return $value
    }

    function Set-WpfSummary {
        param([object]$Summary)
        $isHealth = $Summary.PSObject.Properties['AssessmentType'] -and $Summary.AssessmentType -eq 'Health'
        if ($isHealth) {
            $healthScoreDisplay = if ($Summary.PSObject.Properties['HealthScoreDisplay']) { [string]$Summary.HealthScoreDisplay } elseif ($null -eq $Summary.HealthScore) { 'N/A' } else { [string]$Summary.HealthScore }
            $valueControls.Risk.Text = $healthScoreDisplay
            $valueControls.Total.Text = [string]$Summary.TotalChecks
            $valueControls.Critical.Text = [string]$Summary.Failed
            $valueControls.High.Text = [string]$Summary.Warnings
            $valueControls.Medium.Text = [string]$Summary.Passed
            $valueControls.Low.Text = [string]$Summary.NotAssessed
            $valueControls.Info.Text = "$($Summary.HealthCoveragePercent)%"
            $valueControls.Users.Text = [string]$Summary.CategoriesHealthy
            $valueControls.Computers.Text = [string]$Summary.CategoriesTotal
            $valueControls.DCs.Text = [string]$Summary.DomainControllers
            $labelControls.Risk.Text = 'Health score'
            $labelControls.Total.Text = 'Provjere'
            $labelControls.Critical.Text = 'Neispravno'
            $labelControls.High.Text = 'Upozorenje'
            $labelControls.Medium.Text = 'Proslo'
            $labelControls.Low.Text = 'Nije proc.'
            $labelControls.Info.Text = 'Coverage'
            $labelControls.Users.Text = 'Zdrave oblasti'
            $labelControls.Computers.Text = 'Oblasti'
            $labelControls.DCs.Text = 'DCs'
            if ($null -ne $scoreColumn) { $scoreColumn.Header = 'Tezina' }
            if ($null -ne $severityColumn) { $severityColumn.Header = 'Health status' }
            $riskBaselineText.Text = "Health score: $healthScoreDisplay$(if ($healthScoreDisplay -ne 'N/A') { '/100' }) - $($Summary.HealthStatus). 100 je najbolje. Coverage: $($Summary.HealthCoveragePercent)%."
            return
        }

        $valueControls.Risk.Text = [string]$Summary.RiskScore
        $valueControls.Total.Text = [string]$Summary.TotalFindings
        $valueControls.Critical.Text = [string]$Summary.Critical
        $valueControls.High.Text = [string]$Summary.High
        $valueControls.Medium.Text = [string]$Summary.Medium
        $valueControls.Low.Text = [string]$Summary.Low
        $valueControls.Info.Text = [string]$Summary.Info
        $valueControls.Users.Text = [string]$Summary.Users
        $valueControls.Computers.Text = [string]$Summary.Computers
        $valueControls.DCs.Text = [string]$Summary.DomainControllers
        $labelControls.Risk.Text = 'Rizik'
        $labelControls.Total.Text = 'Ukupno'
        $labelControls.Critical.Text = 'Kriticno'
        $labelControls.High.Text = 'Visoko'
        $labelControls.Medium.Text = 'Srednje'
        $labelControls.Low.Text = 'Nisko'
        $labelControls.Info.Text = 'Info'
        $labelControls.Users.Text = 'Useri'
        $labelControls.Computers.Text = 'PCs'
        $labelControls.DCs.Text = 'DCs'
        if ($null -ne $scoreColumn) { $scoreColumn.Header = 'Maks. bodovi' }
        if ($null -ne $severityColumn) { $severityColumn.Header = 'Ozbiljnost' }
        if ($null -ne $riskBaselineText) {
            if ($Summary.PSObject.Properties['RiskBaseline'] -and $null -ne $Summary.RiskBaseline) {
                $riskBaselineText.Text = "Ocjena rizika: $($Summary.RiskScore) - $($Summary.RiskBaseline.BandLabel). $($Summary.RiskBaseline.BaselineComparison) 0 je najbolje, 100 je najgore."
            }
            else {
                $riskBaselineText.Text = 'Ocjena rizika: 0 je najbolje, 100 je najgore.'
            }
        }
    }

    function Set-WpfFindings {
        param(
            [object[]]$Findings,
            [string]$Mode = 'All',
            [string]$Value = ''
        )

        $allFindings = ConvertTo-GuiFindingArray -InputObject $Findings
        $filtered = Select-GuiFindings -Findings $allFindings -Mode $Mode -Value $Value

        $rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
        foreach ($finding in @($filtered | Sort-Object -Property Score -Descending)) {
            $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
            $isHealthFinding = (ConvertTo-CompatibleString $finding.AssessmentType) -eq 'Health'
            $rows.Add([pscustomobject]@{
                Id = $finding.Id
                Score = $metadata.RuleWeight
                RiskAreaName = $metadata.RiskAreaName
                SeverityLabel = if ($isHealthFinding -and $finding.PSObject.Properties['StatusLabel']) { $finding.StatusLabel } else { Get-SeverityLabel -Severity $finding.Severity }
                Category = $finding.Category
                Title = $finding.Title
                AffectedObject = $finding.AffectedObject
                ObjectType = $finding.ObjectType
                Finding = $finding
            }) | Out-Null
        }

        $findingsGrid.ItemsSource = $rows
        if ($rows.Count -eq 0 -and $allFindings.Count -gt 0 -and $Mode -ne 'All') {
            $detailText.Text = "Prikazano nalaza: 0. Filter nema match u ucitanim nalazima: $Mode = $Value"
        }
        else {
            $detailText.Text = "Prikazano nalaza: $($rows.Count)"
        }
    }

    function New-WpfTreeItem {
        param(
            [string]$Header,
            [string]$Mode,
            [string]$Value
        )
        $item = New-Object System.Windows.Controls.TreeViewItem
        $item.Header = $Header
        $item.Tag = "$Mode`t$Value"
        return $item
    }

    function Set-WpfFilterTree {
        param(
            [object[]]$Findings,
            [object]$Summary
        )

        $allFindings = ConvertTo-GuiFindingArray -InputObject $Findings
        $filterTree.Items.Clear()
        $isHealth = $null -ne $Summary -and $Summary.PSObject.Properties['AssessmentType'] -and $Summary.AssessmentType -eq 'Health'
        $totalCount = if ($isHealth -and $Summary.PSObject.Properties['TotalChecks']) {
            [int]$Summary.TotalChecks
        }
        elseif ($null -ne $Summary -and $Summary.PSObject.Properties['TotalFindings']) {
            [int]$Summary.TotalFindings
        }
        else {
            $allFindings.Count
        }
        $allHeader = if ($isHealth) { "Sve provjere ($totalCount)" } else { "Svi nalazi ($totalCount)" }
        $filterTree.Items.Add((New-WpfTreeItem -Header $allHeader -Mode 'All' -Value '')) | Out-Null

        $severityRoot = New-Object System.Windows.Controls.TreeViewItem
        if ($isHealth) {
            $severityRoot.Header = 'Health status'
            foreach ($statusDefinition in @(
                    @{ Value = 'Fail'; Label = 'Neispravno' },
                    @{ Value = 'Warning'; Label = 'Upozorenje' },
                    @{ Value = 'Pass'; Label = 'Proslo' },
                    @{ Value = 'NotAssessed'; Label = 'Nije procijenjeno' },
                    @{ Value = 'NotApplicable'; Label = 'Nije primjenjivo' }
                )) {
                $count = @($allFindings | Where-Object { $_.Status -eq $statusDefinition.Value }).Count
                $severityRoot.Items.Add((New-WpfTreeItem -Header "$($statusDefinition.Label) ($count)" -Mode 'HealthStatus' -Value $statusDefinition.Value)) | Out-Null
            }
        }
        else {
            $severityRoot.Header = 'Ozbiljnost'
            foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
                $summaryProperty = switch ($severity) {
                    'Critical' { 'Critical' }
                    'High' { 'High' }
                    'Medium' { 'Medium' }
                    'Low' { 'Low' }
                    'Info' { 'Info' }
                }
                $count = if ($allFindings.Count -gt 0) {
                    @($allFindings | Where-Object { (Get-GuiSeverityKey -Value $_.Severity) -eq $severity }).Count
                }
                elseif ($null -ne $Summary -and $Summary.PSObject.Properties[$summaryProperty]) {
                    [int]$Summary.$summaryProperty
                }
                else {
                    0
                }
                $severityRoot.Items.Add((New-WpfTreeItem -Header "$((Get-SeverityLabel -Severity $severity)) ($count)" -Mode 'Severity' -Value $severity)) | Out-Null
            }
        }
        $severityRoot.IsExpanded = $true
        $filterTree.Items.Add($severityRoot) | Out-Null

        $categoryRoot = New-Object System.Windows.Controls.TreeViewItem
        $categoryRoot.Header = 'Kategorija'
        foreach ($group in @(Get-ReportGroupItems -Items $allFindings -PropertyName 'Category' -First 500)) {
            $categoryRoot.Items.Add((New-WpfTreeItem -Header "$($group.Name) ($($group.Count))" -Mode 'Category' -Value $group.Name)) | Out-Null
        }
        $categoryRoot.IsExpanded = $true
        $filterTree.Items.Add($categoryRoot) | Out-Null

        $typeRoot = New-Object System.Windows.Controls.TreeViewItem
        $typeRoot.Header = 'Tip objekta'
        foreach ($group in @(Get-ReportGroupItems -Items $allFindings -PropertyName 'ObjectType' -First 500)) {
            if ([string]::IsNullOrWhiteSpace($group.Name)) { continue }
            $typeRoot.Items.Add((New-WpfTreeItem -Header "$($group.Name) ($($group.Count))" -Mode 'ObjectType' -Value $group.Name)) | Out-Null
        }
        $filterTree.Items.Add($typeRoot) | Out-Null

        $objectRoot = New-Object System.Windows.Controls.TreeViewItem
        $objectRoot.Header = 'Objekti / uredjaji'
        foreach ($group in @(Get-ReportGroupItems -Items $allFindings -PropertyName 'AffectedObject' -First 80)) {
            $objectRoot.Items.Add((New-WpfTreeItem -Header "$($group.Name) ($($group.Count))" -Mode 'AffectedObject' -Value $group.Name)) | Out-Null
        }
        $filterTree.Items.Add($objectRoot) | Out-Null
    }

    Add-WpfLog -Message $defaults.Status

    $browseOutputButton.Add_Click({
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderDialog.SelectedPath = $outputText.Text
        if ($folderDialog.ShowDialog() -eq 'OK') {
            $outputText.Text = $folderDialog.SelectedPath
        }
    })

    $browseConfigButton.Add_Click({
        $openDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openDialog.Filter = 'JSON config (*.json)|*.json|Svi fajlovi (*.*)|*.*'
        if ($openDialog.ShowDialog() -eq 'OK') {
            $configText.Text = $openDialog.FileName
        }
    })

    $findingsGrid.Add_SelectionChanged({
        $row = $findingsGrid.SelectedItem
        if ($null -eq $row -or $null -eq $row.Finding) {
            return
        }
        $finding = $row.Finding
        $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
        if ((ConvertTo-CompatibleString $finding.AssessmentType) -eq 'Health') {
            $detailText.Text = @"
ID: $($finding.Id)
Status: $($finding.StatusLabel)
Oblast: $($finding.Category)
Tezina provjere: $($metadata.RuleWeight)
Objekat: $($finding.AffectedObject)
Tip: $($finding.ObjectType)
Izvor: $($finding.Source)

Provjera:
$($finding.Title)

Dokaz:
$($finding.EvidenceText)

Preporuka:
$($finding.Recommendation)
"@
            return
        }
        $frameworkReferenceText = if ($finding.PSObject.Properties['FrameworkReferences'] -and @($finding.FrameworkReferences).Count -gt 0) {
            @($finding.FrameworkReferences | ForEach-Object {
                "$($_.Framework) $($_.Id) - $($_.Name) [$($_.Relationship)]`r`n$($_.Url)"
            }) -join "`r`n`r`n"
        }
        else {
            'Nema direktnog ili kontekstualnog ATT&CK mapiranja.'
        }
        $detailText.Text = @"
ID: $($finding.Id)
Maks. bodovi pravila: $($metadata.RuleMaxPoints)
Oblast ocjene: $($metadata.RiskAreaName)
Model pravila: $($metadata.RuleModel)
Metod bodovanja: $($metadata.ScoringMethod)
Ozbiljnost: $(Get-SeverityLabel -Severity $finding.Severity)
Kategorija: $($finding.Category)
Objekat: $($finding.AffectedObject)
Tip: $($finding.ObjectType)

Nalaz:
$($finding.Title)

Dokaz:
$($finding.EvidenceText)

Preporuka:
$($finding.Recommendation)

MITRE ATT&CK i reference:
$frameworkReferenceText
"@
    })

    $filterTree.Add_SelectedItemChanged({
        $item = $filterTree.SelectedItem
        if ($null -eq $item -or $null -eq $item.Tag) {
            return
        }
        $tagParts = ([string]$item.Tag) -split "`t", 2
        if ($tagParts.Count -lt 1 -or [string]::IsNullOrWhiteSpace($tagParts[0])) {
            return
        }
        $mode = $tagParts[0]
        $value = if ($tagParts.Count -gt 1) { $tagParts[1] } else { '' }
        Set-WpfFindings -Findings $script:GuiState.Findings -Mode $mode -Value $value
        Add-WpfLog -Message "Filter: $($item.Header)"
    })

    $clearFilterButton.Add_Click({
        Set-WpfFindings -Findings $script:GuiState.Findings -Mode 'All' -Value ''
        Add-WpfLog -Message 'Filter ociscen.'
    })

    $openFolderButton.Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($script:GuiState.ReportPath) -and (Test-Path -LiteralPath $script:GuiState.ReportPath)) {
            Invoke-Item -LiteralPath $script:GuiState.ReportPath
        }
    })

    $saveHtmlButton.Add_Click({
        if ($null -eq $script:GuiState.Summary) {
            [System.Windows.MessageBox]::Show('Nema rezultata za export.', 'Export', 'OK', 'Information') | Out-Null
            return
        }
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = 'HTML izvjestaj (*.html)|*.html'
        $assessmentName = if ($script:GuiState.Summary.PSObject.Properties['AssessmentType'] -and $script:GuiState.Summary.AssessmentType -eq 'Health') { 'AD-Health' } else { 'AD-Security' }
        $saveDialog.FileName = "$assessmentName-$($script:GuiState.Summary.ClientName).html"
        if ($saveDialog.ShowDialog() -eq 'OK') {
            $sourceHtml = Join-Path $script:GuiState.ReportPath 'report.html'
            if (-not (Test-Path -LiteralPath $sourceHtml)) {
                throw "Generisani HTML report nije pronadjen: $sourceHtml"
            }
            Copy-Item -LiteralPath $sourceHtml -Destination $saveDialog.FileName -Force
            Add-WpfLog -Message "HTML sacuvan: $($saveDialog.FileName)"
        }
    })

    $savePdfButton.Add_Click({
        if ($null -eq $script:GuiState.Summary) {
            [System.Windows.MessageBox]::Show('Nema rezultata za export.', 'Export', 'OK', 'Information') | Out-Null
            return
        }
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = 'PDF izvjestaj (*.pdf)|*.pdf'
        $assessmentName = if ($script:GuiState.Summary.PSObject.Properties['AssessmentType'] -and $script:GuiState.Summary.AssessmentType -eq 'Health') { 'AD-Health' } else { 'AD-Security' }
        $saveDialog.FileName = "$assessmentName-$($script:GuiState.Summary.ClientName).pdf"
        if ($saveDialog.ShowDialog() -eq 'OK') {
            try {
                $sourceHtml = Join-Path $script:GuiState.ReportPath 'report.html'
                if (-not (Test-Path -LiteralPath $sourceHtml)) {
                    throw "Generisani HTML report nije pronadjen: $sourceHtml"
                }
                Convert-HtmlReportToPdf -HtmlPath $sourceHtml -PdfPath $saveDialog.FileName
                Add-WpfLog -Message "PDF sacuvan: $($saveDialog.FileName)"
            }
            catch {
                [System.Windows.MessageBox]::Show($_.Exception.Message, 'PDF export nije uspio', 'OK', 'Error') | Out-Null
            }
        }
    })

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds(1)
    $timer.Add_Tick({
        $run = $script:GuiState.ActiveRun
        if ($null -eq $run -or $null -eq $run.Process) {
            return
        }
        if (-not $run.Process.HasExited) {
            return
        }

        $timer.Stop()
        $exitCode = $run.Process.ExitCode
        try {
            $stdoutText = $run.Process.StandardOutput.ReadToEnd()
            $stderrText = $run.Process.StandardError.ReadToEnd()
            $stdoutText | Set-Content -LiteralPath $run.StdOutPath -Encoding ASCII
            $stderrText | Set-Content -LiteralPath $run.StdErrPath -Encoding ASCII
        }
        catch {
        }
        $run.Process.Dispose()

        Set-WpfRunButtonsEnabled -Enabled $true
        Set-WpfActionsEnabled -Enabled $false

        if ($exitCode -ne 0) {
            $stdErr = if (Test-Path -LiteralPath $run.StdErrPath) { Get-Content -LiteralPath $run.StdErrPath -Raw } else { '' }
            $stdOut = if (Test-Path -LiteralPath $run.StdOutPath) { Get-Content -LiteralPath $run.StdOutPath -Raw } else { '' }
            $details = (($stdErr, $stdOut) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
            $message = "Analyzer nije uspio. Exit code $exitCode."
            if (-not [string]::IsNullOrWhiteSpace($details)) {
                $message = "$message`r`n`r`n$details"
            }
            Add-WpfLog -Message "Greska: analyzer proces je zavrsio sa code $exitCode."
            [System.Windows.MessageBox]::Show($message, 'Analyzer nije uspio', 'OK', 'Error') | Out-Null
            $script:GuiState.ActiveRun = $null
            return
        }

        try {
            Add-WpfLog -Message 'Ucitavam generisane rezultate...'
            $result = Read-GuiAnalyzerResult -Settings $run.Settings -StartTime $run.StartTime -StdOutPath $run.StdOutPath -StdErrPath $run.StdErrPath
            $script:GuiState.Summary = $result.Summary
            $script:GuiState.Findings = ConvertTo-GuiFindingArray -InputObject $result.Findings
            $script:GuiState.Warnings = @($result.Warnings)
            $script:GuiState.ReportPath = $result.ReportPath

            Set-WpfSummary -Summary $result.Summary
            Set-WpfFindings -Findings $script:GuiState.Findings -Mode 'All' -Value ''
            Set-WpfFilterTree -Findings $script:GuiState.Findings -Summary $result.Summary
            $hasHtmlReport = Test-Path -LiteralPath $result.HtmlReport
            Set-WpfActionsEnabled -Enabled $true -HtmlAvailable $hasHtmlReport
            if (-not $hasHtmlReport) {
                Add-WpfLog -Message 'HTML report nije generisan; JSON rezultati i report folder su dostupni.'
            }
            Add-WpfLog -Message "Gotovo. Report folder: $($result.ReportPath)"
        }
        catch {
            Add-WpfLog -Message "Greska: $($_.Exception.Message)"
            [System.Windows.MessageBox]::Show($_.Exception.Message, 'Analyzer nije uspio', 'OK', 'Error') | Out-Null
        }
        finally {
            $script:GuiState.ActiveRun = $null
        }
    })

    function Start-WpfAssessment {
        param(
            [ValidateSet('Security', 'Health')]
            [string]$ScanType
        )

        if ($null -ne $script:GuiState.ActiveRun -and $null -ne $script:GuiState.ActiveRun.Process -and -not $script:GuiState.ActiveRun.Process.HasExited) {
            return
        }

        if ([string]::IsNullOrWhiteSpace($clientText.Text)) {
            [System.Windows.MessageBox]::Show('Polje Domena / klijent je obavezno.', 'Nedostaje vrijednost', 'OK', 'Warning') | Out-Null
            return
        }

        try {
            $settings = @{
                ScanType = $ScanType
                ClientName = $clientText.Text.Trim()
                Server = $serverText.Text.Trim()
                OutputPath = $outputText.Text.Trim()
                ConfigPath = $configText.Text.Trim()
                NoCsv = [bool]$noCsvCheck.IsChecked
            }

            if ($ScanType -eq 'Security') {
                $settings.StaleUserDays = Get-WpfIntValue -TextBox $staleUsersText -Name 'Neaktivni useri'
                $settings.StaleComputerDays = Get-WpfIntValue -TextBox $staleComputersText -Name 'Neaktivni PC-evi'
                $settings.PrivilegedStaleDays = Get-WpfIntValue -TextBox $privStaleText -Name 'Priv. nalozi'
                $settings.MaxPasswordAgeDays = $MaxPasswordAgeDays
                $settings.ServiceAccountPasswordAgeDays = $ServiceAccountPasswordAgeDays
                $settings.KrbtgtMaxPasswordAgeDays = Get-WpfIntValue -TextBox $krbtgtAgeText -Name 'krbtgt starost'
                $settings.MinPasswordLength = Get-WpfIntValue -TextBox $minPasswordText -Name 'Min lozinka'
                $settings.MinPasswordHistory = $MinPasswordHistory
                $settings.MaxDomainAdmins = $MaxDomainAdmins
                $settings.MaxEnterpriseAdmins = $MaxEnterpriseAdmins
                $settings.FailedLoginLookbackHours = $FailedLoginLookbackHours
                $settings.FailedLoginMediumThreshold = $FailedLoginMediumThreshold
                $settings.FailedLoginHighThreshold = $FailedLoginHighThreshold
                $settings.FailedLoginAccountThreshold = $FailedLoginAccountThreshold
                $settings.FailedLoginMaxEventsPerDc = $FailedLoginMaxEventsPerDc
                $settings.FailedLoginQueryTimeoutSeconds = $FailedLoginQueryTimeoutSeconds
                $settings.SkipFailedLoginAudit = [bool]$SkipFailedLoginAudit
                $settings.AuditPasswordExpiration = [bool]$auditCheck.IsChecked
            }

            Set-WpfRunButtonsEnabled -Enabled $false
            Set-WpfActionsEnabled -Enabled $false
            $findingsGrid.ItemsSource = $null
            $filterTree.Items.Clear()
            $detailText.Text = ''
            $scanLabel = if ($ScanType -eq 'Health') { 'AD Health Test' } else { 'AD Security Test' }
            Add-WpfLog -Message "Pokrecem $scanLabel za $($settings.ClientName)..."
            $script:GuiState.ActiveRun = Start-GuiAnalyzerProcess -Settings $settings
            Add-WpfLog -Message "$scanLabel proces pokrenut. PID: $($script:GuiState.ActiveRun.Process.Id)"
            $timer.Start()
        }
        catch {
            Set-WpfRunButtonsEnabled -Enabled $true
            Add-WpfLog -Message "Greska: $($_.Exception.Message)"
            [System.Windows.MessageBox]::Show($_.Exception.Message, 'Analyzer nije uspio', 'OK', 'Error') | Out-Null
        }
    }

    $securityStartButton.Add_Click({
        Start-WpfAssessment -ScanType 'Security'
    })

    $healthStartButton.Add_Click({
        Start-WpfAssessment -ScanType 'Health'
    })

    $window.Add_Closing({
        $run = $script:GuiState.ActiveRun
        if ($null -ne $run -and $null -ne $run.Process -and -not $run.Process.HasExited) {
            try {
                $run.Process.Kill()
            }
            catch {
            }
        }
    })

    [void]$window.ShowDialog()
}

function Invoke-EmbeddedADHealthAnalyzer {
    [CmdletBinding()]
    param(
        [string]$ClientName,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$OutputPath,
        [int]$TcpTimeoutMilliseconds = 1800,
        [int]$NativeCommandTimeoutSeconds = 120,
        [int]$ReplicationWarningHours = 4,
        [int]$ReplicationFailureHours = 24,
        [int]$TimeWarningSeconds = 60,
        [int]$TimeFailureSeconds = 300,
        [ValidateRange(1, 10000)]
        [int]$MaxGpoChecks = 5000,
        [switch]$NoCsv,
        [switch]$SkipHtml,
        [switch]$GuiChild
    )

    $ErrorActionPreference = 'Stop'
    $script:Checks = New-Object System.Collections.Generic.List[object]
    $script:CollectionWarnings = New-Object System.Collections.Generic.List[object]
function ConvertTo-HealthString {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $text = [string]$Value
    $replacementMap = [ordered]@{
        ([char]0x010D) = 'c'
        ([char]0x0107) = 'c'
        ([char]0x0161) = 's'
        ([char]0x017E) = 'z'
        ([char]0x0111) = 'dj'
        ([char]0x010C) = 'C'
        ([char]0x0106) = 'C'
        ([char]0x0160) = 'S'
        ([char]0x017D) = 'Z'
        ([char]0x0110) = 'Dj'
    }

    foreach ($entry in $replacementMap.GetEnumerator()) {
        $text = $text.Replace([string]$entry.Key, [string]$entry.Value)
    }

    return $text
}

function ConvertTo-HealthEvidenceText {
    param(
        [AllowNull()]
        [object]$Evidence
    )

    if ($null -eq $Evidence) {
        return ''
    }

    if ($Evidence -is [string]) {
        return (ConvertTo-HealthString $Evidence)
    }

    try {
        return (ConvertTo-HealthString ($Evidence | ConvertTo-Json -Depth 10 -Compress))
    }
    catch {
        return (ConvertTo-HealthString $Evidence)
    }
}

function Get-HealthStatusLabel {
    param([string]$Status)

    switch ($Status) {
        'Pass' { return 'Proslo' }
        'Warning' { return 'Upozorenje' }
        'Fail' { return 'Neispravno' }
        'NotAssessed' { return 'Nije procijenjeno' }
        'NotApplicable' { return 'Nije primjenjivo' }
        default { return (ConvertTo-HealthString $Status) }
    }
}

function Get-HealthSeverity {
    param(
        [string]$Status,
        [bool]$CriticalOnFail
    )

    switch ($Status) {
        'Fail' {
            if ($CriticalOnFail) { return 'Critical' }
            return 'High'
        }
        'Warning' { return 'Medium' }
        'NotAssessed' { return 'Low' }
        'NotApplicable' { return 'Info' }
        default { return 'Info' }
    }
}

function Get-HealthSeverityScore {
    param([string]$Severity)

    switch ($Severity) {
        'Critical' { return 5 }
        'High' { return 4 }
        'Medium' { return 3 }
        'Low' { return 2 }
        default { return 1 }
    }
}

function Add-HealthCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Pass', 'Warning', 'Fail', 'NotAssessed', 'NotApplicable')]
        [string]$Status,

        [string]$Target = '',

        [string]$ObjectType = 'Domena',

        [AllowNull()]
        [object]$Evidence,

        [string]$Recommendation = '',

        [ValidateRange(0, 20)]
        [int]$Weight = 5,

        [switch]$CriticalOnFail,

        [switch]$RequiredForScore,

        [string]$Source = 'Interna provjera'
    )

    $severity = Get-HealthSeverity -Status $Status -CriticalOnFail ([bool]$CriticalOnFail)
    $script:Checks.Add([pscustomobject][ordered]@{
        AssessmentType = 'Health'
        Id = ConvertTo-HealthString $Id
        Status = $Status
        StatusLabel = Get-HealthStatusLabel -Status $Status
        Severity = $severity
        Score = Get-HealthSeverityScore -Severity $severity
        Category = ConvertTo-HealthString $Category
        Title = ConvertTo-HealthString $Title
        AffectedObject = ConvertTo-HealthString $Target
        ObjectType = ConvertTo-HealthString $ObjectType
        Evidence = $Evidence
        EvidenceText = ConvertTo-HealthEvidenceText -Evidence $Evidence
        Recommendation = ConvertTo-HealthString $Recommendation
        HealthWeight = [int]$Weight
        RuleWeight = [int]$Weight
        RuleMaxPoints = [int]$Weight
        RiskArea = ConvertTo-HealthString $Category
        RiskAreaName = ConvertTo-HealthString $Category
        ScoreCategory = ConvertTo-HealthString $Category
        RuleModel = 'AD Health provjera'
        ScoringMethod = 'Weighted pass/warning/fail'
        CriticalOnFail = [bool]$CriticalOnFail
        RequiredForScore = [bool]$RequiredForScore
        Source = ConvertTo-HealthString $Source
    }) | Out-Null
}

function Add-HealthCollectionWarning {
    param(
        [string]$Message,
        [AllowNull()]
        [object]$Detail
    )

    $script:CollectionWarnings.Add([pscustomobject][ordered]@{
        Message = ConvertTo-HealthString $Message
        Detail = ConvertTo-HealthString $Detail
    }) | Out-Null
}

function Quote-HealthNativeArgument {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-HealthNativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [int]$TimeoutSeconds = 60
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = (@($Arguments | ForEach-Object { Quote-HealthNativeArgument -Value ([string]$_) }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $completed = $process.WaitForExit([math]::Max(1, $TimeoutSeconds) * 1000)
    if (-not $completed) {
        try { $process.Kill() } catch {}
        try { $process.WaitForExit() } catch {}
        $stdout = try { $stdoutTask.GetAwaiter().GetResult() } catch { '' }
        $stderr = try { $stderrTask.GetAwaiter().GetResult() } catch { '' }
        $process.Dispose()
        return [pscustomobject][ordered]@{
            ExitCode = -1
            TimedOut = $true
            StdOut = ConvertTo-HealthString $stdout
            StdErr = ConvertTo-HealthString ("Command timed out after $TimeoutSeconds seconds. $stderr")
        }
    }

    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()

    return [pscustomobject][ordered]@{
        ExitCode = [int]$exitCode
        TimedOut = $false
        StdOut = ConvertTo-HealthString $stdout
        StdErr = ConvertTo-HealthString $stderr
    }
}

function Test-RepadminSummaryHasFailures {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    if ($Text -match '(?i)operational errors|DsReplicaGetInfo.*failed|last error') {
        return $true
    }

    return $Text -match '(?im)\b[1-9]\d*\s*/\s*\d+\s+(?:[1-9]\d?|100)\b'
}

function Test-HealthTextIndicatesPermissionIssue {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return $Text -match '(?i)access(?:\s+is)?\s+denied|unauthorized|insufficient\s+(?:access|privilege)|logon\s+failure|does not have.*privilege|error\s+(?:code\s*)?5\b'
}

function Get-DcdiagFailedTestNames {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    return @([regex]::Matches($Text, '(?im)\bfailed\s+test\s+([A-Za-z][A-Za-z0-9_-]*)\b') |
        ForEach-Object { $_.Groups[1].Value } |
        Sort-Object -Unique)
}

function Test-DcdiagTextHasExplicitFailure {
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    return $Text -match '(?im)\bfailed\s+test\b|\ban error event occurred\b|LDAP bind failed|DsBindWithSpnEx.*failed|The replication generated an error|failed with error|fatal error|could not be located|cannot be contacted'
}

function Get-DcdiagQuietResultStatus {
    param(
        [object]$Result
    )

    if ($null -eq $Result) {
        return 'NotAssessed'
    }

    $text = (ConvertTo-HealthString ($Result.StdOut + [Environment]::NewLine + $Result.StdErr)).Trim()
    if ($Result.TimedOut -or [int]$Result.ExitCode -ne 0) {
        return 'Fail'
    }

    if ([string]::IsNullOrWhiteSpace($text)) {
        return 'Pass'
    }

    # CheckSecurityError emits this success message even with /q on some Windows Server versions.
    if ($text -match '(?i)No security related replication errors were found on this\s+DC' -and
        -not (Test-DcdiagTextHasExplicitFailure -Text $text)) {
        return 'Pass'
    }

    # Other /q output is retained as a failure unless the caller applies a narrower
    # classification, such as a SystemLog-only operational warning.
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        return 'Fail'
    }

    return 'Pass'
}

function Test-DcdiagQuietResultHasFailure {
    param(
        [object]$Result
    )

    return (Get-DcdiagQuietResultStatus -Result $Result) -eq 'Fail'
}

function Test-HealthTcpPort {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMilliseconds = 1800
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne([math]::Max(250, $TimeoutMilliseconds), $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Resolve-HealthHostAddresses {
    param([string]$ComputerName)

    try {
        return @([System.Net.Dns]::GetHostAddresses($ComputerName) |
            ForEach-Object { $_.IPAddressToString } |
            Sort-Object -Unique)
    }
    catch {
        return @()
    }
}

function Get-HealthCategoryDefinitions {
    return @(
        [pscustomobject]@{ Name = 'AD osnovne usluge'; Weight = 20 },
        [pscustomobject]@{ Name = 'DNS'; Weight = 25 },
        [pscustomobject]@{ Name = 'Replikacija'; Weight = 15 },
        [pscustomobject]@{ Name = 'SYSVOL i Group Policy'; Weight = 15 },
        [pscustomobject]@{ Name = 'Vrijeme'; Weight = 10 },
        [pscustomobject]@{ Name = 'AD konfiguracija'; Weight = 5 },
        [pscustomobject]@{ Name = 'DCDiag'; Weight = 10 }
    )
}

function Get-HealthAnalysis {
    param([object[]]$Checks)

    $allChecks = @($Checks)
    $categoryDefinitions = Get-HealthCategoryDefinitions
    $categoryResults = New-Object System.Collections.Generic.List[object]
    $weightedScore = 0.0
    $assessedCategoryWeight = 0.0
    $coveredCategoryWeight = 0.0
    $applicableCategoryWeight = 0.0

    foreach ($definition in $categoryDefinitions) {
        $items = @($allChecks | Where-Object { $_.Category -eq $definition.Name -and [int]$_.HealthWeight -gt 0 })
        $applicableItems = @($items | Where-Object { $_.Status -ne 'NotApplicable' })
        $totalCheckWeight = [double](@($applicableItems | Measure-Object -Property HealthWeight -Sum).Sum)
        $assessedItems = @($applicableItems | Where-Object { $_.Status -ne 'NotAssessed' })
        $assessedCheckWeight = [double](@($assessedItems | Measure-Object -Property HealthWeight -Sum).Sum)
        $earned = 0.0

        foreach ($item in $assessedItems) {
            switch ($item.Status) {
                'Pass' { $earned += [double]$item.HealthWeight }
                'Warning' { $earned += ([double]$item.HealthWeight * 0.5) }
            }
        }

        $categoryScore = if ($assessedCheckWeight -gt 0) {
            [int][math]::Round((100.0 * $earned / $assessedCheckWeight), 0)
        }
        else {
            $null
        }
        $coverage = if ($totalCheckWeight -gt 0) {
            [int][math]::Round((100.0 * $assessedCheckWeight / $totalCheckWeight), 0)
        }
        else {
            100
        }

        if ($totalCheckWeight -gt 0) {
            $applicableCategoryWeight += [double]$definition.Weight
            $coveredCategoryWeight += ([double]$definition.Weight * ($coverage / 100.0))
        }
        if ($assessedCheckWeight -gt 0 -and $null -ne $categoryScore) {
            $weightedScore += ($categoryScore * [double]$definition.Weight)
            $assessedCategoryWeight += [double]$definition.Weight
        }

        $failed = @($items | Where-Object { $_.Status -eq 'Fail' }).Count
        $warnings = @($items | Where-Object { $_.Status -eq 'Warning' }).Count
        $notAssessed = @($items | Where-Object { $_.Status -eq 'NotAssessed' }).Count
        $notApplicable = @($items | Where-Object { $_.Status -eq 'NotApplicable' }).Count
        $categoryStatus = if ($totalCheckWeight -le 0) {
            'Nije primjenjivo'
        }
        elseif ($assessedCheckWeight -le 0) {
            'Nije procijenjeno'
        }
        elseif (@($items | Where-Object { $_.Status -eq 'Fail' -and $_.CriticalOnFail }).Count -gt 0) {
            'Kriticno'
        }
        elseif ($failed -gt 0) {
            'Naruseno'
        }
        elseif ($warnings -gt 0) {
            'Upozorenje'
        }
        else {
            'Zdravo'
        }

        $categoryResults.Add([pscustomobject][ordered]@{
            Name = $definition.Name
            Weight = [int]$definition.Weight
            Score = $categoryScore
            ScoreDisplay = if ($null -eq $categoryScore) { 'N/A' } else { [string]$categoryScore }
            CoveragePercent = $coverage
            Status = $categoryStatus
            Passed = @($items | Where-Object { $_.Status -eq 'Pass' }).Count
            Warnings = $warnings
            Failed = $failed
            NotAssessed = $notAssessed
            NotApplicable = $notApplicable
            Total = $items.Count
        }) | Out-Null
    }

    $coveragePercent = if ($applicableCategoryWeight -gt 0) {
        [int][math]::Round((100.0 * $coveredCategoryWeight / $applicableCategoryWeight), 0)
    }
    else {
        0
    }
    $requiredNotAssessed = @($allChecks | Where-Object {
        $_.PSObject.Properties['RequiredForScore'] -and
        [bool]$_.RequiredForScore -and
        $_.Status -eq 'NotAssessed'
    })
    $scoreAvailable = (
        $coveragePercent -ge 85 -and
        $requiredNotAssessed.Count -eq 0 -and
        $assessedCategoryWeight -gt 0
    )
    $healthScore = if ($scoreAvailable) {
        [int][math]::Round(($weightedScore / $assessedCategoryWeight), 0)
    }
    else {
        $null
    }

    $failedCount = @($allChecks | Where-Object { $_.Status -eq 'Fail' }).Count
    $warningCount = @($allChecks | Where-Object { $_.Status -eq 'Warning' }).Count
    $criticalFailureCount = @($allChecks | Where-Object { $_.Status -eq 'Fail' -and $_.CriticalOnFail }).Count
    $coreCategoryNames = @('AD osnovne usluge', 'DNS', 'SYSVOL i Group Policy', 'Vrijeme', 'DCDiag')
    $unassessedCoreCategories = @($categoryResults.ToArray() | Where-Object {
        $_.Name -in $coreCategoryNames -and $_.Status -ne 'Nije primjenjivo' -and $_.CoveragePercent -lt 85
    })
    $isComplete = ($scoreAvailable -and $unassessedCoreCategories.Count -eq 0)
    $overallStatus = if ($criticalFailureCount -gt 0) {
        'Kriticno'
    }
    elseif ($failedCount -gt 0) {
        'Naruseno'
    }
    elseif (-not $isComplete) {
        'Nepotpuna procjena'
    }
    elseif ($warningCount -gt 0) {
        'Upozorenje'
    }
    else {
        'Zdravo'
    }

    return [pscustomobject][ordered]@{
        Score = $healthScore
        ScoreDisplay = if ($null -eq $healthScore) { 'N/A' } else { [string]$healthScore }
        ScoreAvailable = $scoreAvailable
        Status = $overallStatus
        CoveragePercent = $coveragePercent
        IsComplete = $isComplete
        UnassessedCoreCategories = @($unassessedCoreCategories | Select-Object -ExpandProperty Name)
        RequiredChecksNotAssessed = @($requiredNotAssessed | ForEach-Object {
            [pscustomobject]@{ Id = $_.Id; Target = $_.AffectedObject; Title = $_.Title }
        })
        Passed = @($allChecks | Where-Object { $_.Status -eq 'Pass' }).Count
        Warnings = $warningCount
        Failed = $failedCount
        NotAssessed = @($allChecks | Where-Object { $_.Status -eq 'NotAssessed' }).Count
        NotApplicable = @($allChecks | Where-Object { $_.Status -eq 'NotApplicable' }).Count
        Total = $allChecks.Count
        CategoryScores = @($categoryResults.ToArray())
        Methodology = 'Health score je dostupan samo kada je procijenjeno najmanje 85% primjenjivih kontrola i kada su izvrsene sve obavezne core provjere. 100 je najbolje; Warning nosi 50%, Fail 0%, NotApplicable ne ulazi u coverage, a NotAssessed blokira score kada je provjera obavezna.'
    }
}

function Write-HealthJsonFile {
    param(
        [object]$InputObject,
        [string]$Path
    )

    $json = $InputObject | ConvertTo-Json -Depth 15
    $json | Set-Content -LiteralPath $Path -Encoding ASCII
}

function ConvertTo-HealthHtmlText {
    param([AllowNull()][object]$Value)

    return [System.Net.WebUtility]::HtmlEncode((ConvertTo-HealthString $Value))
}

function Get-HealthStatusCssClass {
    param([string]$Status)

    switch ($Status) {
        'Pass' { return 'pass' }
        'Warning' { return 'warning' }
        'Fail' { return 'fail' }
        default { return 'na' }
    }
}

function Write-HealthHtmlReport {
    param(
        [object]$Summary,
        [object[]]$Checks,
        [object[]]$Warnings,
        [string]$Path
    )

    $safeClient = ConvertTo-HealthHtmlText $Summary.ClientName
    $safeDomain = ConvertTo-HealthHtmlText $Summary.DomainDnsRoot
    $safeGenerated = ConvertTo-HealthHtmlText $Summary.GeneratedAt
    $safeStatus = ConvertTo-HealthHtmlText $Summary.HealthStatus

    $categoryCards = New-Object System.Collections.Generic.List[string]
    foreach ($category in @($Summary.HealthScoreDetails.CategoryScores)) {
        $className = switch ($category.Status) {
            'Zdravo' { 'pass' }
            'Upozorenje' { 'warning' }
            'Naruseno' { 'fail' }
            'Kriticno' { 'fail' }
            default { 'na' }
        }
        $categoryScoreDisplay = if ($category.PSObject.Properties['ScoreDisplay']) { $category.ScoreDisplay } elseif ($null -eq $category.Score) { 'N/A' } else { [string]$category.Score }
        $categoryBarWidth = if ($null -eq $category.Score) { 0 } else { [int]$category.Score }
        $categoryCards.Add(@"
<div class="category-card $className">
  <div class="category-head"><strong>$(ConvertTo-HealthHtmlText $category.Name)</strong><span>$categoryScoreDisplay$(if ($categoryScoreDisplay -ne 'N/A') { '/100' })</span></div>
  <div class="bar"><i style="width:$categoryBarWidth%"></i></div>
  <div class="category-meta">Status: $(ConvertTo-HealthHtmlText $category.Status) | Coverage: $($category.CoveragePercent)% | Fail: $($category.Failed) | Warning: $($category.Warnings)</div>
</div>
"@) | Out-Null
    }

    $groupedSections = New-Object System.Collections.Generic.List[string]
    foreach ($group in @($Checks | Group-Object -Property Category | Sort-Object Name)) {
        $rows = New-Object System.Collections.Generic.List[string]
        foreach ($check in @($group.Group | Sort-Object -Property Score -Descending)) {
            $className = Get-HealthStatusCssClass -Status $check.Status
            $rows.Add(@"
<tr>
  <td><span class="status $className">$(ConvertTo-HealthHtmlText $check.StatusLabel)</span></td>
  <td>$(ConvertTo-HealthHtmlText $check.Id)</td>
  <td>$(ConvertTo-HealthHtmlText $check.Title)</td>
  <td>$(ConvertTo-HealthHtmlText $check.AffectedObject)</td>
  <td><code>$(ConvertTo-HealthHtmlText $check.EvidenceText)</code></td>
  <td>$(ConvertTo-HealthHtmlText $check.Recommendation)</td>
</tr>
"@) | Out-Null
        }

        $failedInGroup = @($group.Group | Where-Object { $_.Status -eq 'Fail' }).Count
        $warningInGroup = @($group.Group | Where-Object { $_.Status -eq 'Warning' }).Count
        $groupedSections.Add(@"
<details>
  <summary>$(ConvertTo-HealthHtmlText $group.Name)<span>$($group.Count) provjera | $failedInGroup fail | $warningInGroup warning</span></summary>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Status</th><th>ID</th><th>Provjera</th><th>Objekat</th><th>Dokaz</th><th>Preporuka</th></tr></thead>
      <tbody>$($rows -join [Environment]::NewLine)</tbody>
    </table>
  </div>
</details>
"@) | Out-Null
    }

    $warningHtml = ''
    if (@($Warnings).Count -gt 0) {
        $items = @($Warnings | ForEach-Object {
            "<li><strong>$(ConvertTo-HealthHtmlText $_.Message)</strong>: $(ConvertTo-HealthHtmlText $_.Detail)</li>"
        })
        $warningHtml = "<section><h2>Upozorenja kolekcije</h2><ul>$($items -join '')</ul></section>"
    }

    $coverageWarning = if (-not $Summary.HealthScoreDetails.IsComplete) {
        $missingRequired = @($Summary.HealthScoreDetails.RequiredChecksNotAssessed | ForEach-Object {
            "$(ConvertTo-HealthHtmlText $_.Id) ($(ConvertTo-HealthHtmlText $_.Target))"
        })
        $missingText = if ($missingRequired.Count -gt 0) {
            " Obavezne neizvrsene provjere: $($missingRequired -join ', ')."
        }
        else {
            ''
        }
        "<div class=`"coverage-warning`"><strong>Nepotpuna procjena:</strong> Health score nije objavljen dok coverage nije najmanje 85% i dok sve obavezne core provjere nisu izvrsene.$missingText</div>"
    }
    else {
        ''
    }

    $html = @"
<!doctype html>
<html lang="bs">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>AD Health izvjestaj - $safeClient</title>
<style>
  :root{--ink:#0b2942;--muted:#64748b;--line:#dbe5ef;--panel:#f7fafc;--blue:#2563eb;--green:#15803d;--amber:#b45309;--red:#b91c1c;--gray:#64748b}
  *{box-sizing:border-box} body{margin:0;background:#fff;color:#172033;font:14px/1.45 "Segoe UI",Arial,sans-serif}
  main{max-width:1420px;margin:0 auto;padding:28px 28px 64px} h1{margin:0 0 14px;color:var(--ink);font-size:32px} h2{color:var(--ink);font-size:19px;margin:0 0 14px}
  .meta{color:#475569;margin-bottom:20px}.cards{display:grid;grid-template-columns:repeat(6,minmax(130px,1fr));gap:10px;margin:18px 0}
  .card{border:1px solid var(--line);border-radius:8px;padding:14px;background:var(--panel)}.card .label{font-size:11px;text-transform:uppercase;color:#70849a}.card .value{font-size:28px;font-weight:700;color:var(--ink)}
  .status-pass{color:var(--green)}.status-warning{color:var(--amber)}.status-fail{color:var(--red)}
  .score-note,.coverage-warning{border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:12px 0}.coverage-warning{border-color:#f59e0b;background:#fff7ed;color:#92400e}
  .categories{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-bottom:18px}.category-card{border:1px solid var(--line);border-radius:8px;padding:12px;break-inside:avoid}.category-head{display:flex;justify-content:space-between;gap:12px}
  .bar{height:8px;background:#e8eef5;border-radius:6px;margin:9px 0;overflow:hidden}.bar i{display:block;height:100%;background:var(--blue)}.category-card.pass .bar i{background:var(--green)}.category-card.warning .bar i{background:#f59e0b}.category-card.fail .bar i{background:var(--red)}
  .category-meta{font-size:12px;color:var(--muted)} details{border:1px solid var(--line);border-radius:8px;margin:10px 0;background:#fff} summary{cursor:pointer;padding:13px 15px;color:var(--ink);font-weight:700;display:flex;justify-content:space-between}
  summary span{font-weight:400;color:var(--muted)}.table-wrap{overflow:auto;border-top:1px solid var(--line)}table{width:100%;border-collapse:collapse;min-width:1050px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #edf2f7}th{background:#f5f8fb;color:#52677d;font-size:11px;text-transform:uppercase}
  code{white-space:pre-wrap;word-break:break-word;font:12px/1.4 Consolas,monospace}.status{display:inline-block;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:700;white-space:nowrap}.status.pass{background:#dcfce7;color:#166534}.status.warning{background:#fef3c7;color:#92400e}.status.fail{background:#fee2e2;color:#991b1b}.status.na{background:#e2e8f0;color:#475569}
  footer{max-width:1420px;margin:-44px auto 16px;padding:0 28px;text-align:right;color:#64748b;font-size:10px}@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.categories{grid-template-columns:1fr}main{padding:18px}}
  @media print{main{max-width:none;padding:14px}.cards{grid-template-columns:repeat(6,1fr)}details{break-inside:auto}details:not([open])>:not(summary){display:block!important}.table-wrap{overflow:visible}table{min-width:0;table-layout:fixed;font-size:9px}th,td{padding:5px;word-break:break-word}th:nth-child(1){width:13%}th:nth-child(2){width:9%}th:nth-child(3){width:14%}th:nth-child(4){width:14%}th:nth-child(5){width:24%}th:nth-child(6){width:26%}code{font-size:8px}footer{margin:8px 0 0;padding:0 14px}}
</style>
</head>
<body>
<main>
  <h1>Active Directory Health izvjestaj</h1>
  <div class="meta">
    Klijent: <strong>$safeClient</strong><br />
    Domena: <strong>$safeDomain</strong><br />
    Generisano: <strong>$safeGenerated</strong><br />
    Model: <strong>Protocol-aware AD Health model v3</strong>
  </div>
  <div class="cards">
    <div class="card"><div class="label">Health score</div><div class="value">$($Summary.HealthScoreDisplay)</div></div>
    <div class="card"><div class="label">Status</div><div class="value" style="font-size:20px">$safeStatus</div></div>
    <div class="card"><div class="label">Coverage</div><div class="value">$($Summary.HealthCoveragePercent)%</div></div>
    <div class="card"><div class="label">Proslo</div><div class="value status-pass">$($Summary.Passed)</div></div>
    <div class="card"><div class="label">Upozorenje</div><div class="value status-warning">$($Summary.Warnings)</div></div>
    <div class="card"><div class="label">Neispravno</div><div class="value status-fail">$($Summary.Failed)</div></div>
  </div>
  <div class="score-note"><strong>Kako citati rezultat:</strong> 100 znaci potpuno zdrav procijenjeni AD, a 0 potpuno neispravan. Coverage je udio primjenjivih tezinskih provjera koje su stvarno izvrsene; Nije primjenjivo se izuzima. Port dostupnost je samo dijagnostika i ne donosi bodove. N/A znaci da nema dovoljno pouzdanih podataka za score.</div>
  $coverageWarning
  <section>
    <h2>Health po oblastima</h2>
    <div class="categories">$($categoryCards -join [Environment]::NewLine)</div>
  </section>
  <section>
    <h2>Rezultati provjera</h2>
    $($groupedSections -join [Environment]::NewLine)
  </section>
  $warningHtml
</main>
<footer>Kodeks d.o.o. Sarajevo | Created by: Adis Hadzovic</footer>
<script>
  (function(){
    window.addEventListener('beforeprint',function(){
      document.querySelectorAll('details:not([open])').forEach(function(item){
        item.setAttribute('data-print-open','1');
        item.open=true;
      });
    });
    window.addEventListener('afterprint',function(){
      document.querySelectorAll('details[data-print-open]').forEach(function(item){
        item.open=false;
        item.removeAttribute('data-print-open');
      });
    });
  })();
</script>
</body>
</html>
"@

    $html | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Get-HealthBrowserPath {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe')
    )

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    return $null
}

function Convert-HealthHtmlToPdf {
    param(
        [string]$HtmlPath,
        [string]$PdfPath
    )

    $browser = Get-HealthBrowserPath
    if ($null -eq $browser) {
        throw 'Microsoft Edge ili Google Chrome nije pronadjen.'
    }

    $htmlUri = (New-Object System.Uri((Resolve-Path -LiteralPath $HtmlPath).Path)).AbsoluteUri
    $arguments = @(
        '--headless',
        '--disable-gpu',
        '--no-pdf-header-footer',
        "--print-to-pdf=$PdfPath",
        $htmlUri
    )
    $result = Invoke-HealthNativeCommand -FilePath $browser -Arguments $arguments -TimeoutSeconds 120
    if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $PdfPath)) {
        throw "PDF export nije uspio. Browser exit code: $($result.ExitCode). $($result.StdErr)"
    }
}

function Get-DcName {
    param([object]$DomainController)

    foreach ($propertyName in @('HostName', 'Name')) {
        $property = $DomainController.PSObject.Properties[$propertyName]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return ([string]$property.Value).TrimEnd('.')
        }
    }
    return ''
}

function Get-GptIniVersion {
    param([string]$Path)

    try {
        $line = Get-Content -LiteralPath $Path -ErrorAction Stop |
            Where-Object { $_ -match '^\s*Version\s*=\s*(\d+)\s*$' } |
            Select-Object -First 1
        if ($line -match '^\s*Version\s*=\s*(\d+)\s*$') {
            return [int64]$matches[1]
        }
    }
    catch {
    }
    return $null
}

function Get-HealthCommandPath {
    param([string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) {
        foreach ($propertyName in @('Path', 'Source', 'Definition')) {
            $property = $command.PSObject.Properties[$propertyName]
            if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                $candidate = [string]$property.Value
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return (Resolve-Path -LiteralPath $candidate).Path
                }
            }
        }
    }

    $windowsRoot = if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) { $env:SystemRoot } else { $env:windir }
    if (-not [string]::IsNullOrWhiteSpace($windowsRoot)) {
        foreach ($directory in @('Sysnative', 'System32')) {
            $candidate = Join-Path (Join-Path $windowsRoot $directory) $Name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return $candidate
            }
        }
    }

    return $null
}

function Test-HealthLocalComputer {
    param([string]$ComputerName)

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return $false
    }

    $targetShort = (($ComputerName.TrimEnd('.')) -split '\.')[0]
    $localNames = @(
        $env:COMPUTERNAME,
        [System.Net.Dns]::GetHostName()
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    return @($localNames | Where-Object {
        (([string]$_ -split '\.')[0]).Equals($targetShort, [System.StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
}

function Test-HealthPrivateOrLocalIpAddress {
    param([string]$Address)

    $ip = $null
    $normalized = ([string]$Address).Split('%')[0]
    if (-not [System.Net.IPAddress]::TryParse($normalized, [ref]$ip)) {
        return $false
    }

    if ([System.Net.IPAddress]::IsLoopback($ip)) {
        return $true
    }
    $bytes = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return (
            $bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
            ($bytes[0] -eq 169 -and $bytes[1] -eq 254)
        )
    }

    return (
        ($bytes[0] -band 0xFE) -eq 0xFC -or
        ($bytes[0] -eq 0xFE -and ($bytes[1] -band 0xC0) -eq 0x80)
    )
}

function Test-HealthIpv4InCidr {
    param(
        [string]$Address,
        [string]$Cidr
    )

    if ($Cidr -notmatch '^([^/]+)/(\d{1,2})$') {
        return $false
    }
    $addressIp = $null
    $networkIp = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$addressIp) -or
        -not [System.Net.IPAddress]::TryParse($matches[1], [ref]$networkIp) -or
        $addressIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $networkIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $prefixLength = [int]$matches[2]
    if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
        return $false
    }

    $addressBytes = $addressIp.GetAddressBytes()
    $networkBytes = $networkIp.GetAddressBytes()
    $wholeBytes = [math]::Floor($prefixLength / 8)
    $remainingBits = $prefixLength % 8
    for ($index = 0; $index -lt $wholeBytes; $index++) {
        if ($addressBytes[$index] -ne $networkBytes[$index]) {
            return $false
        }
    }
    if ($remainingBits -gt 0) {
        $mask = (0xFF -shl (8 - $remainingBits)) -band 0xFF
        if (($addressBytes[$wholeBytes] -band $mask) -ne ($networkBytes[$wholeBytes] -band $mask)) {
            return $false
        }
    }
    return $true
}

function Get-HealthDnsClientConfiguration {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    $cimSession = $null
    try {
        $isLocal = Test-HealthLocalComputer -ComputerName $ComputerName
        if ($null -ne (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
            if ($isLocal) {
                $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)
            }
            else {
                $sessionParams = @{
                    ComputerName = $ComputerName
                    ErrorAction = 'Stop'
                }
                if ($null -ne $Credential) {
                    $sessionParams.Credential = $Credential
                }
                if ($null -ne (Get-Command New-CimSessionOption -ErrorAction SilentlyContinue)) {
                    $sessionParams.SessionOption = New-CimSessionOption -Protocol Dcom
                }
                $cimSession = New-CimSession @sessionParams
                $adapters = @(Get-CimInstance -CimSession $cimSession -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -OperationTimeoutSec 15 -ErrorAction Stop)
            }
        }
        elseif ($null -ne (Get-Command Get-WmiObject -ErrorAction SilentlyContinue)) {
            $wmiParams = @{
                Class = 'Win32_NetworkAdapterConfiguration'
                Filter = 'IPEnabled=True'
                ErrorAction = 'Stop'
            }
            if (-not $isLocal) {
                $wmiParams.ComputerName = $ComputerName
                if ($null -ne $Credential) {
                    $wmiParams.Credential = $Credential
                }
            }
            $adapters = @(Get-WmiObject @wmiParams)
        }
        else {
            throw 'CIM/WMI cmdleti nisu dostupni.'
        }

        $resultAdapters = @($adapters | ForEach-Object {
            [pscustomobject][ordered]@{
                Description = ConvertTo-HealthString $_.Description
                SettingId = ConvertTo-HealthString $_.SettingID
                IpAddresses = @($_.IPAddress | ForEach-Object { ConvertTo-HealthString $_ })
                DefaultGateways = @($_.DefaultIPGateway | ForEach-Object { ConvertTo-HealthString $_ })
                DnsServers = @($_.DNSServerSearchOrder | ForEach-Object { ConvertTo-HealthString $_ })
                DnsDomain = ConvertTo-HealthString $_.DNSDomain
                DnsHostName = ConvertTo-HealthString $_.DNSHostName
            }
        })

        return [pscustomobject][ordered]@{
            Success = $true
            IsLocal = $isLocal
            Adapters = $resultAdapters
            Error = ''
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Success = $false
            IsLocal = (Test-HealthLocalComputer -ComputerName $ComputerName)
            Adapters = @()
            Error = ConvertTo-HealthString $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
    }
}

function Test-HealthLdapDirectoryService {
    param(
        [string]$ComputerName,
        [ValidateSet('Negotiate', 'Kerberos')]
        [string]$AuthenticationType,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connection = $null
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($ComputerName, 389, $false, $false)
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
        $connection.Timeout = [TimeSpan]::FromSeconds(15)
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::$AuthenticationType
        if ($null -ne $Credential) {
            $connection.Credential = $Credential.GetNetworkCredential()
        }
        $connection.Bind()

        $request = [System.DirectoryServices.Protocols.SearchRequest]::new()
        $request.DistinguishedName = ''
        $request.Filter = '(objectClass=*)'
        $request.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
        foreach ($attributeName in @('defaultNamingContext', 'dnsHostName', 'dsServiceName', 'supportedCapabilities')) {
            [void]$request.Attributes.Add($attributeName)
        }
        $response = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
        if ($response.Entries.Count -lt 1) {
            throw 'RootDSE upit nije vratio rezultat.'
        }

        $entry = $response.Entries[0]
        $defaultNamingContext = if ($entry.Attributes['defaultNamingContext'] -and $entry.Attributes['defaultNamingContext'].Count -gt 0) {
            ConvertTo-HealthString $entry.Attributes['defaultNamingContext'][0]
        }
        else {
            ''
        }
        $dnsHostName = if ($entry.Attributes['dnsHostName'] -and $entry.Attributes['dnsHostName'].Count -gt 0) {
            ConvertTo-HealthString $entry.Attributes['dnsHostName'][0]
        }
        else {
            ''
        }
        $dsServiceName = if ($entry.Attributes['dsServiceName'] -and $entry.Attributes['dsServiceName'].Count -gt 0) {
            ConvertTo-HealthString $entry.Attributes['dsServiceName'][0]
        }
        else {
            ''
        }

        return [pscustomobject][ordered]@{
            Success = (-not [string]::IsNullOrWhiteSpace($defaultNamingContext) -and -not [string]::IsNullOrWhiteSpace($dsServiceName))
            AuthenticationType = $AuthenticationType
            DefaultNamingContext = $defaultNamingContext
            DnsHostName = $dnsHostName
            DsServiceName = $dsServiceName
            Error = ''
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Success = $false
            AuthenticationType = $AuthenticationType
            DefaultNamingContext = ''
            DnsHostName = ''
            DsServiceName = ''
            Error = ConvertTo-HealthString $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $connection) {
            $connection.Dispose()
        }
    }
}

function Resolve-HealthSrvRecords {
    param(
        [string]$Name,
        [string]$DnsServer = ''
    )

    $method = 'Unavailable'
    try {
        if ($null -eq (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
            Import-Module DnsClient -ErrorAction SilentlyContinue
        }
        if ($null -ne (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
            $method = 'Resolve-DnsName'
            $params = @{
                Name = $Name
                Type = 'SRV'
                ErrorAction = 'Stop'
            }
            if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
                $params.Server = $DnsServer
            }
            $records = @(Resolve-DnsName @params)
            $targets = @($records | ForEach-Object { $_.NameTarget } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { ([string]$_).TrimEnd('.') } |
                Sort-Object -Unique)
            return [pscustomobject][ordered]@{
                Success = ($targets.Count -gt 0)
                Targets = $targets
                Method = $method
                Output = ''
                Error = ''
            }
        }

        $nslookupPath = Get-HealthCommandPath -Name 'nslookup.exe'
        if ($null -eq $nslookupPath) {
            throw 'Resolve-DnsName, DnsClient modul i nslookup.exe nisu dostupni.'
        }
        $method = 'nslookup'
        $arguments = @('-type=SRV', $Name)
        if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
            $arguments += $DnsServer
        }
        $result = Invoke-HealthNativeCommand -FilePath $nslookupPath -Arguments $arguments -TimeoutSeconds 20
        $text = ($result.StdOut + [Environment]::NewLine + $result.StdErr).Trim()
        $targets = @([regex]::Matches($text, '(?im)(?:svr hostname|service|target)\s*=\s*([^\s]+)') |
            ForEach-Object { $_.Groups[1].Value.TrimEnd('.') } |
            Sort-Object -Unique)
        return [pscustomobject][ordered]@{
            Success = (-not $result.TimedOut -and $result.ExitCode -eq 0 -and $targets.Count -gt 0)
            Targets = $targets
            Method = $method
            Output = $text
            Error = ConvertTo-HealthString $result.StdErr
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Success = $false
            Targets = @()
            Method = $method
            Output = ''
            Error = ConvertTo-HealthString $_.Exception.Message
        }
    }
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$adModuleAvailable = $false
$domain = $null
$forest = $null
$domainControllers = @()
$adParams = @{}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adModuleAvailable = $true
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $adParams.Server = $Server
    }
    if ($null -ne $Credential) {
        $adParams.Credential = $Credential
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $domain = Get-ADDomain @adParams -ErrorAction Stop
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ClientName) -and $ClientName -match '\.') {
        try {
            $domain = Get-ADDomain -Identity $ClientName @adParams -ErrorAction Stop
        }
        catch {
            $domain = Get-ADDomain @adParams -ErrorAction Stop
        }
    }
    else {
        $domain = Get-ADDomain @adParams -ErrorAction Stop
    }

    $forest = Get-ADForest @adParams -ErrorAction Stop
    $domainControllers = @(Get-ADDomainController @adParams -Filter * -ErrorAction Stop)
}
catch {
    Add-HealthCollectionWarning -Message 'ActiveDirectory modul ili AD kolekcija nije dostupna.' -Detail $_.Exception.Message
    try {
        $dotNetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainControllers = @($dotNetDomain.DomainControllers)
        $domain = [pscustomobject]@{
            DNSRoot = $dotNetDomain.Name
            DistinguishedName = ''
            PDCEmulator = ''
            RIDMaster = ''
            InfrastructureMaster = ''
            DomainMode = ''
            Forest = $dotNetDomain.Forest.Name
        }
        $forest = [pscustomobject]@{
            Name = $dotNetDomain.Forest.Name
            SchemaMaster = ''
            DomainNamingMaster = ''
            ForestMode = ''
        }
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $domainControllers = @([pscustomobject]@{ HostName = $Server; Name = $Server; Site = ''; IsGlobalCatalog = $false })
            $domain = [pscustomobject]@{
                DNSRoot = $ClientName
                DistinguishedName = ''
                PDCEmulator = ''
                RIDMaster = ''
                InfrastructureMaster = ''
                DomainMode = ''
                Forest = ''
            }
        }
        else {
            throw "Nije moguce pronaci domenu ili domain controllere. $($_.Exception.Message)"
        }
    }
}

$domainDns = ConvertTo-HealthString $domain.DNSRoot
if ([string]::IsNullOrWhiteSpace($domainDns)) {
    $domainDns = ConvertTo-HealthString $ClientName
}
if ([string]::IsNullOrWhiteSpace($ClientName)) {
    $ClientName = $domainDns
}

$dcNames = @($domainControllers | ForEach-Object { Get-DcName -DomainController $_ } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    Sort-Object -Unique)
if ($dcNames.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($Server)) {
    $dcNames = @($Server)
}
if ($dcNames.Count -eq 0) {
    throw 'Nijedan domain controller nije pronadjen.'
}

Add-HealthCheck -Id 'HC-CAP-001' -Category 'AD konfiguracija' -Title 'ActiveDirectory PowerShell modul je dostupan' `
    -Status $(if ($adModuleAvailable) { 'Pass' } else { 'NotAssessed' }) -Target $env:COMPUTERNAME -ObjectType 'Collector' `
    -Evidence @{ ActiveDirectoryModule = $adModuleAvailable } -Weight 0 -RequiredForScore `
    -Recommendation 'Za potpunu procjenu pokrenuti sa management sistema ili DC-a koji ima instaliran AD DS RSAT modul.'

$isElevated = $false
try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $isElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch {
}
$collectorIsDc = @($dcNames | Where-Object { Test-HealthLocalComputer -ComputerName $_ }).Count -gt 0
Add-HealthCheck -Id 'HC-CAP-002' -Category 'AD konfiguracija' -Title 'Health kolektor je pokrenut elevatovano' `
    -Status $(if ($isElevated) { 'Pass' } else { 'NotAssessed' }) -Target $env:COMPUTERNAME -ObjectType 'Collector' `
    -Evidence @{ ElevatedAdministrator = $isElevated; CollectorIsDomainController = $collectorIsDc; User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } `
    -Weight 0 -RequiredForScore -Source 'Windows access token' `
    -Recommendation 'Pokrenuti PowerShell sa Run as administrator. Microsoft DCDiag zahtijeva elevatovan proces; bez toga Health score nije pouzdan.'

$dcReachability = @{}
$dcAddressMap = @{}
$dnsClientResults = @{}
foreach ($dcName in $dcNames) {
    $addresses = @(Resolve-HealthHostAddresses -ComputerName $dcName)
    $dcAddressMap[$dcName] = $addresses
    $dnsStatus = if ($addresses.Count -gt 0) { 'Pass' } else { 'Fail' }
    Add-HealthCheck -Id 'HC-DC-001' -Category 'AD osnovne usluge' -Title 'DC hostname se razrjesava u IP adresu' `
        -Status $dnsStatus -Target $dcName -ObjectType 'Domain controller' -Evidence @{ Addresses = $addresses } `
        -Weight 2 -CriticalOnFail -RequiredForScore -Source 'DNS host resolution' `
        -Recommendation 'Provjeriti A/AAAA zapise, DNS suffix, delegaciju zone i dostupnost autoritativnih DNS servera.'

    $portResults = [ordered]@{}
    foreach ($port in @(53, 88, 135, 389, 445, 464, 9389)) {
        $portResults["TCP$port"] = Test-HealthTcpPort -ComputerName $dcName -Port $port -TimeoutMilliseconds $TcpTimeoutMilliseconds
    }
    $dcReachability[$dcName] = $portResults

    foreach ($portDefinition in @(
            @{ Port = 53; Name = 'DNS TCP'; OptionalManagement = $false },
            @{ Port = 88; Name = 'Kerberos KDC TCP'; OptionalManagement = $false },
            @{ Port = 135; Name = 'RPC endpoint mapper'; OptionalManagement = $false },
            @{ Port = 389; Name = 'LDAP TCP'; OptionalManagement = $false },
            @{ Port = 445; Name = 'SMB TCP'; OptionalManagement = $false },
            @{ Port = 464; Name = 'Kerberos password change TCP'; OptionalManagement = $false },
            @{ Port = 9389; Name = 'Active Directory Web Services TCP'; OptionalManagement = $true }
        )) {
        $portOpen = [bool]$portResults["TCP$($portDefinition.Port)"]
        $portStatus = if ($portOpen) {
            'Pass'
        }
        elseif ([bool]$portDefinition.OptionalManagement) {
            'NotApplicable'
        }
        else {
            'Warning'
        }
        $portNote = if ([bool]$portDefinition.OptionalManagement) {
            'ADWS je opcionalni management endpoint. Nedostupan TCP 9389 ne znaci da LDAP, Kerberos ili AD replikacija ne rade.'
        }
        else {
            'Otvoren port ne dokazuje da AD protokol radi ispravno.'
        }
        $portRecommendation = if ([bool]$portDefinition.OptionalManagement) {
            'TCP 9389 je potreban za ADWS-bazirane management alate. Omoguciti ga samo ako je taj management pristup potreban; nije preduslov za core AD autentikaciju ili replikaciju.'
        }
        else {
            "Provjeriti servis, lokalni firewall, mrezni ACL i routing za TCP $($portDefinition.Port). Ova provjera ne zamjenjuje LDAP, Kerberos ili DCDiag test."
        }
        Add-HealthCheck -Id "HC-PORT-$($portDefinition.Port)" -Category 'AD osnovne usluge' `
            -Title "$($portDefinition.Name) dostupnost na portu $($portDefinition.Port)" `
            -Status $portStatus -Target $dcName -ObjectType 'Domain controller' `
            -Evidence @{ Port = $portDefinition.Port; Reachable = $portOpen; OptionalManagementEndpoint = [bool]$portDefinition.OptionalManagement; Note = $portNote } -Weight 0 `
            -Source 'TCP transport dijagnostika' `
            -Recommendation $portRecommendation
    }

    $ldapResult = Test-HealthLdapDirectoryService -ComputerName $dcName -AuthenticationType Negotiate -Credential $Credential
    Add-HealthCheck -Id 'HC-LDAP-001' -Category 'AD osnovne usluge' -Title 'LDAP RootDSE bind i AD identitet DC-a rade' `
        -Status $(if ($ldapResult.Success) { 'Pass' } else { 'Fail' }) -Target $dcName -ObjectType 'Domain controller' `
        -Evidence $ldapResult -Weight 7 -CriticalOnFail -RequiredForScore -Source 'LDAP RootDSE bind' `
        -Recommendation 'Otkloniti LDAP bind, DNS, NTDS servis, autentikaciju ili firewall problem. Otvoren TCP 389 nije dovoljan dokaz ispravnog LDAP-a.'

    $kerberosLdapResult = Test-HealthLdapDirectoryService -ComputerName $dcName -AuthenticationType Kerberos -Credential $Credential
    Add-HealthCheck -Id 'HC-KERBEROS-001' -Category 'AD osnovne usluge' -Title 'Kerberos autentikovani LDAP bind prema DC-u radi' `
        -Status $(if ($kerberosLdapResult.Success) { 'Pass' } else { 'Fail' }) -Target $dcName -ObjectType 'Domain controller' `
        -Evidence $kerberosLdapResult -Weight 7 -CriticalOnFail -RequiredForScore -Source 'LDAP bind sa Kerberos AuthType' `
        -Recommendation 'Provjeriti KDC servis, vrijeme, DNS, SPN-ove i machine account DC-a. Otvoren TCP 88 ne dokazuje da Kerberos izdaje ispravne tickete.'

    $dnsClientResult = Get-HealthDnsClientConfiguration -ComputerName $dcName -Credential $Credential
    $dnsClientResults[$dcName] = $dnsClientResult
    if (-not $dnsClientResult.Success) {
        Add-HealthCheck -Id 'HC-DNS-CLIENT-001' -Category 'DNS' -Title 'DNS client postavke DC-a koriste interne AD DNS resolvere' `
            -Status 'NotAssessed' -Target $dcName -ObjectType 'Domain controller DNS client' -Weight 12 -CriticalOnFail -RequiredForScore `
            -Evidence @{ Error = $dnsClientResult.Error; IsLocal = $dnsClientResult.IsLocal } -Source 'CIM/WMI Win32_NetworkAdapterConfiguration' `
            -Recommendation 'Pokrenuti kao administrator na DC-u ili omoguciti administrativni CIM/WMI pristup do DC-a.'
    }
    else {
        $configuredResolvers = @($dnsClientResult.Adapters | ForEach-Object { $_.DnsServers } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { ([string]$_).Split('%')[0] } |
            Sort-Object -Unique)
        $resolverTests = @($configuredResolvers | ForEach-Object {
            $resolver = [string]$_
            $ldapSrv = Resolve-HealthSrvRecords -Name "_ldap._tcp.dc._msdcs.$domainDns" -DnsServer $resolver
            $kerberosSrv = Resolve-HealthSrvRecords -Name "_kerberos._tcp.dc._msdcs.$domainDns" -DnsServer $resolver
            [pscustomobject][ordered]@{
                Resolver = $resolver
                LdapSrvSuccess = [bool]$ldapSrv.Success
                LdapTargets = @($ldapSrv.Targets)
                KerberosSrvSuccess = [bool]$kerberosSrv.Success
                KerberosTargets = @($kerberosSrv.Targets)
                Method = "$($ldapSrv.Method)/$($kerberosSrv.Method)"
                Error = (($ldapSrv.Error, $kerberosSrv.Error) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' | '
            }
        })
        $invalidResolvers = @($resolverTests | Where-Object { -not $_.LdapSrvSuccess -or -not $_.KerberosSrvSuccess })
        $publicResolvers = @($configuredResolvers | Where-Object { -not (Test-HealthPrivateOrLocalIpAddress -Address $_) })
        $dcAddressSet = @('127.0.0.1', '::1') + @($dcAddressMap.Values | ForEach-Object { $_ })
        $nonDcResolvers = @($configuredResolvers | Where-Object { $dcAddressSet -notcontains $_ })
        $dnsClientStatus = if ($configuredResolvers.Count -eq 0) {
            'Fail'
        }
        elseif ($publicResolvers.Count -gt 0 -or $invalidResolvers.Count -gt 0) {
            'Fail'
        }
        else {
            'Pass'
        }
        Add-HealthCheck -Id 'HC-DNS-CLIENT-001' -Category 'DNS' -Title 'DNS client postavke DC-a koriste resolvere koji vracaju interne AD zapise' `
            -Status $dnsClientStatus -Target $dcName -ObjectType 'Domain controller DNS client' -Weight 12 -CriticalOnFail -RequiredForScore `
            -Evidence @{
                Adapters = @($dnsClientResult.Adapters)
                ConfiguredResolvers = $configuredResolvers
                PublicOrIspResolvers = $publicResolvers
                ResolverValidation = $resolverTests
                ResolversOutsideDiscoveredDcAddresses = $nonDcResolvers
            } -Source 'CIM/WMI DNS client konfiguracija + direktni SRV upit svakom resolveru' `
            -Recommendation 'DC DNS client mora koristiti interni DNS koji je autoritativan za AD zonu. Google, ISP ili drugi javni DNS ne smije biti na NIC-u; vanjski DNS se konfigurise kao forwarder na internom DNS serveru.'
    }
}

foreach ($srvDefinition in @(
        @{ Id = 'HC-DNS-001'; Name = "_ldap._tcp.dc._msdcs.$domainDns"; Service = 'LDAP DC locator' },
        @{ Id = 'HC-DNS-002'; Name = "_kerberos._tcp.dc._msdcs.$domainDns"; Service = 'Kerberos DC locator' }
    )) {
    $srvResult = Resolve-HealthSrvRecords -Name $srvDefinition.Name
    if ($srvResult.Success) {
        $targets = @($srvResult.Targets | ForEach-Object { ([string]$_).TrimEnd('.').ToLowerInvariant() } | Sort-Object -Unique)
        $missingDcs = @($dcNames | Where-Object { $targets -notcontains ([string]$_).TrimEnd('.').ToLowerInvariant() })
        $status = if ($missingDcs.Count -gt 0) { 'Warning' } else { 'Pass' }
        Add-HealthCheck -Id $srvDefinition.Id -Category 'DNS' -Title "$($srvDefinition.Service) SRV zapisi postoje" `
            -Status $status -Target $srvDefinition.Name -ObjectType 'DNS SRV zapis' -Weight 5 -CriticalOnFail -RequiredForScore `
            -Evidence @{ Targets = $targets; MissingDomainControllers = $missingDcs; Method = $srvResult.Method } `
            -Recommendation 'Provjeriti Netlogon DNS registraciju i _msdcs zonu. Svaki aktivni DC mora imati odgovarajuce locator zapise.'
    }
    else {
        Add-HealthCheck -Id $srvDefinition.Id -Category 'DNS' -Title "$($srvDefinition.Service) SRV zapisi postoje" `
            -Status 'Fail' -Target $srvDefinition.Name -ObjectType 'DNS SRV zapis' -Weight 5 -CriticalOnFail -RequiredForScore `
            -Evidence @{ Error = $srvResult.Error; Output = $srvResult.Output; Method = $srvResult.Method } `
            -Recommendation 'Provjeriti DNS client postavke DC-a, internu DNS zonu, Netlogon servis i registraciju SRV zapisa.'
    }
}

if ($null -eq (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) {
    Import-Module DnsServer -ErrorAction SilentlyContinue
}
foreach ($dcName in $dcNames) {
    if ($null -eq (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) {
        Add-HealthCheck -Id 'HC-DNS-ZONE-001' -Category 'DNS' -Title 'AD DNS zona i dynamic update konfiguracija su ispravni' `
            -Status 'NotAssessed' -Target $dcName -ObjectType 'Domain controller DNS' -Weight 3 `
            -Evidence @{ Reason = 'DnsServer PowerShell modul nije dostupan.' } -Source 'DnsServer modul' `
            -Recommendation 'Instalirati DNS Server RSAT alate ili pokrenuti test direktno na DNS/DC serveru.'
        continue
    }

    try {
        $zones = @(Get-DnsServerZone -ComputerName $dcName -ErrorAction Stop)
        $domainZone = @($zones | Where-Object { ([string]$_.ZoneName).TrimEnd('.').Equals($domainDns.TrimEnd('.'), [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
        $zoneStatus = if ($domainZone.Count -eq 0) {
            'Fail'
        }
        elseif (-not [bool]$domainZone[0].IsDsIntegrated -or ([string]$domainZone[0].DynamicUpdate -notmatch '(?i)secure')) {
            'Warning'
        }
        else {
            'Pass'
        }
        Add-HealthCheck -Id 'HC-DNS-ZONE-001' -Category 'DNS' -Title 'AD DNS zona postoji i koristi AD-integraciju sa secure dynamic updates' `
            -Status $zoneStatus -Target $dcName -ObjectType 'Domain controller DNS' -Weight 3 -CriticalOnFail `
            -Evidence @{
                ZoneFound = ($domainZone.Count -gt 0)
                ZoneName = if ($domainZone.Count -gt 0) { $domainZone[0].ZoneName } else { '' }
                IsDsIntegrated = if ($domainZone.Count -gt 0) { [bool]$domainZone[0].IsDsIntegrated } else { $false }
                DynamicUpdate = if ($domainZone.Count -gt 0) { ConvertTo-HealthString $domainZone[0].DynamicUpdate } else { '' }
                AvailableZones = @($zones | Select-Object -ExpandProperty ZoneName)
            } -Source 'Get-DnsServerZone' `
            -Recommendation 'Hostati AD zonu na internom DNS-u, preferirano kao AD-integrisanu zonu sa secure dynamic updates. Ne stavljati javne DNS servere na NIC DC-a.'

        if ($null -ne (Get-Command Get-DnsServerForwarder -ErrorAction SilentlyContinue)) {
            try {
                $forwarder = Get-DnsServerForwarder -ComputerName $dcName -ErrorAction Stop
                Add-HealthCheck -Id 'HC-DNS-FORWARDER-INFO' -Category 'DNS' -Title 'Konfigurisani vanjski DNS forwarderi' `
                    -Status 'Pass' -Target $dcName -ObjectType 'Domain controller DNS' -Weight 0 `
                    -Evidence @{ Forwarders = @($forwarder.IPAddress | ForEach-Object { ConvertTo-HealthString $_ }) } `
                    -Source 'Get-DnsServerForwarder' `
                    -Recommendation 'Vanjske DNS adrese pripadaju ovdje kao forwarderi, a ne u DNS client postavke mreznog adaptera DC-a.'
            }
            catch {
            }
        }
    }
    catch {
        $dnsRoleExpected = [bool]$dcReachability[$dcName]['TCP53']
        Add-HealthCheck -Id 'HC-DNS-ZONE-001' -Category 'DNS' -Title 'AD DNS zona i dynamic update konfiguracija su ispravni' `
            -Status $(if ($dnsRoleExpected) { 'NotAssessed' } else { 'NotApplicable' }) -Target $dcName -ObjectType 'Domain controller DNS' -Weight 3 `
            -Evidence @{ Error = $_.Exception.Message; Tcp53Reachable = $dnsRoleExpected } -Source 'Get-DnsServerZone' `
            -Recommendation 'Ako DC hosta DNS, omoguciti administratorski pristup i provjeriti zonu. Ako DNS nije na DC-u, interni autoritativni DNS i dalje mora vracati sve AD SRV zapise.'
    }
}

foreach ($dcName in $dcNames) {
    $smbOpen = [bool]$dcReachability[$dcName]['TCP445']
    $shareResults = [ordered]@{}
    foreach ($share in @('SYSVOL', 'NETLOGON')) {
        $path = "\\$dcName\$share"
        $accessible = $false
        $errorText = ''
        $errorType = ''
        if ($smbOpen) {
            try {
                $accessible = Test-Path -LiteralPath $path -ErrorAction Stop
            }
            catch {
                $errorText = $_.Exception.Message
                $errorType = $_.Exception.GetType().FullName
            }
        }
        else {
            $errorText = 'TCP 445 nije dostupan.'
        }
        $shareResults[$share] = $accessible
        $shareStatus = if ($accessible) {
            'Pass'
        }
        elseif ($errorType -match 'UnauthorizedAccess|SecurityException' -or $errorText -match '(?i)access.*denied|unauthorized|logon failure|user name or password is incorrect') {
            'NotAssessed'
        }
        else {
            'Fail'
        }
        Add-HealthCheck -Id "HC-SYSVOL-$share" -Category 'SYSVOL i Group Policy' -Title "$share share je dostupan" `
            -Status $shareStatus -Target $dcName -ObjectType 'Domain controller share' `
            -Evidence @{ Path = $path; Accessible = $accessible; Error = $errorText; ErrorType = $errorType } -Weight 6 -CriticalOnFail -RequiredForScore `
            -Source 'SMB UNC provjera' `
            -Recommendation "Provjeriti DFSR/SYSVOL inicijalizaciju, Netlogon servis i da li je $share share objavljen."
    }
}

if ($dcNames.Count -le 1) {
    Add-HealthCheck -Id 'HC-REPL-001' -Category 'Replikacija' -Title 'AD replikacija izmedju domain controllera' `
        -Status 'NotApplicable' -Target $domainDns -ObjectType 'Domena' -Weight 20 `
        -Evidence @{ DomainControllerCount = $dcNames.Count; Reason = 'Replikacija izmedju DC-eva nije primjenjiva jer domena ima samo jedan DC.' } `
        -Recommendation 'Dodati najmanje jos jedan domain controller radi redundanse, odrzavanja i oporavka.'
    Add-HealthCheck -Id 'HC-CONFIG-001' -Category 'AD konfiguracija' -Title 'Domena ima redundantne domain controllere' `
        -Status 'Warning' -Target $domainDns -ObjectType 'Domena' -Weight 6 `
        -Evidence @{ DomainControllerCount = $dcNames.Count } `
        -Recommendation 'Planirati najmanje dva ispravna domain controllera po domeni.'
}
else {
    $repadminStatus = $null
    $repadminEvidence = $null
    $repadminPath = Get-HealthCommandPath -Name 'repadmin.exe'
    if ($null -ne $repadminPath) {
        $repadminResult = Invoke-HealthNativeCommand -FilePath $repadminPath -Arguments @('/replsummary') -TimeoutSeconds $NativeCommandTimeoutSeconds
        $repadminText = $repadminResult.StdOut + [Environment]::NewLine + $repadminResult.StdErr
        $repadminHasFailures = Test-RepadminSummaryHasFailures -Text $repadminText
        $replicationStatus = if (Test-HealthTextIndicatesPermissionIssue -Text $repadminText) {
            'NotAssessed'
        }
        elseif ($repadminResult.TimedOut -or $repadminResult.ExitCode -ne 0 -or $repadminHasFailures) {
            'Fail'
        }
        else {
            'Pass'
        }
        $repadminStatus = $replicationStatus
        $repadminEvidence = [ordered]@{
            Executable = $repadminPath
            ExitCode = $repadminResult.ExitCode
            TimedOut = $repadminResult.TimedOut
            FailureRowsDetected = $repadminHasFailures
            Output = $repadminResult.StdOut
            Error = $repadminResult.StdErr
        }
    }
    else {
        $repadminEvidence = [ordered]@{ Reason = 'repadmin.exe nije dostupan.' }
    }

    $adReplicationStatus = $null
    $adReplicationEvidence = $null
    $adReplicationError = ''
    $adwsUnavailableDcs = @($dcNames | Where-Object { -not [bool]$dcReachability[$_]['TCP9389'] })
    $adReplicationCommandsAvailable = $adModuleAvailable -and
        $null -ne (Get-Command Get-ADReplicationPartnerMetadata -ErrorAction SilentlyContinue) -and
        $null -ne (Get-Command Get-ADReplicationFailure -ErrorAction SilentlyContinue)
    $collectAdReplicationTelemetry = $adReplicationCommandsAvailable -and $adwsUnavailableDcs.Count -eq 0

    if ($collectAdReplicationTelemetry) {
        try {
            $replicationParams = @{
                Target = $domainDns
                Scope = 'Domain'
                Partition = '*'
                ErrorAction = 'Stop'
            }
            if ($null -ne $Credential) {
                $replicationParams.Credential = $Credential
            }
            $replicationMetadata = @(Get-ADReplicationPartnerMetadata @replicationParams)

            $failureParams = @{
                Target = $domainDns
                Scope = 'Domain'
                ErrorAction = 'Stop'
            }
            if ($null -ne $Credential) {
                $failureParams.Credential = $Credential
            }
            $replicationFailures = @(Get-ADReplicationFailure @failureParams)

            $now = Get-Date
            $problemPartners = @($replicationMetadata | Where-Object { [int64]$_.LastReplicationResult -ne 0 })
            $missingLastSuccess = @($replicationMetadata | Where-Object { $null -eq $_.LastReplicationSuccess })
            $ages = @($replicationMetadata | ForEach-Object {
                if ($null -ne $_.LastReplicationSuccess) {
                    [math]::Round(($now - [datetime]$_.LastReplicationSuccess).TotalHours, 2)
                }
            })
            $maxAgeHours = if ($ages.Count -gt 0) { [double](@($ages | Measure-Object -Maximum).Maximum) } else { 0.0 }
            $adReplicationStatus = if ($replicationMetadata.Count -eq 0 -or $problemPartners.Count -gt 0 -or $replicationFailures.Count -gt 0 -or $missingLastSuccess.Count -gt 0 -or $maxAgeHours -ge $ReplicationFailureHours) {
                'Fail'
            }
            elseif ($maxAgeHours -ge $ReplicationWarningHours) {
                'Warning'
            }
            else {
                'Pass'
            }
            $adReplicationEvidence = [ordered]@{
                PartnerRecords = $replicationMetadata.Count
                CurrentFailures = $replicationFailures.Count
                NonZeroResults = $problemPartners.Count
                MissingLastSuccess = $missingLastSuccess.Count
                MaxLastSuccessAgeHours = $maxAgeHours
                WarningHours = $ReplicationWarningHours
                FailureHours = $ReplicationFailureHours
                ProblemPartners = @($problemPartners | Select-Object -First 20 Server, Partner, Partition, LastReplicationResult, LastReplicationAttempt, LastReplicationSuccess)
            }
        }
        catch {
            $adReplicationError = $_.Exception.Message
        }
    }
    elseif (-not $adReplicationCommandsAvailable) {
        $adReplicationError = 'AD replication PowerShell cmdleti nisu dostupni.'
    }
    else {
        $adReplicationError = "Dopunska AD PowerShell telemetry je preskocena jer ADWS nije dostupan na: $($adwsUnavailableDcs -join ', '). Repadmin rezultat ne zavisi od ADWS-a."
    }

    $replicationStatus = 'NotAssessed'
    $replicationSource = 'Nije dostupna pouzdana metoda'
    if ($null -ne $repadminStatus) {
        $replicationSource = 'repadmin /replsummary'
        if ($repadminStatus -eq 'Fail') {
            $replicationStatus = 'Fail'
        }
        elseif ($repadminStatus -eq 'Pass') {
            if ($adReplicationStatus -eq 'Fail' -or $adReplicationStatus -eq 'Warning') {
                $replicationStatus = 'Warning'
                $replicationSource = 'repadmin /replsummary + AD PowerShell telemetry'
            }
            else {
                $replicationStatus = 'Pass'
            }
        }
        elseif ($null -ne $adReplicationStatus) {
            $replicationStatus = $adReplicationStatus
            $replicationSource = 'AD PowerShell replication telemetry'
        }
    }
    elseif ($null -ne $adReplicationStatus) {
        $replicationStatus = $adReplicationStatus
        $replicationSource = 'AD PowerShell replication telemetry'
    }

    Add-HealthCheck -Id 'HC-REPL-001' -Category 'Replikacija' -Title 'AD replikacija prolazi bez prijavljenih gresaka' `
        -Status $replicationStatus -Target $domainDns -ObjectType 'Domena' -Weight 20 -CriticalOnFail -RequiredForScore `
        -Evidence @{
            SelectedSource = $replicationSource
            RepadminStatus = $repadminStatus
            Repadmin = $repadminEvidence
            AdPowerShellStatus = $adReplicationStatus
            AdPowerShell = $adReplicationEvidence
            AdPowerShellError = $adReplicationError
            AdwsUnavailableDomainControllers = $adwsUnavailableDcs
        } `
        -Source $replicationSource `
        -Recommendation 'Repadmin je primarni dokaz za samu replikaciju. Nedostupan ADWS (TCP 9389) utice na AD PowerShell management telemetry, ali sam po sebi ne dokazuje kvar replikacije. Za stvarnu gresku pregledati repadmin /showrepl i otkloniti DNS, RPC, autentikacijski ili topology uzrok.'
}

$gpoStatus = 'NotAssessed'
$gpoEvidence = [ordered]@{ Reason = 'AD modul ili DistinguishedName nije dostupan.' }
if ($adModuleAvailable -and -not [string]::IsNullOrWhiteSpace([string]$domain.DistinguishedName)) {
    try {
        $gpoSearchBase = "CN=Policies,CN=System,$($domain.DistinguishedName)"
        $gpoObjects = @(Get-ADObject @adParams -LDAPFilter '(objectClass=groupPolicyContainer)' -SearchBase $gpoSearchBase -Properties displayName, versionNumber -ErrorAction Stop |
            Sort-Object Name)
        $gpoTruncated = $gpoObjects.Count -gt $MaxGpoChecks
        $gposToCheck = @($gpoObjects | Select-Object -First ([math]::Max(1, $MaxGpoChecks)))
        $missingFolders = New-Object System.Collections.Generic.List[object]
        $invalidGptIniFiles = New-Object System.Collections.Generic.List[object]
        $versionMismatches = New-Object System.Collections.Generic.List[object]
        $unavailableRoots = New-Object System.Collections.Generic.List[string]
        $checkedRootCount = 0

        foreach ($dcName in $dcNames) {
            if (-not [bool]$dcReachability[$dcName]['TCP445']) {
                $unavailableRoots.Add($dcName) | Out-Null
                continue
            }
            $policyRoot = "\\$dcName\SYSVOL\$domainDns\Policies"
            try {
                [void](Get-Item -LiteralPath $policyRoot -ErrorAction Stop)
                $checkedRootCount++
            }
            catch {
                $unavailableRoots.Add($dcName) | Out-Null
                continue
            }

            foreach ($gpo in $gposToCheck) {
                $gpoFolder = Join-Path $policyRoot ([string]$gpo.Name)
                if (-not (Test-Path -LiteralPath $gpoFolder)) {
                    $missingFolders.Add([pscustomobject]@{ DC = $dcName; GPO = $gpo.Name; DisplayName = $gpo.DisplayName }) | Out-Null
                    continue
                }
                $gptIniPath = Join-Path $gpoFolder 'GPT.INI'
                $gptVersion = Get-GptIniVersion -Path $gptIniPath
                if ($null -eq $gptVersion) {
                    $invalidGptIniFiles.Add([pscustomobject]@{
                        DC = $dcName
                        GPO = $gpo.Name
                        DisplayName = $gpo.DisplayName
                        Path = $gptIniPath
                    }) | Out-Null
                }
                elseif ([int64]$gpo.versionNumber -ne [int64]$gptVersion) {
                    $versionMismatches.Add([pscustomobject]@{
                        DC = $dcName
                        GPO = $gpo.Name
                        DisplayName = $gpo.DisplayName
                        AdVersion = [int64]$gpo.versionNumber
                        SysvolVersion = [int64]$gptVersion
                    }) | Out-Null
                }
            }
        }

        $gpoStatus = if ($checkedRootCount -eq 0 -or $gpoTruncated) {
            'NotAssessed'
        }
        elseif ($gpoObjects.Count -lt 2 -or $missingFolders.Count -gt 0 -or $invalidGptIniFiles.Count -gt 0) {
            'Fail'
        }
        elseif ($versionMismatches.Count -gt 0 -or $unavailableRoots.Count -gt 0) {
            'Warning'
        }
        else {
            'Pass'
        }
        $gpoEvidence = [ordered]@{
            GpoObjects = $gpoObjects.Count
            CheckedGpos = $gposToCheck.Count
            CheckedDomainControllers = $checkedRootCount
            Truncated = $gpoTruncated
            MissingFolders = $missingFolders.Count
            InvalidOrMissingGptIni = $invalidGptIniFiles.Count
            VersionMismatches = $versionMismatches.Count
            UnavailableSysvolRoots = @($unavailableRoots.ToArray())
            MissingFolderExamples = @($missingFolders.ToArray() | Select-Object -First 20)
            InvalidGptIniExamples = @($invalidGptIniFiles.ToArray() | Select-Object -First 20)
            VersionMismatchExamples = @($versionMismatches.ToArray() | Select-Object -First 20)
        }
    }
    catch {
        $gpoEvidence = [ordered]@{ Error = $_.Exception.Message }
    }
}
Add-HealthCheck -Id 'HC-GPO-001' -Category 'SYSVOL i Group Policy' -Title 'GPO objekti i SYSVOL sadrzaj su konzistentni' `
    -Status $gpoStatus -Target $domainDns -ObjectType 'Group Policy' -Weight 15 -CriticalOnFail -RequiredForScore `
    -Evidence $gpoEvidence -Source 'AD groupPolicyContainer / SYSVOL GPT.INI' `
    -Recommendation 'Popraviti nedostajuce GPO foldere ili version mismatch tek nakon potvrde replikacijskog stanja i backup-a. Ne kopirati SYSVOL sadrzaj naslijepo.'

$w32tmPath = Get-HealthCommandPath -Name 'w32tm.exe'
if ($null -ne $w32tmPath) {
    $timeResult = Invoke-HealthNativeCommand -FilePath $w32tmPath -Arguments @('/monitor', "/domain:$domainDns") -TimeoutSeconds ([math]::Min(45, $NativeCommandTimeoutSeconds))
    $offsetMatches = [regex]::Matches(($timeResult.StdOut + [Environment]::NewLine + $timeResult.StdErr), '([+-]?\d+(?:[\.,]\d+)?)s\b')
    $offsets = @($offsetMatches | ForEach-Object {
        [double](($_.Groups[1].Value) -replace ',', '.')
    })
    $maxOffset = if ($offsets.Count -gt 0) {
        [double](@($offsets | ForEach-Object { [math]::Abs($_) } | Measure-Object -Maximum).Maximum)
    }
    else {
        0.0
    }
    $timeStatus = if ($timeResult.TimedOut -or $timeResult.ExitCode -ne 0) {
        'Fail'
    }
    elseif ($offsets.Count -eq 0) {
        'NotAssessed'
    }
    elseif ($maxOffset -ge $TimeFailureSeconds) {
        'Fail'
    }
    elseif ($maxOffset -ge $TimeWarningSeconds) {
        'Warning'
    }
    else {
        'Pass'
    }
    Add-HealthCheck -Id 'HC-TIME-001' -Category 'Vrijeme' -Title 'Vrijeme domain controllera je sinhronizovano' `
        -Status $timeStatus -Target $domainDns -ObjectType 'Domena' -Weight 10 -CriticalOnFail -RequiredForScore `
        -Evidence @{ MaxOffsetSeconds = [math]::Round($maxOffset, 3); WarningSeconds = $TimeWarningSeconds; FailureSeconds = $TimeFailureSeconds; ExitCode = $timeResult.ExitCode; Output = $timeResult.StdOut; Error = $timeResult.StdErr } `
        -Source 'w32tm /monitor' `
        -Recommendation 'Provjeriti Windows Time servis i hijerarhiju. Forest-root PDC treba koristiti odobren pouzdan vanjski izvor, a ostali domain clanovi domensku hijerarhiju.'

    $pdcName = ConvertTo-HealthString $domain.PDCEmulator
    if (-not [string]::IsNullOrWhiteSpace($pdcName)) {
        $sourceResult = Invoke-HealthNativeCommand -FilePath $w32tmPath -Arguments @('/query', "/computer:$pdcName", '/source') -TimeoutSeconds ([math]::Min(30, $NativeCommandTimeoutSeconds))
        $sourceText = ($sourceResult.StdOut.Trim())
        $sourceStatus = if ($sourceResult.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($sourceText)) {
            'NotAssessed'
        }
        elseif ($sourceText -match '(?i)local cmos|free-running|unspecified|vm ic time synchronization') {
            'Warning'
        }
        else {
            'Pass'
        }
        Add-HealthCheck -Id 'HC-TIME-002' -Category 'Vrijeme' -Title 'PDC Emulator ima odgovarajuci time source' `
            -Status $sourceStatus -Target $pdcName -ObjectType 'FSMO role owner' -Weight 5 `
            -Evidence @{ Source = $sourceText; ExitCode = $sourceResult.ExitCode; Error = $sourceResult.StdErr } `
            -Source 'w32tm /query /source' `
            -Recommendation 'Na forest-root PDC-u podesiti odobrene vanjske NTP izvore i pratiti offset. VM host time provider ne treba biti jedini autoritativni izvor za PDC.'
    }
}
else {
    Add-HealthCheck -Id 'HC-TIME-001' -Category 'Vrijeme' -Title 'Vrijeme domain controllera je sinhronizovano' `
        -Status 'NotAssessed' -Target $domainDns -ObjectType 'Domena' -Weight 10 -RequiredForScore `
        -Evidence @{ Reason = 'w32tm.exe nije dostupan.' } `
        -Recommendation 'Pokrenuti test na Windows management sistemu ili domain controlleru.'
}

$knownDcShortNames = @($dcNames | ForEach-Object { ($_ -split '\.')[0].ToLowerInvariant() })
$fsmoRoles = [ordered]@{
    PDCEmulator = ConvertTo-HealthString $domain.PDCEmulator
    RIDMaster = ConvertTo-HealthString $domain.RIDMaster
    InfrastructureMaster = ConvertTo-HealthString $domain.InfrastructureMaster
    SchemaMaster = if ($null -ne $forest) { ConvertTo-HealthString $forest.SchemaMaster } else { '' }
    DomainNamingMaster = if ($null -ne $forest) { ConvertTo-HealthString $forest.DomainNamingMaster } else { '' }
}
$missingFsmo = @()
foreach ($entry in $fsmoRoles.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
        $missingFsmo += $entry.Key
        continue
    }
    $ownerShort = (([string]$entry.Value -split '\.')[0]).ToLowerInvariant()
    if ($knownDcShortNames -notcontains $ownerShort) {
        $missingFsmo += "$($entry.Key):$($entry.Value)"
    }
}
Add-HealthCheck -Id 'HC-CONFIG-002' -Category 'AD konfiguracija' -Title 'FSMO role imaju poznate domain controller vlasnike' `
    -Status $(if ($missingFsmo.Count -eq 0) { 'Pass' } elseif ($adModuleAvailable) { 'Fail' } else { 'NotAssessed' }) `
    -Target $domainDns -ObjectType 'Domena' -Weight 6 -CriticalOnFail `
    -Evidence @{ Roles = $fsmoRoles; MissingOrUnknown = $missingFsmo } `
    -Recommendation 'Provjeriti dostupnost FSMO vlasnika. Role prenositi ili seize-ati samo prema dokumentovanoj proceduri i nakon potvrde da se stari vlasnik nece vratiti.'

if ($adModuleAvailable -and $null -ne (Get-Command Get-ADReplicationSite -ErrorAction SilentlyContinue)) {
    try {
        $sites = @(Get-ADReplicationSite @adParams -Filter * -ErrorAction Stop)
        $subnets = @(Get-ADReplicationSubnet @adParams -Filter * -ErrorAction Stop)
        $dcSites = @($domainControllers | ForEach-Object { ConvertTo-HealthString $_.Site } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $subnetNames = @($subnets | ForEach-Object { ConvertTo-HealthString $_.Name })
        $unmappedDcAddresses = @($dcAddressMap.GetEnumerator() | ForEach-Object {
            $dcNameForAddress = $_.Key
            foreach ($address in @($_.Value)) {
                $parsed = $null
                if (-not [System.Net.IPAddress]::TryParse(([string]$address).Split('%')[0], [ref]$parsed) -or
                    $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
                    [System.Net.IPAddress]::IsLoopback($parsed)) {
                    continue
                }
                $mapped = @($subnetNames | Where-Object { Test-HealthIpv4InCidr -Address $parsed.IPAddressToString -Cidr $_ }).Count -gt 0
                if (-not $mapped) {
                    [pscustomobject]@{ DomainController = $dcNameForAddress; Address = $parsed.IPAddressToString }
                }
            }
        })
        $siteStatus = if ($dcSites.Count -lt $dcNames.Count) {
            'Fail'
        }
        elseif ($subnets.Count -eq 0) {
            'Warning'
        }
        elseif ($unmappedDcAddresses.Count -gt 0) {
            'Warning'
        }
        else {
            'Pass'
        }
        Add-HealthCheck -Id 'HC-CONFIG-003' -Category 'AD konfiguracija' -Title 'AD Sites/Subnets konfiguracija pokriva domain controllere' `
            -Status $siteStatus -Target $domainDns -ObjectType 'AD topology' -Weight 4 `
            -Evidence @{ Sites = @($sites | Select-Object -ExpandProperty Name); Subnets = $subnetNames; SubnetCount = $subnets.Count; DomainControllerSites = $dcSites; UnmappedDomainControllerAddresses = $unmappedDcAddresses } `
            -Recommendation 'Definisati stvarne mrezne CIDR subnete i mapirati ih na odgovarajuce AD site-ove. Ovo je potrebno i kada svi DC-evi pripadaju jednom site-u, jer DC Locator koristi IP subnet klijenta za izbor site-a i DC-a.'
    }
    catch {
        Add-HealthCheck -Id 'HC-CONFIG-003' -Category 'AD konfiguracija' -Title 'AD Sites/Subnets konfiguracija pokriva domain controllere' `
            -Status 'NotAssessed' -Target $domainDns -ObjectType 'AD topology' -Weight 4 `
            -Evidence @{ Error = $_.Exception.Message } `
            -Recommendation 'Pokrenuti sa AD DS RSAT modulom i pravom citanja Configuration partitiona.'
    }
}
else {
    Add-HealthCheck -Id 'HC-CONFIG-003' -Category 'AD konfiguracija' -Title 'AD Sites/Subnets konfiguracija pokriva domain controllere' `
        -Status 'NotAssessed' -Target $domainDns -ObjectType 'AD topology' -Weight 4 `
        -Evidence @{ Reason = 'AD Sites cmdleti nisu dostupni.' } `
        -Recommendation 'Instalirati AD DS RSAT alate na management sistem.'
}

$dcdiagPath = Get-HealthCommandPath -Name 'dcdiag.exe'
if ($null -eq $dcdiagPath) {
    Add-HealthCheck -Id 'HC-DCDIAG-000' -Category 'DCDiag' -Title 'Microsoft DCDiag core testovi su izvrseni' `
        -Status 'NotAssessed' -Target $env:COMPUTERNAME -ObjectType 'Collector' -Weight 10 -RequiredForScore `
        -Evidence @{ Reason = 'dcdiag.exe nije pronadjen ni kroz PATH, System32 ili Sysnative.' } `
        -Recommendation 'Pokrenuti test na domain controlleru ili management serveru sa kompletnim AD DS RSAT alatima. Bez DCDiag rezultata Health score se ne objavljuje.'
}
else {
    foreach ($dcName in $dcNames) {
        $diagResult = Invoke-HealthNativeCommand -FilePath $dcdiagPath -Arguments @("/s:$dcName", '/q') -TimeoutSeconds $NativeCommandTimeoutSeconds
        $diagStatus = Get-DcdiagQuietResultStatus -Result $diagResult
        $diagText = $diagResult.StdOut + [Environment]::NewLine + $diagResult.StdErr
        $diagFailedTests = @(Get-DcdiagFailedTestNames -Text $diagText)
        $diagSystemLogOnly = $diagStatus -eq 'Fail' -and
            $diagFailedTests.Count -gt 0 -and
            @($diagFailedTests | Where-Object { $_ -notmatch '^(?i:SystemLog)$' }).Count -eq 0
        $diagAdRelatedSystemLog = $diagSystemLogOnly -and
            $diagText -match '(?i)\bNTDS\b|\bNetlogon\b|\bKDC\b|\bKerberos\b|\bDFSR\b|DFS Replication|Directory Service|ActiveDirectory_DomainService|DNS Server|\bLSASRV\b|\bW32Time\b|\bSYSVOL\b'
        if ($diagSystemLogOnly) {
            $diagStatus = 'Warning'
        }
        $diagWeight = if (-not $diagSystemLogOnly) {
            10
        }
        elseif ($diagAdRelatedSystemLog) {
            4
        }
        else {
            0
        }
        $diagRecommendation = if ($diagSystemLogOnly -and -not $diagAdRelatedSystemLog) {
            'DCDiag core AD testovi nisu prijavili pad. SystemLog je pronasao dogadjaj druge server role; prikazan je kao operativno upozorenje, ali ne ulazi u AD Health score. Pregledati dogadjaj u servisu koji ga je generisao.'
        }
        elseif ($diagSystemLogOnly) {
            'DCDiag core AD testovi nisu prijavili pad, ali SystemLog test je pronasao nedavni server event. Pregledati event kao operativno ili sigurnosno upozorenje i potvrditi da nije uzrokovan AD DS servisom.'
        }
        else {
            'Pregledati prikazani DCDiag output i zatim pokrenuti dcdiag /s:<DC> /v za puni kontekst. Ne tretirati otvorene portove kao zamjenu za ove testove.'
        }
        Add-HealthCheck -Id 'HC-DCDIAG-001' -Category 'DCDiag' -Title 'DCDiag default testovi i System log provjera' `
            -Status $diagStatus -Target $dcName -ObjectType 'Domain controller' `
            -Weight $diagWeight -CriticalOnFail -RequiredForScore -Evidence @{ Executable = $dcdiagPath; ExitCode = $diagResult.ExitCode; TimedOut = $diagResult.TimedOut; FailedTests = $diagFailedTests; SystemLogOnly = $diagSystemLogOnly; AdRelatedSystemLog = $diagAdRelatedSystemLog; ScoreWeight = $diagWeight; Output = $diagResult.StdOut; Error = $diagResult.StdErr } `
            -Source 'dcdiag /q' `
            -Recommendation $diagRecommendation

        $securityDiagResult = Invoke-HealthNativeCommand -FilePath $dcdiagPath -Arguments @("/s:$dcName", '/test:CheckSecurityError', '/q') -TimeoutSeconds $NativeCommandTimeoutSeconds
        $securityDiagStatus = Get-DcdiagQuietResultStatus -Result $securityDiagResult
        Add-HealthCheck -Id 'HC-DCDIAG-SECURITY' -Category 'DCDiag' -Title 'DCDiag CheckSecurityError prolazi za KDC, SPN, machine account i LDAP/RPC sigurnost' `
            -Status $securityDiagStatus -Target $dcName -ObjectType 'Domain controller' `
            -Weight 8 -CriticalOnFail -RequiredForScore -Evidence @{ Executable = $dcdiagPath; ExitCode = $securityDiagResult.ExitCode; TimedOut = $securityDiagResult.TimedOut; Output = $securityDiagResult.StdOut; Error = $securityDiagResult.StdErr } `
            -Source 'dcdiag /test:CheckSecurityError /q' `
            -Recommendation 'Otkloniti prijavljene KDC, SPN, DC machine account, LDAP/RPC, prava ili time-skew probleme. Access denied u ovom testu je nalaz, ne razlog da se test preskoci.'

        $advertisingDiagResult = Invoke-HealthNativeCommand -FilePath $dcdiagPath -Arguments @("/s:$dcName", '/test:Advertising', '/q') -TimeoutSeconds $NativeCommandTimeoutSeconds
        $advertisingDiagStatus = Get-DcdiagQuietResultStatus -Result $advertisingDiagResult
        Add-HealthCheck -Id 'HC-DCDIAG-ADVERTISING' -Category 'AD osnovne usluge' -Title 'DC se pravilno oglasava kao LDAP/KDC/GC server za svoje role' `
            -Status $advertisingDiagStatus -Target $dcName -ObjectType 'Domain controller' `
            -Weight 5 -CriticalOnFail -RequiredForScore -Evidence @{ Executable = $dcdiagPath; ExitCode = $advertisingDiagResult.ExitCode; TimedOut = $advertisingDiagResult.TimedOut; Output = $advertisingDiagResult.StdOut; Error = $advertisingDiagResult.StdErr } `
            -Source 'dcdiag /test:Advertising /q' `
            -Recommendation 'Provjeriti Netlogon, KDC, NTDS, DNS locator zapise i role koje DC mora oglasavati.'

        $dnsDiagResult = Invoke-HealthNativeCommand -FilePath $dcdiagPath -Arguments @("/s:$dcName", '/test:DNS', '/DnsAll', '/q') -TimeoutSeconds $NativeCommandTimeoutSeconds
        $dnsDiagStatus = Get-DcdiagQuietResultStatus -Result $dnsDiagResult
        Add-HealthCheck -Id 'HC-DNS-003' -Category 'DNS' -Title 'DCDiag DNS All testovi prolaze' `
            -Status $dnsDiagStatus -Target $dcName -ObjectType 'Domain controller DNS' `
            -Weight 8 -CriticalOnFail -RequiredForScore -Evidence @{ Executable = $dcdiagPath; ExitCode = $dnsDiagResult.ExitCode; TimedOut = $dnsDiagResult.TimedOut; Output = $dnsDiagResult.StdOut; Error = $dnsDiagResult.StdErr } `
            -Source 'dcdiag /test:DNS /DnsAll /q' `
            -Recommendation 'Pregledati DNS client konfiguraciju, SOA/zone, delegaciju, forwardere, dynamic update i registraciju A/SRV zapisa.'
    }
}

$healthAnalysis = Get-HealthAnalysis -Checks @($script:Checks.ToArray())
$summary = [pscustomobject][ordered]@{
    AssessmentType = 'Health'
    ClientName = ConvertTo-HealthString $ClientName
    DomainDnsRoot = $domainDns
    Forest = if ($null -ne $forest) { ConvertTo-HealthString $forest.Name } else { '' }
    GeneratedAt = (Get-Date).ToString('s')
    Model = 'Protocol-aware AD Health model v3'
    HealthScore = $healthAnalysis.Score
    HealthScoreDisplay = $healthAnalysis.ScoreDisplay
    HealthScoreAvailable = [bool]$healthAnalysis.ScoreAvailable
    HealthStatus = $healthAnalysis.Status
    HealthCoveragePercent = [int]$healthAnalysis.CoveragePercent
    HealthScoreDetails = $healthAnalysis
    RiskScore = $healthAnalysis.Score
    RiskScoreStatus = $healthAnalysis.Status
    RiskScoreComplete = [bool]$healthAnalysis.IsComplete
    TotalChecks = [int]$healthAnalysis.Total
    TotalFindings = [int]$healthAnalysis.Total
    Passed = [int]$healthAnalysis.Passed
    Warnings = [int]$healthAnalysis.Warnings
    Failed = [int]$healthAnalysis.Failed
    NotAssessed = [int]$healthAnalysis.NotAssessed
    NotApplicable = [int]$healthAnalysis.NotApplicable
    Critical = @($script:Checks | Where-Object { $_.Severity -eq 'Critical' }).Count
    High = @($script:Checks | Where-Object { $_.Severity -eq 'High' }).Count
    Medium = @($script:Checks | Where-Object { $_.Severity -eq 'Medium' }).Count
    Low = @($script:Checks | Where-Object { $_.Severity -eq 'Low' }).Count
    Info = @($script:Checks | Where-Object { $_.Severity -eq 'Info' }).Count
    Users = 0
    Computers = 0
    DomainControllers = $dcNames.Count
    CategoriesHealthy = @($healthAnalysis.CategoryScores | Where-Object { $_.Status -eq 'Zdravo' }).Count
    CategoriesTotal = @($healthAnalysis.CategoryScores | Where-Object { $_.Status -ne 'Nije primjenjivo' }).Count
    CollectionWarnings = $script:CollectionWarnings.Count
}

$safeClientSegment = ((ConvertTo-HealthString $ClientName) -replace '[^\w\.-]+', '_')
$reportRoot = Join-Path $OutputPath ("{0}-health-{1}" -f $safeClientSegment, (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null

$sortedChecks = @($script:Checks | Sort-Object -Property Score -Descending)
Write-HealthJsonFile -InputObject $summary -Path (Join-Path $reportRoot 'summary.json')
Write-HealthJsonFile -InputObject $sortedChecks -Path (Join-Path $reportRoot 'findings.json')
Write-HealthJsonFile -InputObject $script:CollectionWarnings -Path (Join-Path $reportRoot 'collection-warnings.json')

if (-not $NoCsv) {
    $sortedChecks | Select-Object Id, Status, StatusLabel, Category, Title, AffectedObject, ObjectType, HealthWeight, EvidenceText, Recommendation, Source |
        Export-Csv -LiteralPath (Join-Path $reportRoot 'findings.csv') -NoTypeInformation -Encoding ASCII
}

if (-not $SkipHtml) {
    try {
        Write-HealthHtmlReport -Summary $summary -Checks $sortedChecks -Warnings @($script:CollectionWarnings.ToArray()) -Path (Join-Path $reportRoot 'report.html')
    }
    catch {
        Add-HealthCollectionWarning -Message 'HTML health report nije generisan.' -Detail $_.Exception.Message
    }
}

Write-HealthJsonFile -InputObject $script:CollectionWarnings -Path (Join-Path $reportRoot 'collection-warnings.json')

$result = [pscustomobject][ordered]@{
    Summary = $summary
    ReportPath = $reportRoot
    HtmlReport = if ($SkipHtml) { $null } else { Join-Path $reportRoot 'report.html' }
    JsonReport = Join-Path $reportRoot 'findings.json'
    CsvReport = if ($NoCsv) { $null } else { Join-Path $reportRoot 'findings.csv' }
    WarningPath = Join-Path $reportRoot 'collection-warnings.json'
}

if (-not $GuiChild) {
    $result
}
}

if ($NoGui -and $AssessmentType -eq 'Health') {
    Invoke-EmbeddedADHealthAnalyzer -ClientName $ClientName -Server $Server -Credential $Credential -OutputPath $OutputPath `
        -TcpTimeoutMilliseconds $HealthTcpTimeoutMilliseconds -NativeCommandTimeoutSeconds $HealthNativeCommandTimeoutSeconds `
        -ReplicationWarningHours $HealthReplicationWarningHours -ReplicationFailureHours $HealthReplicationFailureHours `
        -TimeWarningSeconds $HealthTimeWarningSeconds -TimeFailureSeconds $HealthTimeFailureSeconds `
        -MaxGpoChecks $HealthMaxGpoChecks -NoCsv:$NoCsv -SkipHtml:$SkipHtml -GuiChild:$GuiChild
    return
}
if (-not $NoGui) {
    try {
        $selfPath = Get-SelfScriptPath
        if ([string]::IsNullOrWhiteSpace($selfPath)) {
            throw 'Nije moguce odrediti putanju skripte za GUI start.'
        }

        if ($PSVersionTable.PSEdition -eq 'Core' -or [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
            $psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if (-not (Test-Path -LiteralPath $psExe)) {
                throw 'Windows PowerShell 5.1 nije pronadjen. Pokreni skriptu iz Windows PowerShell-a sa -STA.'
            }

            $argumentList = @(
                '-NoProfile',
                '-STA',
                '-ExecutionPolicy',
                'Bypass',
                '-File',
                "`"$selfPath`""
            )
            Start-Process -FilePath $psExe -ArgumentList $argumentList -WindowStyle Normal | Out-Null
            return
        }

        Show-ADSecurityRiskAnalyzerWpfGui -InitialClientName $ClientName -InitialServer $Server -InitialOutputPath $OutputPath -InitialConfigPath $ConfigPath
    }
    catch {
        Show-GuiStartupError -ErrorRecord $_
    }
    return
}

$script:CurrentScanStage = 'Scan startup'
trap {
    $stage = if ([string]::IsNullOrWhiteSpace($script:CurrentScanStage)) { 'Unknown stage' } else { $script:CurrentScanStage }
    $detail = @(
        "Stage: $stage",
        "Error: $($_.Exception.Message)",
        "Script stack:",
        $_.ScriptStackTrace,
        "Original error:",
        ($_ | Out-String)
    ) -join [Environment]::NewLine
    Write-Error $detail
    exit 1
}

Set-ScanStage 'Loading Active Directory module'
Import-RequiredModule

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:CollectionWarnings = New-Object System.Collections.Generic.List[object]
$script:Config = $null
$script:AdParams = @{}

if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $script:AdParams.Server = $Server
}

if ($null -ne $Credential) {
    $script:AdParams.Credential = $Credential
}

if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    Set-ScanStage 'Loading config file'
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Konfiguracijski fajl nije pronadjen: $ConfigPath"
    }

    $script:Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
}

Set-ScanStage 'Collecting domain metadata'
$domain = Get-ADDomain @script:AdParams
$forest = Get-ADForest @script:AdParams
$passwordPolicy = Get-ADDefaultDomainPasswordPolicy @script:AdParams

if ([string]::IsNullOrWhiteSpace($ClientName)) {
    $ClientName = $domain.DNSRoot
}

try {
    $fineGrainedPasswordPolicies = @(Get-ADFineGrainedPasswordPolicy @script:AdParams -Filter * -Properties AppliesTo)
}
catch {
    $fineGrainedPasswordPolicies = @()
    Add-CollectionWarning -Message 'Nije moguce prikupiti detaljne politike lozinki.' -Detail $_.Exception.Message
}

Set-ScanStage 'Collecting users, computers, groups and domain controllers'
$userProperties = @(
    'AccountNotDelegated',
    'AdminCount',
    'AllowReversiblePasswordEncryption',
    'Description',
    'DoesNotRequirePreAuth',
    'Enabled',
    'LastLogonDate',
    'MemberOf',
    'PasswordLastSet',
    'PasswordNeverExpires',
    'ServicePrincipalName',
    'SIDHistory',
    'msDS-AllowedToDelegateTo',
    'msDS-SupportedEncryptionTypes',
    'TrustedForDelegation',
    'TrustedToAuthForDelegation',
    'UseDESKeyOnly',
    'UserPrincipalName',
    'whenCreated'
)

$computerProperties = @(
    'DNSHostName',
    'Enabled',
    'LastLogonDate',
    'MemberOf',
    'OperatingSystem',
    'OperatingSystemVersion',
    'PasswordLastSet',
    'PrimaryGroupID',
    'ServicePrincipalName',
    'msDS-AllowedToDelegateTo',
    'TrustedForDelegation',
    'TrustedToAuthForDelegation',
    'whenCreated'
)

$users = @(Get-ADUser @script:AdParams -Filter * -Properties $userProperties)
$computers = @(Get-ADComputer @script:AdParams -Filter * -Properties $computerProperties)
$domainControllers = @(Get-ADDomainController @script:AdParams -Filter *)
$trustCollectionStatus = 'Complete'
try {
    $trusts = @(Get-ADTrust @script:AdParams -Filter * -Properties * -ErrorAction Stop)
}
catch {
    $trusts = @()
    $trustCollectionStatus = 'Failed'
    Add-CollectionWarning -Message 'Nije moguce prikupiti AD trust odnose.' -Detail $_.Exception.Message
}

$usersByDn = @{}
foreach ($user in $users) {
    $usersByDn[$user.DistinguishedName] = $user
}

$domainControllerHostNames = @{}
foreach ($dc in $domainControllers) {
    if (-not [string]::IsNullOrWhiteSpace($dc.HostName)) {
        $domainControllerHostNames[$dc.HostName.ToLowerInvariant()] = $true
    }
}

$domainSid = Get-DomainSidValue -Domain $domain
$netBIOSName = $domain.NetBIOSName

Set-ScanStage 'Resolving privileged and sensitive groups'
$groupDefinitions = @(
    @{ Name = 'Domain Admins'; Sid = "$domainSid-512"; Category = 'CorePrivileged'; Severity = 'High' },
    @{ Name = 'Enterprise Admins'; Sid = "$domainSid-519"; Category = 'CorePrivileged'; Severity = 'High' },
    @{ Name = 'Schema Admins'; Sid = "$domainSid-518"; Category = 'CorePrivileged'; Severity = 'High' },
    @{ Name = 'Administrators'; Sid = 'S-1-5-32-544'; Category = 'BuiltInPrivileged'; Severity = 'High' },
    @{ Name = 'Account Operators'; Sid = 'S-1-5-32-548'; Category = 'SensitiveOperator'; Severity = 'High' },
    @{ Name = 'Server Operators'; Sid = 'S-1-5-32-549'; Category = 'SensitiveOperator'; Severity = 'High' },
    @{ Name = 'Print Operators'; Sid = 'S-1-5-32-550'; Category = 'SensitiveOperator'; Severity = 'Medium' },
    @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551'; Category = 'SensitiveOperator'; Severity = 'High' },
    @{ Name = 'Replicator'; Sid = 'S-1-5-32-552'; Category = 'SensitiveOperator'; Severity = 'Medium' },
    @{ Name = 'Group Policy Creator Owners'; Sid = "$domainSid-520"; Category = 'GpoPrivileged'; Severity = 'Medium' },
    @{ Name = 'DnsAdmins'; Sid = 'DnsAdmins'; Category = 'DnsPrivileged'; Severity = 'High' },
    @{ Name = 'Pre-Windows 2000 Compatible Access'; Sid = 'S-1-5-32-554'; Category = 'LegacyAccess'; Severity = 'Medium' }
)

$resolvedGroups = New-Object System.Collections.Generic.List[object]
$privilegedUserDns = @{}
$privilegedUserInfoByDn = @{}

foreach ($definition in $groupDefinitions) {
    $group = Get-ADGroupSafe -Identity $definition.Sid -DisplayName $definition.Name
    if ($null -eq $group) {
        continue
    }

    $members = @(Get-ADGroupMembersSafe -Group $group)
    $directMembers = @(Get-ADGroupDirectMembersSafe -Group $group)
    $activeMembers = New-Object System.Collections.Generic.List[object]
    $disabledUserMembers = New-Object System.Collections.Generic.List[object]

    foreach ($member in $members) {
        $knownUser = Get-KnownUserForPrincipal -Principal $member -UsersByDn $usersByDn
        if ($null -ne $knownUser) {
            if ($knownUser.Enabled) {
                $activeMembers.Add($member) | Out-Null
            }
            else {
                $disabledUserMembers.Add($member) | Out-Null
            }
        }
        else {
            $activeMembers.Add($member) | Out-Null
        }
    }

    $resolvedGroups.Add([pscustomobject]@{
        Name                   = $group.Name
        Category               = $definition.Category
        Severity               = $definition.Severity
        Group                  = $group
        Members                = $members
        DirectMembers          = $directMembers
        ActiveMembers          = @($activeMembers.ToArray())
        DisabledUserMembers    = @($disabledUserMembers.ToArray())
        MemberText             = @($members | ForEach-Object { Get-PrincipalDisplayName -Principal $_ -NetBIOSName $netBIOSName })
        DirectMemberText       = @($directMembers | ForEach-Object { Get-PrincipalDisplayName -Principal $_ -NetBIOSName $netBIOSName })
        ActiveMemberText       = @($activeMembers.ToArray() | ForEach-Object { Get-PrincipalDisplayName -Principal $_ -NetBIOSName $netBIOSName })
        DisabledUserMemberText = @($disabledUserMembers.ToArray() | ForEach-Object { Get-PrincipalDisplayName -Principal $_ -NetBIOSName $netBIOSName })
    }) | Out-Null

    if ($definition.Category -in @('CorePrivileged', 'BuiltInPrivileged', 'SensitiveOperator', 'GpoPrivileged', 'DnsPrivileged')) {
        foreach ($member in @($activeMembers.ToArray())) {
            if ($member.objectClass -eq 'user' -and $member.PSObject.Properties['DistinguishedName']) {
                $privilegedUserDns[$member.DistinguishedName] = $true
                if (-not $privilegedUserInfoByDn.ContainsKey($member.DistinguishedName)) {
                    $privilegedUserInfoByDn[$member.DistinguishedName] = [pscustomobject]@{
                        Groups     = New-Object System.Collections.Generic.List[string]
                        Categories = New-Object System.Collections.Generic.List[string]
                    }
                }

                $privilegedUserInfoByDn[$member.DistinguishedName].Groups.Add($group.Name) | Out-Null
                $privilegedUserInfoByDn[$member.DistinguishedName].Categories.Add($definition.Category) | Out-Null
            }
        }
    }
}

$requiredPrivilegedGroups = @('Domain Admins', 'Administrators')
if ((ConvertTo-CompatibleString $forest.RootDomain) -ieq (ConvertTo-CompatibleString $domain.DNSRoot)) {
    $requiredPrivilegedGroups += @('Enterprise Admins', 'Schema Admins')
}
$resolvedPrivilegedGroupNames = @($resolvedGroups.ToArray() | Select-Object -ExpandProperty Name)
$missingPrivilegedGroups = @($requiredPrivilegedGroups | Where-Object { $resolvedPrivilegedGroupNames -notcontains $_ })
$privilegedCoverageStatus = if ($missingPrivilegedGroups.Count -eq 0) { 'Complete' } else { 'Partial' }
if ($missingPrivilegedGroups.Count -gt 0) {
    Add-CollectionWarning -Message 'Dio osnovnih privilegovanih grupa nije pronadjen.' -Detail ($missingPrivilegedGroups -join ', ')
}

$privilegedUsers = @($users | Where-Object { $privilegedUserDns.ContainsKey($_.DistinguishedName) })
$enabledUsersForPrivilegeRatio = @($users | Where-Object { $_.Enabled }).Count
$enabledPrivilegedUserCount = @($privilegedUsers | Where-Object { $_.Enabled }).Count
$privilegedUserPercent = if ($enabledUsersForPrivilegeRatio -gt 0) { [math]::Round((100.0 * $enabledPrivilegedUserCount / $enabledUsersForPrivilegeRatio), 2) } else { 0.0 }
if ($enabledUsersForPrivilegeRatio -gt 100 -and ($enabledPrivilegedUserCount -gt 50 -or $privilegedUserPercent -gt 10)) {
    Add-Finding -Id 'AD-PRIV-009' -Severity 'Medium' -Category 'Privilegovani pristup' -Title 'Prevelik udio aktivnih korisnika ima privilegovani pristup' -AffectedObject $domain.DNSRoot -ObjectType 'Domena' -Evidence @{
        EnabledUsers = $enabledUsersForPrivilegeRatio
        EnabledPrivilegedUsers = $enabledPrivilegedUserCount
        PrivilegedUserPercent = $privilegedUserPercent
        CountThreshold = 50
        PercentThreshold = 10
    } -Recommendation 'Pregledati ukupan skup privilegovanih naloga i ukloniti stalne privilegije koje nisu potrebne. Koristiti odvojene administratorske identitete i vremenski ogranicenu elevaciju gdje je moguce.'
}

Set-ScanStage 'Password policy checks'
$currentMaxPasswordAgeDays = [int]$passwordPolicy.MaxPasswordAge.TotalDays
$hasPeriodicPasswordExpiration = $currentMaxPasswordAgeDays -gt 0

if ($passwordPolicy.MinPasswordLength -lt $MinPasswordLength) {
    $passwordLengthSeverity = if ($passwordPolicy.MinPasswordLength -lt 12) { 'High' } else { 'Medium' }
    Add-Finding -Id 'AD-POLICY-001' -Severity $passwordLengthSeverity -Category 'Politika lozinki' -Title 'Minimalna duzina lozinke na domeni je ispod referentne vrijednosti' -AffectedObject $domain.DNSRoot -ObjectType 'Domena' -Evidence @{
        Current = $passwordPolicy.MinPasswordLength
        Baseline = $MinPasswordLength
        SeverityReason = if ($passwordLengthSeverity -eq 'High') { 'Minimalna duzina je znatno ispod moderne baseline vrijednosti.' } else { 'Minimalna duzina je ispod baseline vrijednosti, ali nije ekstremno niska.' }
    } -Recommendation "Povecati minimalnu duzinu lozinke na najmanje $MinPasswordLength karaktera ili dokumentovati odobrenu kompenzacijsku kontrolu."
}

if (-not $passwordPolicy.ComplexityEnabled) {
    Add-Finding -Id 'AD-POLICY-002' -Severity 'Info' -Category 'Politika lozinki' -Title 'Kompleksnost lozinki je iskljucena' -AffectedObject $domain.DNSRoot -ObjectType 'Domena' -Evidence @{
        ComplexityEnabled = $passwordPolicy.ComplexityEnabled
    } -Recommendation 'Ovo nije automatski rizik po modernim smjernicama ako postoje duge lozinke/passphrase, blocklist kompromitovanih i cestih lozinki, lockout/rate limiting i monitoring. Ako nema blocklist rjesenja, razmotriti password filter ili drugu kompenzacijsku kontrolu.'
}

if ($passwordPolicy.LockoutThreshold -eq 0) {
    Add-Finding -Id 'AD-POLICY-003' -Severity 'High' -Category 'Politika lozinki' -Title 'Prag zakljucavanja naloga je iskljucen' -AffectedObject $domain.DNSRoot -ObjectType 'Domena' -Evidence @{
        LockoutThreshold = $passwordPolicy.LockoutThreshold
    } -Recommendation 'Konfigurisati prag zakljucavanja naloga u skladu sa rizikom klijenta, zatim pratiti izvore lockout dogadjaja da se izbjegne nepotreban broj support ticketa.'
}

if ($passwordPolicy.PasswordHistoryCount -lt $MinPasswordHistory) {
    $historySeverity = if ($hasPeriodicPasswordExpiration -or $AuditPasswordExpiration) { 'Low' } else { 'Info' }
    Add-Finding -Id 'AD-POLICY-004' -Severity $historySeverity -Category 'Politika lozinki' -Title 'Historija lozinki je ispod referentne vrijednosti' -AffectedObject $domain.DNSRoot -ObjectType 'Domena' -Evidence @{
        Current = $passwordPolicy.PasswordHistoryCount
        Baseline = $MinPasswordHistory
    } -Recommendation "Povecati historiju lozinki na najmanje $MinPasswordHistory zapamcenih lozinki, posebno ako se koristi periodican istek lozinki ili ceste administrativne promjene lozinki."
}

if ($AuditPasswordExpiration -and ($currentMaxPasswordAgeDays -le 0 -or $currentMaxPasswordAgeDays -gt $MaxPasswordAgeDays)) {
    Add-Finding -Id 'AD-POLICY-005' -Severity 'Low' -Category 'Politika lozinki' -Title 'Maksimalna starost lozinke ne odgovara legacy/compliance pragu' -AffectedObject $domain.DNSRoot -ObjectType 'Domena' -Evidence @{
        CurrentDays = $currentMaxPasswordAgeDays
        BaselineDays = $MaxPasswordAgeDays
        AuditPasswordExpiration = [bool]$AuditPasswordExpiration
    } -Recommendation 'Ovaj nalaz postoji samo zato sto je ukljucen -AuditPasswordExpiration. Moderna preporuka je da se lozinke ne mijenjaju arbitrarno/periodicno, nego da se koriste duge jedinstvene lozinke, blocklist, lockout/rate limiting, monitoring i promjena pri sumnji na kompromitaciju.'
}
elseif (-not $AuditPasswordExpiration -and $hasPeriodicPasswordExpiration) {
    Add-Finding -Id 'AD-POLICY-005' -Severity 'Info' -Category 'Politika lozinki' -Title 'Periodican istek lozinki je omogucen' -AffectedObject $domain.DNSRoot -ObjectType 'Domena' -Evidence @{
        CurrentDays = $currentMaxPasswordAgeDays
        AuditPasswordExpiration = [bool]$AuditPasswordExpiration
    } -Recommendation 'Moderne NIST i Microsoft smjernice ne preporucuju arbitrarni periodican istek lozinki. Razmotriti prelazak na duge jedinstvene lozinke/passphrase, blocklist cestih i kompromitovanih lozinki, lockout/rate limiting, monitoring i obaveznu promjenu samo pri sumnji na kompromitaciju.'
}

if ($fineGrainedPasswordPolicies.Count -gt 0) {
    foreach ($fgpp in $fineGrainedPasswordPolicies) {
        $fgppAppliesTo = @($fgpp.AppliesTo | Where-Object { $null -ne $_ })
        if ($fgppAppliesTo.Count -gt 0 -and ($fgpp.MinPasswordLength -lt $MinPasswordLength -or $fgpp.LockoutThreshold -eq 0)) {
            Add-Finding -Id 'AD-POLICY-006' -Severity 'Medium' -Category 'Politika lozinki' -Title 'Detaljna politika lozinki je slabija od referentne vrijednosti' -AffectedObject $fgpp.Name -ObjectType 'Detaljna politika lozinki' -Evidence @{
                MinPasswordLength = $fgpp.MinPasswordLength
                ComplexityEnabled = $fgpp.ComplexityEnabled
                LockoutThreshold = $fgpp.LockoutThreshold
                AppliesToCount = $fgppAppliesTo.Count
                AppliesTo = @($fgppAppliesTo | ForEach-Object { [string]$_ })
            } -Recommendation 'Pregledati ovu detaljnu politiku lozinki i uskladiti minimalnu duzinu i lockout/rate limiting sa standardnom referentnom vrijednoscu klijenta, osim ako postoji odobren izuzetak.'
        }
    }
}

Set-ScanStage 'Privileged access checks'
foreach ($groupInfo in $resolvedGroups) {
    $memberCount = @($groupInfo.ActiveMembers).Count
    $memberText = @($groupInfo.ActiveMemberText | Sort-Object)
    $disabledMemberText = @($groupInfo.DisabledUserMemberText | Sort-Object)

    if ($groupInfo.Name -eq 'Domain Admins' -and $memberCount -gt $MaxDomainAdmins) {
        $domainAdminOverage = $memberCount - $MaxDomainAdmins
        $domainAdminRatio = if ($MaxDomainAdmins -gt 0) { [double]$memberCount / [double]$MaxDomainAdmins } else { [double]$memberCount }
        $domainAdminSeverity = if ($memberCount -ge 10 -or $domainAdminOverage -ge 3 -or $domainAdminRatio -ge 2.0) { 'High' } else { 'Medium' }
        Add-Finding -Id 'AD-PRIV-001' -Severity $domainAdminSeverity -Category 'Privilegovani pristup' -Title 'Clanstvo u Domain Admins grupi prelazi referentnu vrijednost' -AffectedObject $groupInfo.Name -ObjectType 'Grupa' -Evidence @{
            ActiveMemberCount = $memberCount
            DisabledUserMemberCount = $disabledMemberText.Count
            Baseline = $MaxDomainAdmins
            Overage = $domainAdminOverage
            ActiveMembers = $memberText
            DisabledUserMembers = $disabledMemberText
            SeverityReason = if ($domainAdminSeverity -eq 'High') { 'Broj aktivnih clanova je znatno iznad baseline vrijednosti.' } else { 'Broj aktivnih clanova je malo iznad baseline vrijednosti; ovo je privilegovani hygiene nalaz, ne direktan dokaz kompromitacije.' }
        } -Recommendation 'Smanjiti stalno clanstvo u Domain Admins grupi. Preferirati odvojene imenovane admin naloge i just-in-time elevaciju gdje je moguce.'
    }

    if ($groupInfo.Name -eq 'Enterprise Admins' -and $memberCount -gt $MaxEnterpriseAdmins) {
        Add-Finding -Id 'AD-PRIV-002' -Severity 'High' -Category 'Privilegovani pristup' -Title 'Clanstvo u Enterprise Admins grupi prelazi referentnu vrijednost' -AffectedObject $groupInfo.Name -ObjectType 'Grupa' -Evidence @{
            ActiveMemberCount = $memberCount
            DisabledUserMemberCount = $disabledMemberText.Count
            Baseline = $MaxEnterpriseAdmins
            ActiveMembers = $memberText
            DisabledUserMembers = $disabledMemberText
        } -Recommendation 'Drzati Enterprise Admins grupu praznom osim tokom odobrenog odrzavanja na forest nivou.'
    }

    if ($groupInfo.Category -in @('SensitiveOperator', 'DnsPrivileged', 'GpoPrivileged', 'LegacyAccess') -and $memberCount -gt 0) {
        Add-Finding -Id 'AD-PRIV-003' -Severity $groupInfo.Severity -Category 'Privilegovani pristup' -Title "Osjetljiva grupa ima clanove: $($groupInfo.Name)" -AffectedObject $groupInfo.Name -ObjectType 'Grupa' -Evidence @{
            GroupCategory = $groupInfo.Category
            ActiveMemberCount = $memberCount
            DisabledUserMemberCount = $disabledMemberText.Count
            ActiveMembers = $memberText
            DisabledUserMembers = $disabledMemberText
        } -Recommendation 'Validirati svakog clana. Ukloniti zastarjelo clanstvo i dokumentovati odobrene operativne izuzetke.'
    }

    if ($disabledMemberText.Count -gt 0) {
        $disabledMembershipSeverity = 'Low'
        Add-Finding -Id 'AD-PRIV-008' -Severity $disabledMembershipSeverity -Category 'Privilegovani pristup' -Title 'Onemoguceni nalozi i dalje imaju privilegovano clanstvo' -AffectedObject $groupInfo.Name -ObjectType 'Grupa' -Evidence @{
            DisabledUserMemberCount = $disabledMemberText.Count
            DisabledUserMembers = $disabledMemberText
            Group = $groupInfo.Name
            GroupCategory = $groupInfo.Category
            SeverityReason = 'Nalog je onemogucen, zato ovo nije aktivni login rizik. Rizik se vraca ako neko ponovo omoguci nalog bez uklanjanja clanstva.'
        } -Recommendation 'Nalozi su vec onemoguceni, zato ovo nije aktivni login rizik. Ipak ukloniti privilegovano clanstvo ili dokumentovati retention razlog, jer re-enable naloga odmah vraca privilegije.'
    }

    $allowedPatterns = Get-GroupConfigPatterns -SectionName 'AllowedPrivilegedGroupMembers' -GroupName $groupInfo.Name
    if ($allowedPatterns.Count -gt 0) {
        foreach ($member in $groupInfo.DirectMembers) {
            $knownUser = Get-KnownUserForPrincipal -Principal $member -UsersByDn $usersByDn
            if ($null -ne $knownUser -and -not $knownUser.Enabled) {
                continue
            }

            $principalName = Get-PrincipalDisplayName -Principal $member -NetBIOSName $netBIOSName
            if (-not (Test-PatternMatch -Value $principalName -Patterns $allowedPatterns)) {
                Add-Finding -Id 'AD-PRIV-004' -Severity 'High' -Category 'Privilegovani pristup' -Title 'Neocekivan clan u privilegovanoj grupi' -AffectedObject $principalName -ObjectType $member.objectClass -Evidence @{
                    Group = $groupInfo.Name
                    AllowedPatterns = $allowedPatterns
                } -Recommendation 'Potvrditi da li ovaj principal treba imati privilegovani pristup. Ako je odobren, dodati ga u referentnu konfiguraciju analizatora; u suprotnom ukloniti clanstvo.'
            }
        }
    }
}

foreach ($user in $privilegedUsers) {
    if (Test-IgnoredSamAccountName -SamAccountName $user.SamAccountName) {
        continue
    }

    if (-not $user.Enabled) {
        continue
    }

    $principalName = Get-PrincipalDisplayName -Principal $user -NetBIOSName $netBIOSName
    $lastLogonDays = Get-DaysSince -Date $user.LastLogonDate
    $privPasswordAgeDays = Get-DaysSince -Date $user.PasswordLastSet
    $privilegedGroups = @()
    $privilegedCategories = @()

    if ($privilegedUserInfoByDn.ContainsKey($user.DistinguishedName)) {
        $privilegedGroups = @($privilegedUserInfoByDn[$user.DistinguishedName].Groups.ToArray() | Sort-Object -Unique)
        $privilegedCategories = @($privilegedUserInfoByDn[$user.DistinguishedName].Categories.ToArray() | Sort-Object -Unique)
    }

    $isCorePrivileged = @($privilegedCategories | Where-Object { $_ -in @('CorePrivileged', 'BuiltInPrivileged') }).Count -gt 0

    if ($null -eq $lastLogonDays -or $lastLogonDays -gt $PrivilegedStaleDays) {
        $privilegedPasswordVeryOld = ($null -eq $privPasswordAgeDays -or $privPasswordAgeDays -gt 730)
        $privilegedStaleSeverity = if ($isCorePrivileged -and $privilegedPasswordVeryOld) { 'High' } else { 'Medium' }
        Add-Finding -Id 'AD-PRIV-005' -Severity $privilegedStaleSeverity -Category 'Privilegovani pristup' -Title 'Privilegovani nalog je zastario ili nema skorasnji logon' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            Enabled = $user.Enabled
            LastLogonDate = $user.LastLogonDate
            DaysSinceLastLogon = $lastLogonDays
            PasswordLastSet = $user.PasswordLastSet
            PasswordAgeDays = $privPasswordAgeDays
            BaselineDays = $PrivilegedStaleDays
            PrivilegedGroups = $privilegedGroups
            PrivilegedCategories = $privilegedCategories
            SeverityReason = if ($privilegedStaleSeverity -eq 'High') { 'Nalog je omogucen, ima Tier-0/core privilegije i lozinka je vrlo stara ili datum nije citljiv.' } else { 'Nalog je omogucen i privilegovan, ali sam izostanak skorog logona nije dovoljan za High ako nema dodatnog password-risk signala.' }
        } -Recommendation 'Ukloniti privilegovana prava ili onemoguciti nalog ako vise nije potreban, nakon potvrde vlasnistva i poslovne potrebe.'
    }

    if (-not $user.AccountNotDelegated) {
        $delegablePrivilegedSeverity = 'Low'
        Add-Finding -Id 'AD-PRIV-006' -Severity $delegablePrivilegedSeverity -Category 'Privilegovani pristup' -Title 'Privilegovani nalog nije oznacen kao sensitive/non-delegable' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            Enabled = $user.Enabled
            AccountNotDelegated = $user.AccountNotDelegated
            PrivilegedGroups = $privilegedGroups
            PrivilegedCategories = $privilegedCategories
            SeverityReason = 'Ovo znaci da checkbox "Account is sensitive and cannot be delegated" nije ukljucen. To je preporucena hardening zastita za privilegovane naloge, ali samo po sebi ne znaci da je delegacija vec konfigurisana ili iskoristena.'
        } -Recommendation 'Za ljudske privilegovane naloge ukljuciti "Account is sensitive and cannot be delegated" nakon kratke provjere da nalog ne koristi aplikacijske delegacijske scenarije. Ako se radi o break-glass nalogu, dokumentovati izuzetak i osigurati da se koristi samo na DC/PAW sistemima.'
    }

    if ($user.PasswordNeverExpires) {
        $privilegedPasswordIsVeryOld = ($null -eq $privPasswordAgeDays -or $privPasswordAgeDays -gt 730)
        $privilegedNoExpireSeverity = if ($isCorePrivileged -and $privilegedPasswordIsVeryOld) { 'Medium' } else { 'Low' }
        $privilegedNoExpireTitle = if ($privilegedNoExpireSeverity -eq 'Medium') { 'Privilegovani nalog koristi no-expiration i staru lozinku' } else { 'Privilegovani nalog koristi no-expiration politiku lozinke' }
        Add-Finding -Id 'AD-PRIV-007' -Severity $privilegedNoExpireSeverity -Category 'Privilegovani pristup' -Title $privilegedNoExpireTitle -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            Enabled = $user.Enabled
            PasswordNeverExpires = $user.PasswordNeverExpires
            PasswordLastSet = $user.PasswordLastSet
            PasswordAgeDays = $privPasswordAgeDays
            PrivilegedGroups = $privilegedGroups
            PrivilegedCategories = $privilegedCategories
            SeverityReason = if ($privilegedNoExpireSeverity -eq 'Medium') { 'Core privilegovani nalog koristi no-expiration i lozinka je vrlo stara ili datum nije citljiv. No-expiration sam po sebi nije problem ako je lozinka duga, jedinstvena i rotira se pri sumnji na kompromitaciju.' } else { 'No-expiration je kontrolni nalaz. Moderne smjernice ne zahtijevaju periodicnu promjenu ako su lozinke duge, jedinstvene, monitorisane i mijenjaju se pri sumnji na kompromitaciju.' }
        } -Recommendation 'No-expiration nije automatski losa praksa ako se koriste duge jedinstvene lozinke/passphrase, zabrana reuse-a, monitoring, lockout/rate limiting i promjena pri sumnji na kompromitaciju. Za privilegovane naloge validirati da je lozinka duga, jedinstvena, cuvana u vaultu i da postoji proces hitne rotacije.'
    }
}

Set-ScanStage 'User account risk checks'
$staleObjectsCoverageStatus = 'Complete'
try {
    $guest = Get-ADUser @script:AdParams -Identity "$domainSid-501" -Properties Enabled, LastLogonDate -ErrorAction Stop
    if ($guest.Enabled) {
        Add-Finding -Id 'AD-USER-001' -Severity 'High' -Category 'Higijena naloga' -Title 'Ugradjeni Guest nalog je omogucen' -AffectedObject (Get-PrincipalDisplayName -Principal $guest -NetBIOSName $netBIOSName) -ObjectType 'Korisnik' -Evidence @{
            Enabled = $guest.Enabled
            LastLogonDate = $guest.LastLogonDate
        } -Recommendation 'Onemoguciti ugradjeni Guest nalog.'
    }
}
catch {
    $staleObjectsCoverageStatus = 'Partial'
    Add-CollectionWarning -Message 'Nije moguce provjeriti ugradjeni Guest nalog.' -Detail $_.Exception.Message
}

try {
    $krbtgt = Get-ADUser @script:AdParams -Identity 'krbtgt' -Properties PasswordLastSet, Enabled -ErrorAction Stop
    $krbtgtPasswordAgeDays = Get-DaysSince -Date $krbtgt.PasswordLastSet
    if ($null -eq $krbtgtPasswordAgeDays -or $krbtgtPasswordAgeDays -gt $KrbtgtMaxPasswordAgeDays) {
        $krbtgtSeverity = if ($null -eq $krbtgtPasswordAgeDays) {
            'Medium'
        } elseif ($krbtgtPasswordAgeDays -ge 1464) {
            'High'
        } elseif ($krbtgtPasswordAgeDays -ge 732) {
            'Medium'
        } else {
            'Low'
        }
        Add-Finding -Id 'AD-USER-002' -Severity $krbtgtSeverity -Category 'Higijena naloga' -Title 'krbtgt lozinka je starija od referentne vrijednosti' -AffectedObject (Get-PrincipalDisplayName -Principal $krbtgt -NetBIOSName $netBIOSName) -ObjectType 'Korisnik' -Evidence @{
            Enabled = $krbtgt.Enabled
            PasswordLastSet = $krbtgt.PasswordLastSet
            PasswordAgeDays = $krbtgtPasswordAgeDays
            BaselineDays = $KrbtgtMaxPasswordAgeDays
            SeverityReason = if ($krbtgtSeverity -eq 'Medium') { 'Lozinka je ekstremno stara ili datum nije citljiv.' } else { 'Lozinka je starija od referentne vrijednosti, ali sama starost nije dokaz kompromitacije.' }
        } -Recommendation 'Starost krbtgt lozinke sama po sebi nije dokaz kompromitacije. Planirati kontrolisani dvostepeni reset krbtgt lozinke, s pauzom vecom od Kerberos ticket lifetime-a i validacijom replikacije. Ako postoji sumnja na kompromitaciju domene, tretirati kao incident response i rotirati hitno.'
    }
}
catch {
    $staleObjectsCoverageStatus = 'Partial'
    Add-CollectionWarning -Message 'Nije moguce provjeriti krbtgt nalog.' -Detail $_.Exception.Message
}

foreach ($user in $users) {
    if (Test-IgnoredSamAccountName -SamAccountName $user.SamAccountName) {
        continue
    }

    $principalName = Get-PrincipalDisplayName -Principal $user -NetBIOSName $netBIOSName
    $lastLogonDays = Get-DaysSince -Date $user.LastLogonDate
    $createdDays = Get-DaysSince -Date $user.whenCreated
    $passwordAgeDays = Get-DaysSince -Date $user.PasswordLastSet
    $isPrivileged = $privilegedUserDns.ContainsKey($user.DistinguishedName)
    $userPrivilegedGroups = @()
    $userPrivilegedCategories = @()

    if ($isPrivileged -and $privilegedUserInfoByDn.ContainsKey($user.DistinguishedName)) {
        $userPrivilegedGroups = @($privilegedUserInfoByDn[$user.DistinguishedName].Groups.ToArray() | Sort-Object -Unique)
        $userPrivilegedCategories = @($privilegedUserInfoByDn[$user.DistinguishedName].Categories.ToArray() | Sort-Object -Unique)
    }

    $userIsCorePrivileged = @($userPrivilegedCategories | Where-Object { $_ -in @('CorePrivileged', 'BuiltInPrivileged') }).Count -gt 0

    if ($user.Enabled -and (($null -ne $lastLogonDays -and $lastLogonDays -gt $StaleUserDays) -or ($null -eq $lastLogonDays -and $createdDays -gt $StaleUserDays))) {
        Add-Finding -Id 'AD-USER-003' -Severity 'Low' -Category 'Higijena naloga' -Title 'Omogucen korisnicki nalog je zastario' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            LastLogonDate = $user.LastLogonDate
            DaysSinceLastLogon = $lastLogonDays
            Created = $user.whenCreated
            BaselineDays = $StaleUserDays
        } -Recommendation 'Potvrditi da li je nalog jos potreban. Onemoguciti zastarjele naloge prije brisanja u skladu sa retention politikom klijenta.'
    }

    if ($user.Enabled -and $user.PasswordNeverExpires -and -not $isPrivileged) {
        Add-Finding -Id 'AD-USER-004' -Severity 'Low' -Category 'Higijena naloga' -Title 'Korisnicki nalog ima eksplicitno PasswordNeverExpires' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            PasswordNeverExpires = $user.PasswordNeverExpires
            PasswordLastSet = $user.PasswordLastSet
        } -Recommendation 'Pregledati da li je ovo svjesna iznimka ili servisni nalog. Moderna praksa dozvoljava no-expiration za jake jedinstvene korisnicke lozinke, ali za servisne naloge preferirati gMSA ili dokumentovanu rotaciju i monitoring.'
    }

    if ($AuditPasswordExpiration -and $user.Enabled -and $null -ne $passwordAgeDays -and $passwordAgeDays -gt $MaxPasswordAgeDays -and -not $user.PasswordNeverExpires) {
        Add-Finding -Id 'AD-USER-005' -Severity 'Low' -Category 'Higijena naloga' -Title 'Starost korisnicke lozinke prelazi referentnu vrijednost' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            PasswordLastSet = $user.PasswordLastSet
            PasswordAgeDays = $passwordAgeDays
            BaselineDays = $MaxPasswordAgeDays
            AuditPasswordExpiration = [bool]$AuditPasswordExpiration
        } -Recommendation 'Ovaj nalaz postoji samo zato sto je ukljucen -AuditPasswordExpiration. U modernom modelu promjenu lozinke forsirati pri korisnickom zahtjevu, promjeni role ili sumnji na kompromitaciju, a ne samo zbog starosti.'
    }

    if ($user.Enabled -and $user.DoesNotRequirePreAuth) {
        $asRepSeverity = if ($isPrivileged) { 'High' } else { 'Medium' }
        Add-Finding -Id 'AD-USER-006' -Severity $asRepSeverity -Category 'Putanja napada' -Title 'Detektovan AS-REP roastable nalog' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            DoesNotRequirePreAuth = $user.DoesNotRequirePreAuth
            IsPrivileged = $isPrivileged
            PrivilegedGroups = $userPrivilegedGroups
            PrivilegedCategories = $userPrivilegedCategories
            SeverityReason = if ($isPrivileged) { 'Privilegovani nalog je AS-REP roastable.' } else { 'Omogucen standardni nalog je AS-REP roastable; stvarni uticaj zavisi od jacine lozinke i dodijeljenih prava.' }
        } -Recommendation 'Ukljuciti Kerberos pre-authentication za ovaj nalog i rotirati lozinku.'
    }

    if ($user.Enabled -and $user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0) {
        $supportedEncryptionTypes = $user.'msDS-SupportedEncryptionTypes'
        $encryptionTypeValue = if ($null -ne $supportedEncryptionTypes) { [int64]$supportedEncryptionTypes } else { [int64]0 }
        $rc4Permitted = ($null -eq $supportedEncryptionTypes -or $encryptionTypeValue -eq 0 -or ($encryptionTypeValue -band 0x4) -ne 0)
        $aesSupported = (($encryptionTypeValue -band 0x18) -ne 0)
        $severity = 'Low'
        if ($isPrivileged) {
            $severity = 'High'
        }
        elseif ($rc4Permitted -and ($user.PasswordNeverExpires -or $null -eq $passwordAgeDays -or $passwordAgeDays -gt $ServiceAccountPasswordAgeDays)) {
            $severity = 'Medium'
        }

        Add-Finding -Id 'AD-USER-007' -Severity $severity -Category 'Putanja napada' -Title 'Kerberoastable korisnicki nalog ima SPN zapise' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            ServicePrincipalNames = @($user.ServicePrincipalName)
            PasswordLastSet = $user.PasswordLastSet
            PasswordAgeDays = $passwordAgeDays
            PasswordNeverExpires = $user.PasswordNeverExpires
            SupportedEncryptionTypes = $supportedEncryptionTypes
            Rc4Permitted = $rc4Permitted
            AesSupported = $aesSupported
            IsPrivileged = $isPrivileged
            PrivilegedGroups = $userPrivilegedGroups
            PrivilegedCategories = $userPrivilegedCategories
            SeverityReason = if ($severity -eq 'High') { 'Servisni nalog je privilegovan; kompromitacija njegove lozinke ima visok uticaj.' } elseif ($severity -eq 'Medium') { 'RC4 je dostupan, a lozinka je stara, nepoznate starosti ili bez isteka.' } else { 'SPN sam po sebi nije dokaz slabe lozinke; nalog nije poznato privilegovan i nema dodatni signal visokog rizika.' }
        } -Recommendation 'Koristiti gMSA gdje je moguce, ukloniti nepotrebne SPN zapise, osigurati AES podrsku, rotirati slabe/stare lozinke i izbjegavati privilegovane servisne naloge.'
    }

    if ($user.Enabled -and $user.TrustedForDelegation) {
        Add-Finding -Id 'AD-USER-008' -Severity 'High' -Category 'Putanja napada' -Title 'Korisnicki nalog je trusted for unconstrained delegation' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            TrustedForDelegation = $user.TrustedForDelegation
            IsPrivileged = $isPrivileged
            PrivilegedGroups = $userPrivilegedGroups
            PrivilegedCategories = $userPrivilegedCategories
        } -Recommendation 'Ukloniti unconstrained delegation sa korisnickih naloga. Ako je delegacija potrebna, koristiti constrained delegation po principu najmanjih privilegija.'
    }

    $userDelegationTargets = @($user.'msDS-AllowedToDelegateTo' | Where-Object { -not [string]::IsNullOrWhiteSpace((ConvertTo-CompatibleString $_)) })
    if ($user.Enabled -and $user.TrustedToAuthForDelegation -and $userDelegationTargets.Count -gt 0) {
        $userDelegatesToDc = Test-DelegationTargetsDomainController -Targets $userDelegationTargets -DomainControllerHostNames $domainControllerHostNames
        $protocolTransitionSeverity = if ($userDelegatesToDc) { 'High' } else { 'Medium' }
        Add-Finding -Id 'AD-USER-009' -Severity $protocolTransitionSeverity -Category 'Putanja napada' -Title 'Korisnicki nalog ima protocol transition delegation' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
            AllowedToDelegateTo = $userDelegationTargets
            DelegatesToDomainController = $userDelegatesToDc
            IsPrivileged = $isPrivileged
            PrivilegedGroups = $userPrivilegedGroups
            PrivilegedCategories = $userPrivilegedCategories
            SeverityReason = if ($userDelegatesToDc) { 'Protocol transition je dozvoljen prema servisu na domenskom kontroleru.' } else { 'Protocol transition je ogranicen na navedene non-DC servisne targete; validirati da li su svi potrebni.' }
        } -Recommendation 'Validirati ovu delegacijsku putanju. Preferirati servisne naloge sa uskom constrained delegation konfiguracijom i jakom rotacijom lozinki.'
    }

    if ($user.Enabled -and $user.UseDESKeyOnly) {
        Add-Finding -Id 'AD-USER-010' -Severity 'High' -Category 'Kriptografija' -Title 'Korisnicki nalog je konfigurisan da koristi samo DES enkripciju' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            UseDESKeyOnly = $user.UseDESKeyOnly
        } -Recommendation 'Iskljuciti DES-only enkripciju i rotirati lozinku naloga nakon potvrde kompatibilnosti aplikacije.'
    }

    if ($user.Enabled -and $user.AllowReversiblePasswordEncryption) {
        Add-Finding -Id 'AD-USER-011' -Severity 'High' -Category 'Kriptografija' -Title 'Korisnicki nalog dozvoljava reverzibilnu enkripciju lozinke' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            AllowReversiblePasswordEncryption = $user.AllowReversiblePasswordEncryption
        } -Recommendation 'Iskljuciti reverzibilnu enkripciju lozinke i rotirati lozinku naloga.'
    }

    if ($user.Enabled -and $user.AdminCount -eq 1 -and -not $isPrivileged) {
        Add-Finding -Id 'AD-USER-012' -Severity 'Medium' -Category 'Privilegovani pristup' -Title 'Korisnik ima zastarjeli adminCount flag, ali trenutno nije u poznatim privilegovanim grupama' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            Enabled = $user.Enabled
            AdminCount = $user.AdminCount
            MemberOf = @($user.MemberOf)
        } -Recommendation 'Pregledati historijsko privilegovano clanstvo. Ako nalog vise nije privilegovan, resetovati adminCount i vratiti inheritance nakon validacije.'
    }

    if ($user.Enabled -and $user.SIDHistory -and $user.SIDHistory.Count -gt 0) {
        $sidHistoryValues = @($user.SIDHistory | ForEach-Object { [string]$_ })
        $sidHistoryHasPrivilegedSid = @($user.SIDHistory | Where-Object { Test-PrivilegedSidValue -SidValue $_ }).Count -gt 0
        $sidHistorySeverity = if ($sidHistoryHasPrivilegedSid) { 'High' } else { 'Medium' }
        Add-Finding -Id 'AD-USER-013' -Severity $sidHistorySeverity -Category 'Higijena naloga' -Title 'Korisnicki nalog ima SIDHistory' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            Enabled = $user.Enabled
            SIDHistory = $sidHistoryValues
            ContainsPrivilegedSid = $sidHistoryHasPrivilegedSid
            SeverityReason = if ($sidHistorySeverity -eq 'High') { 'SIDHistory sadrzi poznati privilegovani RID/SID pattern.' } else { 'SIDHistory postoji i treba ga validirati, ali nije detektovan poznati privilegovani RID/SID pattern.' }
        } -Recommendation 'Validirati migracijsku historiju i ukloniti SIDHistory kada vise nije potreban.'
    }
}

Set-ScanStage 'Computer and operating system checks'
foreach ($computer in $computers) {
    if (Test-IgnoredSamAccountName -SamAccountName $computer.SamAccountName) {
        continue
    }

    $computerName = Get-PrincipalDisplayName -Principal $computer -NetBIOSName $netBIOSName
    $lastLogonDays = Get-DaysSince -Date $computer.LastLogonDate
    $createdDays = Get-DaysSince -Date $computer.whenCreated
    $passwordAgeDays = Get-DaysSince -Date $computer.PasswordLastSet
    $isDomainController = $false

    if (-not [string]::IsNullOrWhiteSpace($computer.DNSHostName) -and $domainControllerHostNames.ContainsKey($computer.DNSHostName.ToLowerInvariant())) {
        $isDomainController = $true
    }

    if ($computer.Enabled -and (($null -ne $lastLogonDays -and $lastLogonDays -gt $StaleComputerDays) -or ($null -eq $lastLogonDays -and $createdDays -gt $StaleComputerDays))) {
        Add-Finding -Id 'AD-COMP-001' -Severity 'Low' -Category 'Higijena racunara' -Title 'Omogucen racunarski nalog je zastario' -AffectedObject $computerName -ObjectType 'Racunar' -Evidence @{
            LastLogonDate = $computer.LastLogonDate
            DaysSinceLastLogon = $lastLogonDays
            Created = $computer.whenCreated
            BaselineDays = $StaleComputerDays
        } -Recommendation 'Potvrditi da li uredjaj jos postoji. Onemoguciti stare racunarske naloge nakon validacije kroz RMM inventar.'
    }

    if ($computer.Enabled -and $null -ne $passwordAgeDays -and $passwordAgeDays -gt 90) {
        Add-Finding -Id 'AD-COMP-002' -Severity 'Medium' -Category 'Higijena racunara' -Title 'Lozinka racunarskog naloga je zastarjela' -AffectedObject $computerName -ObjectType 'Racunar' -Evidence @{
            PasswordLastSet = $computer.PasswordLastSet
            PasswordAgeDays = $passwordAgeDays
        } -Recommendation 'Istraziti zasto se lozinka masinskog naloga ne rotira. Potvrditi da je uredjaj online i ispravan.'
    }

    $osRisk = Test-UnsupportedOperatingSystem -OperatingSystem $computer.OperatingSystem
    if ($computer.Enabled -and $null -ne $osRisk) {
        $osFindingSeverity = Get-UnsupportedOsFindingSeverity -Computer $computer -OsRisk $osRisk -IsDomainController $isDomainController
        $isServerOperatingSystem = ((ConvertTo-CompatibleString $computer.OperatingSystem) -like '*Server*')
        Add-Finding -Id 'AD-COMP-003' -Severity $osFindingSeverity -Category 'Operativni sistem' -Title 'Detektovan nepodrzan ili zastario Windows operativni sistem' -AffectedObject $computerName -ObjectType 'Racunar' -Evidence @{
            Enabled = $computer.Enabled
            OperatingSystem = $computer.OperatingSystem
            OperatingSystemVersion = $computer.OperatingSystemVersion
            MatchedPattern = $osRisk.Match
            IsDomainController = $isDomainController
            IsServer = $isServerOperatingSystem
            ExtendedSupportUnknown = $true
            SeverityReason = if ($osFindingSeverity -eq 'High') { 'Vrlo stari server ili domain controller OS ima veci AD uticaj.' } elseif ($isServerOperatingSystem) { 'AD ne pokazuje da li uredjaj ima placeni ESU; status podrske mora se potvrditi prije sanacije.' } else { 'Zastarjeli workstation OS je endpoint hygiene problem, ali sam po sebi nije direktan dokaz AD kompromitacije.' }
        } -Recommendation 'Potvrditi stvarni lifecycle i ESU status. Ako nema sigurnosnih zakrpa, planirati upgrade, zamjenu ili izolaciju; prioritet dati DC-evima, serverima i privilegovanim radnim stanicama.'
    }

    if ($computer.Enabled -and $computer.TrustedForDelegation -and -not $isDomainController) {
        Add-Finding -Id 'AD-COMP-004' -Severity 'High' -Category 'Putanja napada' -Title 'Racunar je trusted for unconstrained delegation' -AffectedObject $computerName -ObjectType 'Racunar' -Evidence @{
            TrustedForDelegation = $computer.TrustedForDelegation
            IsDomainController = $isDomainController
        } -Recommendation 'Ukloniti unconstrained delegation. Koristiti constrained delegation samo gdje je potrebna i dokumentovati poslovni razlog.'
    }

    $computerDelegationTargets = @($computer.'msDS-AllowedToDelegateTo' | Where-Object { -not [string]::IsNullOrWhiteSpace((ConvertTo-CompatibleString $_)) })
    if ($computer.Enabled -and $computer.TrustedToAuthForDelegation -and $computerDelegationTargets.Count -gt 0) {
        $computerDelegatesToDc = Test-DelegationTargetsDomainController -Targets $computerDelegationTargets -DomainControllerHostNames $domainControllerHostNames
        $computerDelegationSeverity = if ($computerDelegatesToDc) { 'High' } else { 'Medium' }
        Add-Finding -Id 'AD-COMP-005' -Severity $computerDelegationSeverity -Category 'Putanja napada' -Title 'Racunar ima protocol transition delegation' -AffectedObject $computerName -ObjectType 'Racunar' -Evidence @{
            TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
            AllowedToDelegateTo = $computerDelegationTargets
            DelegatesToDomainController = $computerDelegatesToDc
        } -Recommendation 'Validirati constrained delegation targete i osigurati da je server hardenovan i nadgledan.'
    }
}

Set-ScanStage 'Trust relationship checks'
foreach ($trust in $trusts) {
    $trustName = Get-TrustPartnerName -Trust $trust
    $trustType = ConvertTo-CompatibleString (Get-TrustPropertyValue -Trust $trust -PropertyName 'TrustType')
    $trustDirection = ConvertTo-CompatibleString (Get-TrustPropertyValue -Trust $trust -PropertyName 'Direction')
    $trustAttributes = Get-TrustAttributesValue -Trust $trust

    if ($trustType -match '^(Downlevel|1)$') {
        Add-Finding -Id 'AD-TRUST-001' -Severity 'High' -Category 'Trust odnosi' -Title 'Detektovan downlevel trust odnos' -AffectedObject $trustName -ObjectType 'Trust' -Evidence @{
            TrustType = $trustType
            Direction = $trustDirection
            TrustAttributes = $trustAttributes
        } -Recommendation 'Ukloniti downlevel trust ako vise nije potreban. Ako postoji poslovna zavisnost, dokumentovati vlasnika, smjer pristupa i plan migracije na podrzani trust model.'
    }

    if (Test-TrustSidFilteringDisabled -Trust $trust) {
        Add-Finding -Id 'AD-TRUST-002' -Severity 'High' -Category 'Trust odnosi' -Title 'SID filtering nije aktivan na izlaznom trust odnosu' -AffectedObject $trustName -ObjectType 'Trust' -Evidence @{
            Direction = $trustDirection
            TrustType = $trustType
            TrustAttributes = $trustAttributes
            SIDFilteringQuarantined = Get-TrustPropertyValue -Trust $trust -PropertyName 'SIDFilteringQuarantined'
            SIDFilteringForestAware = Get-TrustPropertyValue -Trust $trust -PropertyName 'SIDFilteringForestAware'
        } -Recommendation 'Potvrditi da li je SIDHistory migracija jos aktivna. Ako nije, ukljuciti odgovarajuci SID filtering za ovaj trust i validirati pristup nakon promjene.'
    }

    if (Test-TrustTgtDelegationEnabled -Trust $trust) {
        Add-Finding -Id 'AD-TRUST-003' -Severity 'High' -Category 'Trust odnosi' -Title 'TGT delegation je dozvoljen preko forest trusta' -AffectedObject $trustName -ObjectType 'Trust' -Evidence @{
            Direction = $trustDirection
            TrustType = $trustType
            TrustAttributes = $trustAttributes
            TGTDelegation = Get-TrustPropertyValue -Trust $trust -PropertyName 'TGTDelegation'
        } -Recommendation 'Iskljuciti TGT delegation preko trusta osim ako postoji dokumentovana i validirana potreba. Nakon promjene testirati autentikacijske tokove izmedju forest okruzenja.'
    }

    $usesAesKeys = Get-TrustPropertyValue -Trust $trust -PropertyName 'UsesAESKeys'
    if ($null -ne $usesAesKeys -and $usesAesKeys -eq $false -and (Get-TrustDirectionCode -Trust $trust) -in @(2, 3)) {
        Add-Finding -Id 'AD-TRUST-004' -Severity 'Low' -Category 'Trust odnosi' -Title 'Trust odnos nema aktivne AES Kerberos kljuceve' -AffectedObject $trustName -ObjectType 'Trust' -Evidence @{
            Direction = $trustDirection
            TrustType = $trustType
            UsesAESKeys = $usesAesKeys
            TrustAttributes = $trustAttributes
        } -Recommendation 'Provjeriti kompatibilnost obje strane i omoguciti AES kljuceve za trust, zatim rotirati trust lozinku kroz kontrolisan postupak.'
    }
}

$failedLoginEvents = @()
$failedLoginDcStats = @()
$failedLoginSourceScope = 'DomainControllers'

Set-ScanStage 'Failed login checks'
if ($SkipFailedLoginAudit) {
    Add-CollectionWarning -Message 'Failed login provjera je preskocena.' -Detail 'Pokrenuto sa -SkipFailedLoginAudit.'
}
elseif ($FailedLoginLookbackHours -gt 0) {
    $failedLoginStartTime = (Get-Date).AddHours(-1 * [math]::Abs($FailedLoginLookbackHours))
    try {
        $failedLoginAudit = Get-FailedLoginAudit -DomainControllers $domainControllers -StartTime $failedLoginStartTime -Credential $Credential -MaxEventsPerDc $FailedLoginMaxEventsPerDc -QueryTimeoutSeconds $FailedLoginQueryTimeoutSeconds
        if (@($failedLoginAudit.DomainControllers | Where-Object { $_.Status -eq 'OK' }).Count -eq 0) {
            $localEndpoint = [pscustomobject][ordered]@{
                HostName = $env:COMPUTERNAME
                Name     = $env:COMPUTERNAME
            }
            Add-CollectionWarning -Message 'Nije moguce procitati failed login evente ni sa jednog DC-a.' -Detail 'Pokusavam fallback na lokalni endpoint Security log.'
            $failedLoginAudit = Get-FailedLoginAudit -DomainControllers @($localEndpoint) -StartTime $failedLoginStartTime -Credential $null -MaxEventsPerDc $FailedLoginMaxEventsPerDc -QueryTimeoutSeconds $FailedLoginQueryTimeoutSeconds
            $failedLoginSourceScope = 'LocalEndpoint'
        }

        $failedLoginEvents = @($failedLoginAudit.Events)
        $failedLoginDcStats = @($failedLoginAudit.DomainControllers)
        $failedLoginTotal = $failedLoginEvents.Count
        $failedLoginReachedCap = @($failedLoginDcStats | Where-Object { $_.ReachedMaxEvents }).Count -gt 0

        if ($failedLoginTotal -gt 0) {
            $failedLoginSeverity = 'Info'
            if ($failedLoginReachedCap -or $failedLoginTotal -ge $FailedLoginHighThreshold) {
                $failedLoginSeverity = 'High'
            }
            elseif ($failedLoginTotal -ge $FailedLoginMediumThreshold) {
                $failedLoginSeverity = 'Medium'
            }

            $topFailedLoginAccounts = New-FailedLoginGroupSummary -Events $failedLoginEvents -PropertyName 'Account' -First 20
            $topFailedLoginSources = New-FailedLoginGroupSummary -Events $failedLoginEvents -PropertyName 'Source' -First 20
            $eventIdSummary = @($failedLoginEvents |
                Group-Object -Property EventId |
                Sort-Object -Property Count -Descending |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        EventId = $_.Name
                        Count   = [int]$_.Count
                    }
                })

            Add-Finding -Id 'AD-AUTH-001' -Severity $failedLoginSeverity -Category 'Autentikacija' -Title 'Failed logins detektovani na domenskim kontrolerima' -AffectedObject $domain.DNSRoot -ObjectType 'Domena' -Evidence @{
                LookbackHours = $FailedLoginLookbackHours
                Since = $failedLoginStartTime.ToString('s')
                TotalFailedLogins = $failedLoginTotal
                MediumThreshold = $FailedLoginMediumThreshold
                HighThreshold = $FailedLoginHighThreshold
                MaxEventsPerDc = $FailedLoginMaxEventsPerDc
                QueryTimeoutSeconds = $FailedLoginQueryTimeoutSeconds
                ReachedMaxEvents = $failedLoginReachedCap
                SourceScope = $failedLoginSourceScope
                DomainControllers = $failedLoginDcStats
                EventIds = $eventIdSummary
                TopAccounts = $topFailedLoginAccounts
                TopSources = $topFailedLoginSources
            } -Recommendation 'Pregledati top naloge i izvore failed logina. Korelirati sa Wazuh/SentinelOne/RMM podacima, provjeriti password spraying, brute force, stare servise i pogresno sacuvane lozinke. Ako postoji obrazac napada, blokirati izvor, rotirati ugrozene lozinke i podesiti lockout/rate limiting i alerting.'

            $accountHighThreshold = [math]::Max(($FailedLoginAccountThreshold * 3), 30)
            foreach ($accountSummary in @($topFailedLoginAccounts | Where-Object { $_.Count -ge $FailedLoginAccountThreshold } | Select-Object -First 20)) {
                $accountSeverity = if ($accountSummary.Count -ge $accountHighThreshold) { 'High' } else { 'Medium' }
                Add-Finding -Id 'AD-AUTH-002' -Severity $accountSeverity -Category 'Autentikacija' -Title 'Nalog ima povecan broj failed logina' -AffectedObject $accountSummary.Name -ObjectType 'Login nalog' -Evidence @{
                    LookbackHours = $FailedLoginLookbackHours
                    FailedLogins = [int]$accountSummary.Count
                    MediumThreshold = $FailedLoginAccountThreshold
                    HighThreshold = $accountHighThreshold
                    Sources = $accountSummary.Sources
                    DomainControllers = $accountSummary.DomainControllers
                    LastSeen = $accountSummary.LastSeen
                } -Recommendation 'Provjeriti da li korisnik ima stare sacuvane kredencijale, mapirane diskove, servise, mobile mail profile ili pokusaje napada. Ako je nepoznat izvor ili visok broj pokusaja, tretirati kao moguci password spraying/brute force i eskalirati incident.'
            }
        }
    }
    catch {
        Add-CollectionWarning -Message 'Failed login provjera nije zavrsena.' -Detail $_.Exception.Message
    }
}
else {
    Add-CollectionWarning -Message 'Failed login provjera je preskocena.' -Detail 'FailedLoginLookbackHours je 0 ili manji.'
}

Set-ScanStage 'Building summary and reports'
$criticalCount = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount = @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
$mediumCount = @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowCount = @($script:Findings | Where-Object { $_.Severity -eq 'Low' }).Count
$infoCount = @($script:Findings | Where-Object { $_.Severity -eq 'Info' }).Count

$scoreContext = [ordered]@{
    EnabledUsers     = @($users | Where-Object { $_.Enabled }).Count
    EnabledComputers = @($computers | Where-Object { $_.Enabled }).Count
    PrivilegedUsers  = @($privilegedUsers | Where-Object { $_.Enabled }).Count
    Trusts           = $trusts.Count
}
$assessmentCoverage = [ordered]@{
    StaleObjects       = $staleObjectsCoverageStatus
    PrivilegedAccounts = $privilegedCoverageStatus
    Trusts             = $trustCollectionStatus
    Anomalies          = 'Complete'
}

$riskScoreAnalysis = Get-RiskScoreAnalysis -Findings $script:Findings -Context $scoreContext -Coverage $assessmentCoverage
$riskScore = [int]$riskScoreAnalysis.Score
$riskBaseline = Get-RiskScoreBaseline -Score $riskScore -RiskScoreDetails $riskScoreAnalysis

$summary = [pscustomobject][ordered]@{
    AssessmentType              = 'Security'
    ClientName                  = $ClientName
    DomainDnsRoot               = $domain.DNSRoot
    Forest                      = $forest.Name
    GeneratedAt                 = (Get-Date).ToString('s')
    RiskScore                   = $riskScore
    RiskScoreModel              = $riskScoreAnalysis.Model
    RiskScoreStatus             = $riskScoreAnalysis.ScoreStatus
    RiskScoreComplete           = $riskScoreAnalysis.IsComplete
    RiskScoreDetails            = $riskScoreAnalysis
    RiskBaseline                = $riskBaseline
    AssessmentCoverage          = $assessmentCoverage
    Critical                    = $criticalCount
    High                        = $highCount
    Medium                      = $mediumCount
    Low                         = $lowCount
    Info                        = $infoCount
    TotalFindings               = $script:Findings.Count
    Users                       = $users.Count
    EnabledUsers                = @($users | Where-Object { $_.Enabled }).Count
    Computers                   = $computers.Count
    EnabledComputers            = @($computers | Where-Object { $_.Enabled }).Count
    DomainControllers           = $domainControllers.Count
    Trusts                      = $trusts.Count
    FineGrainedPasswordPolicies = $fineGrainedPasswordPolicies.Count
    FailedLogins                = $failedLoginEvents.Count
    FailedLoginSourceScope      = $failedLoginSourceScope
    FailedLoginLookbackHours    = $FailedLoginLookbackHours
    FailedLoginQueryTimeoutSec  = $FailedLoginQueryTimeoutSeconds
    FailedLoginDcsQueried       = @($failedLoginDcStats | Where-Object { $_.Status -eq 'OK' }).Count
    FailedLoginDcsFailed        = @($failedLoginDcStats | Where-Object { $_.Status -ne 'OK' }).Count
    CollectionWarnings          = $script:CollectionWarnings.Count
}

$safeClientSegment = ($ClientName -replace '[^\w\.-]+', '_')
$reportRoot = Join-Path $OutputPath ("{0}-{1}" -f $safeClientSegment, (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null

$sortedFindings = @(ConvertTo-GuiFindingArray -InputObject $script:Findings | Sort-Object -Property Score -Descending)
$reportFindings = Select-ReportFindingFields -Findings $sortedFindings

Write-JsonFile -InputObject $summary -Path (Join-Path $reportRoot 'summary.json')
Write-JsonFile -InputObject $sortedFindings -Path (Join-Path $reportRoot 'findings.json')
Write-JsonFile -InputObject $script:CollectionWarnings -Path (Join-Path $reportRoot 'collection-warnings.json')

if (-not $NoCsv) {
    $reportFindings | Export-Csv -LiteralPath (Join-Path $reportRoot 'findings.csv') -NoTypeInformation -Encoding ASCII
}

if (-not $SkipHtml) {
    try {
        Set-ScanStage 'Writing HTML report'
        Write-HtmlReport -Summary $summary -Findings $sortedFindings -Warnings @($script:CollectionWarnings.ToArray()) -Path (Join-Path $reportRoot 'report.html')
    }
    catch {
        Add-CollectionWarning -Message 'HTML report nije generisan.' -Detail $_.Exception.Message
    }
}

Write-JsonFile -InputObject $script:CollectionWarnings -Path (Join-Path $reportRoot 'collection-warnings.json')

$result = [pscustomobject][ordered]@{
    Summary     = $summary
    ReportPath  = $reportRoot
    HtmlReport  = if ($SkipHtml) { $null } else { Join-Path $reportRoot 'report.html' }
    JsonReport  = Join-Path $reportRoot 'findings.json'
    CsvReport   = if ($NoCsv) { $null } else { Join-Path $reportRoot 'findings.csv' }
    WarningPath = Join-Path $reportRoot 'collection-warnings.json'
}

if (-not $GuiChild) {
    $result
}

