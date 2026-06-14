<#
.SYNOPSIS
    Read-only Active Directory sigurnosni analizator za MSP klijentske domene.

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

    [int]$MaxEnterpriseAdmins = 2,

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

    [switch]$NoCsv
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
        'Putanja napada' { return 'AttackPath' }
        'Privilegovani pristup' { return 'PrivilegedAccess' }
        'Autentikacija' { return 'Authentication' }
        'Kriptografija' { return 'Crypto' }
        'Politika lozinki' { return 'PasswordPolicy' }
        'Higijena naloga' { return 'AccountHygiene' }
        'Higijena racunara' { return 'ComputerHygiene' }
        'Operativni sistem' { return 'OperatingSystem' }
        default { return 'General' }
    }
}

function Get-RiskAreaLabel {
    param(
        [string]$RiskArea
    )

    switch ((ConvertTo-CompatibleString $RiskArea)) {
        'AttackPath' { return 'Putanja napada' }
        'PrivilegedAccess' { return 'Privilegovani pristup' }
        'Authentication' { return 'Autentikacija' }
        'Crypto' { return 'Kriptografija' }
        'PasswordPolicy' { return 'Politika lozinki' }
        'AccountHygiene' { return 'Higijena naloga' }
        'ComputerHygiene' { return 'Higijena racunara' }
        'OperatingSystem' { return 'Operativni sistem' }
        default { return 'Opste' }
    }
}

function Get-FindingRuleMetadata {
    param(
        [string]$Id,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        [string]$Category
    )

    $riskArea = Get-RiskAreaFromCategory -Category $Category
    $weight = switch ($Severity) {
        'Critical' { 85 }
        'High' { 50 }
        'Medium' { 24 }
        'Low' { 6 }
        'Info' { 0 }
    }
    $cap = switch ($Severity) {
        'Critical' { 95 }
        'High' { 70 }
        'Medium' { 45 }
        'Low' { 20 }
        'Info' { 3 }
    }
    $scale = switch ($Severity) {
        'Critical' { 2.0 }
        'High' { 6.0 }
        'Medium' { 20.0 }
        'Low' { 120.0 }
        'Info' { 100.0 }
    }

    switch -Regex ((ConvertTo-CompatibleString $Id)) {
        '^AD-USER-008$' { $riskArea = 'AttackPath'; $weight = 90; $cap = 96; $scale = 1.0; break }
        '^AD-COMP-004$' { $riskArea = 'AttackPath'; $weight = 72; $cap = 88; $scale = 4.0; break }
        '^AD-USER-006$' {
            $riskArea = 'AttackPath'
            if ($Severity -eq 'Critical') { $weight = 82; $cap = 92; $scale = 2.0 }
            else { $weight = 55; $cap = 75; $scale = 8.0 }
            break
        }
        '^AD-USER-007$' {
            $riskArea = 'AttackPath'
            if ($Severity -eq 'Critical') { $weight = 84; $cap = 93; $scale = 2.0 }
            elseif ($Severity -eq 'High') { $weight = 58; $cap = 78; $scale = 10.0 }
            else { $weight = 30; $cap = 50; $scale = 18.0 }
            break
        }
        '^AD-USER-009$' {
            $riskArea = 'AttackPath'
            if ($Severity -eq 'Critical') { $weight = 82; $cap = 92; $scale = 2.0 }
            else { $weight = 55; $cap = 75; $scale = 7.0 }
            break
        }
        '^AD-COMP-005$' { $riskArea = 'AttackPath'; $weight = 35; $cap = 58; $scale = 12.0; break }

        '^AD-PRIV-002$' {
            $riskArea = 'PrivilegedAccess'
            if ($Severity -eq 'High') { $weight = 68; $cap = 88; $scale = 1.0 }
            else { $weight = 36; $cap = 55; $scale = 1.0 }
            break
        }
        '^AD-PRIV-004$' { $riskArea = 'PrivilegedAccess'; $weight = 62; $cap = 82; $scale = 4.0; break }
        '^AD-PRIV-005$' {
            $riskArea = 'PrivilegedAccess'
            if ($Severity -eq 'High') { $weight = 50; $cap = 65; $scale = 6.0 }
            else { $weight = 28; $cap = 45; $scale = 10.0 }
            break
        }
        '^AD-PRIV-006$' {
            $riskArea = 'PrivilegedAccess'
            if ($Severity -eq 'Medium') { $weight = 14; $cap = 28; $scale = 12.0 }
            elseif ($Severity -eq 'Low') { $weight = 5; $cap = 12; $scale = 20.0 }
            else { $weight = 3; $cap = 8; $scale = 20.0 }
            break
        }
        '^AD-PRIV-007$' {
            $riskArea = 'PrivilegedAccess'
            if ($Severity -eq 'Medium') { $weight = 14; $cap = 28; $scale = 12.0 }
            elseif ($Severity -eq 'Low') { $weight = 6; $cap = 14; $scale = 20.0 }
            else { $weight = 3; $cap = 8; $scale = 20.0 }
            break
        }
        '^AD-PRIV-008$' {
            $riskArea = 'PrivilegedAccess'
            if ($Severity -eq 'Medium') { $weight = 12; $cap = 24; $scale = 12.0 }
            else { $weight = 6; $cap = 12; $scale = 20.0 }
            break
        }
        '^AD-PRIV-001$' {
            $riskArea = 'PrivilegedAccess'
            if ($Severity -eq 'High') { $weight = 58; $cap = 75; $scale = 1.0 }
            else { $weight = 28; $cap = 45; $scale = 1.0 }
            break
        }
        '^AD-PRIV-003$' {
            $riskArea = 'PrivilegedAccess'
            if ($Severity -eq 'High') { $weight = 50; $cap = 70; $scale = 4.0 }
            else { $weight = 28; $cap = 50; $scale = 8.0 }
            break
        }
        '^AD-USER-012$' { $riskArea = 'PrivilegedAccess'; $weight = 22; $cap = 40; $scale = 10.0; break }

        '^AD-AUTH-001$' {
            $riskArea = 'Authentication'
            if ($Severity -eq 'High') { $weight = 40; $cap = 60; $scale = 1.0 }
            elseif ($Severity -eq 'Medium') { $weight = 22; $cap = 42; $scale = 1.0 }
            else { $weight = 3; $cap = 8; $scale = 1.0 }
            break
        }
        '^AD-AUTH-002$' {
            $riskArea = 'Authentication'
            if ($Severity -eq 'High') { $weight = 45; $cap = 65; $scale = 6.0 }
            else { $weight = 25; $cap = 45; $scale = 8.0 }
            break
        }

        '^AD-USER-010$|^AD-USER-011$' { $riskArea = 'Crypto'; $weight = 60; $cap = 82; $scale = 5.0; break }

        '^AD-POLICY-001$' {
            $riskArea = 'PasswordPolicy'
            if ($Severity -eq 'High') { $weight = 35; $cap = 50; $scale = 1.0 }
            else { $weight = 18; $cap = 35; $scale = 1.0 }
            break
        }
        '^AD-POLICY-003$' { $riskArea = 'PasswordPolicy'; $weight = 50; $cap = 70; $scale = 1.0; break }
        '^AD-POLICY-006$' { $riskArea = 'PasswordPolicy'; $weight = 25; $cap = 45; $scale = 3.0; break }
        '^AD-POLICY-004$|^AD-POLICY-005$' { $riskArea = 'PasswordPolicy'; $weight = 5; $cap = 15; $scale = 2.0; break }
        '^AD-POLICY-002$' { $riskArea = 'PasswordPolicy'; $weight = 0; $cap = 3; $scale = 1.0; break }

        '^AD-USER-001$' { $riskArea = 'AccountHygiene'; $weight = 50; $cap = 65; $scale = 1.0; break }
        '^AD-USER-002$' {
            $riskArea = 'AccountHygiene'
            if ($Severity -eq 'High') { $weight = 45; $cap = 65; $scale = 1.0 }
            elseif ($Severity -eq 'Medium') { $weight = 20; $cap = 35; $scale = 1.0 }
            else { $weight = 8; $cap = 18; $scale = 1.0 }
            break
        }
        '^AD-USER-003$' { $riskArea = 'AccountHygiene'; $weight = 5; $cap = 20; $scale = 150.0; break }
        '^AD-USER-004$' { $riskArea = 'AccountHygiene'; $weight = 5; $cap = 18; $scale = 50.0; break }
        '^AD-USER-005$' { $riskArea = 'AccountHygiene'; $weight = 3; $cap = 10; $scale = 60.0; break }
        '^AD-USER-013$' {
            $riskArea = 'AccountHygiene'
            if ($Severity -eq 'High') { $weight = 45; $cap = 65; $scale = 6.0 }
            else { $weight = 25; $cap = 45; $scale = 10.0 }
            break
        }

        '^AD-COMP-001$' { $riskArea = 'ComputerHygiene'; $weight = 4; $cap = 18; $scale = 180.0; break }
        '^AD-COMP-002$' { $riskArea = 'ComputerHygiene'; $weight = 10; $cap = 30; $scale = 100.0; break }

        '^AD-COMP-003$' {
            $riskArea = 'OperatingSystem'
            if ($Severity -eq 'High') { $weight = 42; $cap = 70; $scale = 80.0 }
            else { $weight = 18; $cap = 45; $scale = 100.0 }
            break
        }
    }

    return [pscustomobject][ordered]@{
        RiskArea   = $riskArea
        RuleWeight = [int]$weight
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

    $metadata = Get-FindingRuleMetadata -Id (ConvertTo-CompatibleString $Finding.Id) -Severity $severity -Category (ConvertTo-CompatibleString $Finding.Category)
    $riskArea = if ($Finding.PSObject.Properties['RiskArea'] -and -not [string]::IsNullOrWhiteSpace($Finding.RiskArea)) { ConvertTo-CompatibleString $Finding.RiskArea } else { ConvertTo-CompatibleString $metadata.RiskArea }
    $ruleWeight = if ($Finding.PSObject.Properties['RuleWeight'] -and $null -ne $Finding.RuleWeight) { [int]$Finding.RuleWeight } else { [int]$metadata.RuleWeight }

    return [pscustomobject][ordered]@{
        RiskArea        = $riskArea
        RiskAreaName    = Get-RiskAreaLabel -RiskArea $riskArea
        RuleWeight      = $ruleWeight
        OccurrenceModel = 'ProbabilityUnionSqrtDiminishing'
    }
}

function Get-SeverityProbabilityFactor {
    param(
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { return 1.15 }
        'High' { return 0.85 }
        'Medium' { return 0.45 }
        'Low' { return 0.18 }
        'Info' { return 0.03 }
        default { return 0.03 }
    }
}

function Get-RuleRiskContribution {
    param(
        [int]$Count,
        [int]$RuleWeight,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )

    if ($Count -le 0) {
        return [pscustomobject][ordered]@{
            BaseProbability      = 0.0
            RiskMass             = 0.0
            Contribution         = 0.0
            OccurrenceModel      = 'ProbabilityUnionSqrtDiminishing'
            RepeatAdjustedEvents = 0.0
        }
    }

    $normalizedWeight = [math]::Max(0.0, [math]::Min(1.0, ([double]$RuleWeight / 100.0)))
    $severityFactor = Get-SeverityProbabilityFactor -Severity $Severity
    $baseProbability = [math]::Pow($normalizedWeight, 2.0) * [double]$severityFactor
    $baseProbability = [math]::Max(0.0, [math]::Min(0.92, $baseProbability))
    $riskMass = 0.0
    $repeatAdjustedEvents = 0.0

    for ($i = 1; $i -le $Count; $i++) {
        $repeatFactor = 1.0 / [math]::Sqrt([double]$i)
        $occurrenceProbability = [math]::Max(0.0, [math]::Min(0.95, ($baseProbability * $repeatFactor)))
        if ($occurrenceProbability -le 0) {
            continue
        }

        $riskMass += (-1.0 * [math]::Log(1.0 - $occurrenceProbability))
        $repeatAdjustedEvents += $repeatFactor
    }

    $contribution = 100.0 * (1.0 - [math]::Exp(-1.0 * $riskMass))

    return [pscustomobject][ordered]@{
        BaseProbability      = [math]::Round($baseProbability, 4)
        RiskMass             = [math]::Round($riskMass, 4)
        Contribution         = [math]::Round($contribution, 2)
        OccurrenceModel      = 'ProbabilityUnionSqrtDiminishing'
        RepeatAdjustedEvents = [math]::Round($repeatAdjustedEvents, 2)
    }
}

function Get-RiskAreaWeight {
    param(
        [string]$RiskArea
    )

    switch ((ConvertTo-CompatibleString $RiskArea)) {
        'AttackPath' { return 0.24 }
        'PrivilegedAccess' { return 0.24 }
        'Authentication' { return 0.13 }
        'Crypto' { return 0.11 }
        'PasswordPolicy' { return 0.10 }
        'OperatingSystem' { return 0.08 }
        'AccountHygiene' { return 0.06 }
        'ComputerHygiene' { return 0.04 }
        default { return 0.03 }
    }
}

function Get-RiskScoreAnalysis {
    param(
        [object[]]$Findings
    )

    $allFindings = ConvertTo-GuiFindingArray -InputObject $Findings
    $ruleSummaries = New-Object System.Collections.Generic.List[object]
    $areaRaw = @{}
    $totalRiskMass = 0.0
    $criticalCount = @($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = @($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $infoCount = @($allFindings | Where-Object { $_.Severity -eq 'Info' }).Count

    foreach ($group in @($allFindings | Group-Object -Property Id, Severity)) {
        $sample = @($group.Group | Select-Object -First 1)[0]
        $metadata = Get-FindingEffectiveRuleMetadata -Finding $sample
        $riskArea = $metadata.RiskArea
        $ruleWeight = [int]$metadata.RuleWeight
        $ruleRisk = Get-RuleRiskContribution -Count $group.Count -RuleWeight $ruleWeight -Severity (ConvertTo-CompatibleString $sample.Severity)
        $contribution = [double]$ruleRisk.Contribution

        if (-not $areaRaw.ContainsKey($riskArea)) {
            $areaRaw[$riskArea] = 0.0
        }
        $areaRaw[$riskArea] = [double]$areaRaw[$riskArea] + [double]$ruleRisk.RiskMass
        $totalRiskMass += [double]$ruleRisk.RiskMass

        $ruleSummaries.Add([pscustomobject][ordered]@{
            Id                   = ConvertTo-CompatibleString $sample.Id
            Title                = ConvertTo-CompatibleString $sample.Title
            Severity             = ConvertTo-CompatibleString $sample.Severity
            RiskArea             = ConvertTo-CompatibleString $riskArea
            RiskAreaName         = Get-RiskAreaLabel -RiskArea $riskArea
            Count                = [int]$group.Count
            RuleWeight           = [int]$ruleWeight
            BaseProbability      = [double]$ruleRisk.BaseProbability
            RiskMass             = [double]$ruleRisk.RiskMass
            RepeatAdjustedEvents = [double]$ruleRisk.RepeatAdjustedEvents
            Contribution         = [double]$contribution
        }) | Out-Null
    }

    $areaSummaries = New-Object System.Collections.Generic.List[object]
    $dominantScore = 0.0

    foreach ($riskArea in @($areaRaw.Keys)) {
        $weight = Get-RiskAreaWeight -RiskArea $riskArea
        $riskMass = [double]$areaRaw[$riskArea]
        $areaRules = @($ruleSummaries.ToArray() | Where-Object { (ConvertTo-CompatibleString $_.RiskArea) -eq (ConvertTo-CompatibleString $riskArea) })
        $dominantRuleContribution = 0.0
        if ($areaRules.Count -gt 0) {
            $dominantRuleContribution = [double](@($areaRules | Measure-Object -Property Contribution -Maximum).Maximum)
        }
        $score = [math]::Round((100.0 * (1.0 - [math]::Exp(-1.0 * $riskMass))), 2)
        $dominantScore = [math]::Max($dominantScore, $score)
        $areaSummaries.Add([pscustomobject][ordered]@{
            RiskArea                 = ConvertTo-CompatibleString $riskArea
            Name                     = Get-RiskAreaLabel -RiskArea $riskArea
            Score                    = [double]$score
            RiskMass                 = [math]::Round($riskMass, 4)
            DominantRuleContribution = [math]::Round($dominantRuleContribution, 2)
            Weight                   = [double]$weight
        }) | Out-Null
    }

    $scoreValue = 100.0 * (1.0 - [math]::Exp(-1.0 * $totalRiskMass))
    $score = [int][math]::Round([math]::Min(100, $scoreValue), 0)

    return [pscustomobject][ordered]@{
        Score         = [int][math]::Min(100, $score)
        Model         = 'NIST likelihood-impact probability union v7'
        DominantScore = [math]::Round($dominantScore, 2)
        RiskMass      = [math]::Round($totalRiskMass, 4)
        WeightedScore = [math]::Round($scoreValue, 2)
        Counts        = [pscustomobject][ordered]@{
            Critical = $criticalCount
            High     = $highCount
            Medium   = $mediumCount
            Low      = $lowCount
            Info     = $infoCount
            Total    = $allFindings.Count
        }
        AreaScores    = @($areaSummaries | Sort-Object -Property Score -Descending)
        RuleScores    = @($ruleSummaries | Sort-Object -Property Contribution -Descending)
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

    $criticalCount = [math]::Max(0, $Critical)
    $highCount = [math]::Max(0, $High)
    $mediumCount = [math]::Max(0, $Medium)
    $lowCount = [math]::Max(0, $Low)
    $infoCount = [math]::Max(0, $Info)

    $riskMass = 0.0
    foreach ($item in @(
            @{ Count = $criticalCount; Weight = 85; Severity = 'Critical' },
            @{ Count = $highCount; Weight = 50; Severity = 'High' },
            @{ Count = $mediumCount; Weight = 24; Severity = 'Medium' },
            @{ Count = $lowCount; Weight = 6; Severity = 'Low' },
            @{ Count = $infoCount; Weight = 0; Severity = 'Info' }
        )) {
        $riskMass += [double](Get-RuleRiskContribution -Count $item.Count -RuleWeight $item.Weight -Severity $item.Severity).RiskMass
    }

    $score = [int][math]::Round((100.0 * (1.0 - [math]::Exp(-1.0 * $riskMass))), 0)

    return [int]$score
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

    $ruleMetadata = Get-FindingRuleMetadata -Id $Id -Severity $Severity -Category $Category

    $script:Findings.Add([pscustomobject][ordered]@{
        Id             = $Id
        Severity       = $Severity
        Score          = [int]$ruleMetadata.RuleWeight
        RiskArea       = ConvertTo-CompatibleString $ruleMetadata.RiskArea
        RiskAreaName   = Get-RiskAreaLabel -RiskArea $ruleMetadata.RiskArea
        RuleWeight     = [int]$ruleMetadata.RuleWeight
        Category       = ConvertTo-CompatibleString $Category
        Title          = ConvertTo-CompatibleString $Title
        AffectedObject = ConvertTo-CompatibleString $AffectedObject
        ObjectType     = ConvertTo-CompatibleString $ObjectType
        Evidence       = $compatibleEvidence
        EvidenceText   = ConvertTo-EvidenceText -Evidence $compatibleEvidence
        Recommendation = ConvertTo-CompatibleString $Recommendation
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
            if ([string]::IsNullOrWhiteSpace($source)) {
                $source = 'Unknown'
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
                Status           = Get-JobEventDataValue -Data $data -Names @('Status')
                SubStatus        = Get-JobEventDataValue -Data $data -Names @('SubStatus')
                FailureReason    = Get-JobEventDataValue -Data $data -Names @('FailureReason')
                AuthPackage      = Get-JobEventDataValue -Data $data -Names @('AuthenticationPackageName', 'PackageName')
            }
        }

        $results = New-Object System.Collections.Generic.List[object]
        $filter = @{
            LogName   = 'Security'
            Id        = @(4625, 4771, 4776)
            StartTime = $QueryStartTime
        }
        $eventParams = @{
            FilterHashtable = $filter
            ComputerName    = $ComputerName
            MaxEvents       = $QueryMaxEvents
            ErrorAction     = 'Stop'
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

    return ($sidText -match '-(512|518|519|544|548|549|550|551|552|520|1102)$')
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

function Test-UnsupportedOperatingSystem {
    param(
        [string]$OperatingSystem
    )

    if ([string]::IsNullOrWhiteSpace($OperatingSystem)) {
        return $null
    }

    $highRiskPatterns = @(
        'Windows XP',
        'Windows Vista',
        'Windows 7',
        'Windows 8',
        'Windows Server 2003',
        'Windows Server 2008',
        'Windows Server 2012'
    )

    foreach ($pattern in $highRiskPatterns) {
        if ($OperatingSystem -like "*$pattern*") {
            return [pscustomobject]@{
                Severity = 'High'
                Match    = $pattern
            }
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
            Score          = $metadata.RuleWeight
            RiskArea       = $metadata.RiskArea
            RiskAreaName   = $metadata.RiskAreaName
            RuleWeight     = $metadata.RuleWeight
            Category       = $finding.Category
            Title          = $finding.Title
            AffectedObject = $finding.AffectedObject
            ObjectType     = $finding.ObjectType
            EvidenceText   = $finding.EvidenceText
            Recommendation = $finding.Recommendation
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
    $rows.Add('<table><thead><tr><th>ID</th><th>Tezina</th><th>Oblast</th><th>Ozbiljnost</th><th>Kategorija</th><th>Nalaz</th><th>Objekat</th><th>Tip objekta</th><th>Detalji</th><th>Preporuka</th></tr></thead><tbody>') | Out-Null

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
        $html.Add('<table><thead><tr><th>ID</th><th>Tezina</th><th>Oblast</th><th>Kategorija</th><th>Nalaz</th><th>Objekat</th><th>Tip objekta</th><th>Detalji</th><th>Preporuka</th></tr></thead><tbody>') | Out-Null

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
        $html.Add('<table><thead><tr><th>Ozbiljnost</th><th>Tezina</th><th>Oblast</th><th>Nalaz</th><th>Objekat</th><th>Tip objekta</th><th>Preporuka</th></tr></thead><tbody>') | Out-Null

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
details { border: 1px solid #d9e2ec; border-radius: 8px; margin: 10px 0; background: #fff; }
summary { cursor: pointer; padding: 10px 12px; font-weight: 700; color: #102a43; background: #f8fafc; }
summary span { color: #667085; font-weight: 600; margin-left: 6px; }
.company-footer { position: fixed; right: 24px; bottom: 10px; color: #667085; font-size: 11px; font-weight: 600; background: rgba(255,255,255,.9); padding: 3px 0 3px 10px; }
@media print { .chart-row { grid-template-columns: 1fr; } details { page-break-inside: avoid; } .company-footer { position: fixed; right: 18px; bottom: 8px; } }
</style>
'@

    $safeClientName = ConvertTo-HtmlText $Summary.ClientName
    $safeDomain = ConvertTo-HtmlText $Summary.DomainDnsRoot
    $safeGenerated = ConvertTo-HtmlText $Summary.GeneratedAt
    $safeRiskScoreModel = if ($Summary.PSObject.Properties['RiskScoreModel']) { ConvertTo-HtmlText $Summary.RiskScoreModel } else { '' }

    $summaryCards = @"
<h1>AD sigurnosni izvjestaj rizika</h1>
<div class="meta">
Klijent: <strong>$safeClientName</strong><br />
Domena: <strong>$safeDomain</strong><br />
Generisano: <strong>$safeGenerated</strong><br />
Model score-a: <strong>$safeRiskScoreModel</strong>
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
    $riskAreaBars = New-BarListHtml -Items $riskAreaItems -EmptyText 'Nema score podataka po oblasti.'
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

    $body = $summaryCards + $chartSection + '<h2>Nalazi - grupisano po ozbiljnosti</h2>' + $severityGroupedFindings + '<h2>Grupisano po kategoriji</h2>' + $groupedFindings + $warningFragment + '<div class="company-footer">Kodeks d.o.o. Sarajevo | Created by: Adis Hadzovic</div>'
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

    $scriptPath = Get-SelfScriptPath

    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw 'Nije moguce odrediti path skripte.'
    }

    if (-not (Test-Path -LiteralPath $Settings.OutputPath)) {
        New-Item -ItemType Directory -Path $Settings.OutputPath -Force | Out-Null
    }

    $startTime = Get-Date
    $logRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ad-security-risk-gui-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $stdoutPath = Join-Path $logRoot 'stdout.log'
    $stderrPath = Join-Path $logRoot 'stderr.log'

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($part in @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath, '-NoGui', '-GuiChild', '-ClientName', $Settings.ClientName, '-OutputPath', $Settings.OutputPath)) {
        $parts.Add((Quote-NativeArgument ([string]$part))) | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($Settings.Server)) {
        $parts.Add('-Server') | Out-Null
        $parts.Add((Quote-NativeArgument $Settings.Server)) | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($Settings.ConfigPath)) {
        $parts.Add('-ConfigPath') | Out-Null
        $parts.Add((Quote-NativeArgument $Settings.ConfigPath)) | Out-Null
    }

    foreach ($name in @('StaleUserDays', 'StaleComputerDays', 'PrivilegedStaleDays', 'MaxPasswordAgeDays', 'ServiceAccountPasswordAgeDays', 'KrbtgtMaxPasswordAgeDays', 'MinPasswordLength', 'MinPasswordHistory', 'MaxDomainAdmins', 'MaxEnterpriseAdmins', 'FailedLoginLookbackHours', 'FailedLoginMediumThreshold', 'FailedLoginHighThreshold', 'FailedLoginAccountThreshold', 'FailedLoginMaxEventsPerDc', 'FailedLoginQueryTimeoutSeconds')) {
        $parts.Add("-$name") | Out-Null
        $parts.Add([string]$Settings[$name]) | Out-Null
    }

    if ($Settings.AuditPasswordExpiration) {
        $parts.Add('-AuditPasswordExpiration') | Out-Null
    }

    if ($Settings.NoCsv) {
        $parts.Add('-NoCsv') | Out-Null
    }

    if ($Settings.SkipFailedLoginAudit) {
        $parts.Add('-SkipFailedLoginAudit') | Out-Null
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
    }
}

function Read-GuiAnalyzerResult {
    param(
        [hashtable]$Settings,
        [datetime]$StartTime,
        [string]$StdOutPath,
        [string]$StdErrPath
    )

    $reportDir = Get-ChildItem -LiteralPath $Settings.OutputPath -Directory |
        Where-Object {
            $_.LastWriteTime -ge $StartTime.AddSeconds(-10) -and
            $_.Name -ne '_gui-child-logs' -and
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
        [hashtable]$Cards
    )

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

    foreach ($finding in @($filtered | Sort-Object -Property Score -Descending)) {
        $metadata = Get-FindingEffectiveRuleMetadata -Finding $finding
        $rowIndex = $Grid.Rows.Add(
            $finding.Id,
            $metadata.RuleWeight,
            $metadata.RiskAreaName,
            (Get-SeverityLabel -Severity $finding.Severity),
            $finding.Category,
            $finding.Title,
            $finding.AffectedObject,
            $finding.ObjectType
        )
        $Grid.Rows[$rowIndex].Tag = $finding

        switch ($finding.Severity) {
            'Critical' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(69, 10, 10) }
            'High' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(67, 20, 7) }
            'Medium' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(63, 48, 11) }
            'Low' { $Grid.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(23, 37, 84) }
        }
        $Grid.Rows[$rowIndex].DefaultCellStyle.ForeColor = $script:GuiColors.Text
        $Grid.Rows[$rowIndex].DefaultCellStyle.SelectionBackColor = $script:GuiColors.Accent
        $Grid.Rows[$rowIndex].DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    }

    $DetailBox.Text = "Prikazano nalaza: $($Grid.Rows.Count)"
}

function Update-GuiFilterTree {
    param(
        [System.Windows.Forms.TreeView]$Tree,
        [object[]]$Findings
    )

    $Tree.Nodes.Clear()
    $allNode = $Tree.Nodes.Add('Svi nalazi')
    $allNode.Tag = @{ Mode = 'All'; Value = '' }

    $severityRoot = $Tree.Nodes.Add('Ozbiljnost')
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $count = @($Findings | Where-Object { $_.Severity -eq $severity }).Count
        $node = $severityRoot.Nodes.Add("$((Get-SeverityLabel -Severity $severity)) ($count)")
        $node.Tag = @{ Mode = 'Severity'; Value = $severity }
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
    $form.Text = 'AD Security Risk Analyzer'
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
    $title.Text = 'AD Security Risk Analyzer'
    $title.ForeColor = [System.Drawing.Color]::White
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 20, [System.Drawing.FontStyle]::Bold)
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(18, 14)
    $header.Controls.Add($title)

    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = 'Read-only AD risk scan, izvjestaji, grupisanje i export'
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
    $configGroup.Size = New-Object System.Drawing.Size(398, 414)
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
    $btnStart.Text = 'Pokreni'
    $btnStart.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
    $btnStart.Location = New-Object System.Drawing.Point(246, 342)
    $btnStart.Size = New-Object System.Drawing.Size(126, 38)
    Set-GuiButtonStyle -Button $btnStart -Primary
    $configGroup.Controls.Add($btnStart)

    $baselineNote = New-Object System.Windows.Forms.Label
    $baselineNote.Text = 'Default pragovi prate NIST/Microsoft/CIS. Mijenjati samo za odobrenu politiku.'
    $baselineNote.Location = New-Object System.Drawing.Point(14, 384)
    $baselineNote.Size = New-Object System.Drawing.Size(360, 22)
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
    }

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
    $tree.Location = New-Object System.Drawing.Point(16, 514)
    $tree.Size = New-Object System.Drawing.Size(398, 265)
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
    [void]$grid.Columns.Add('Score', 'Tezina')
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

        $detailBox.Text = @"
ID: $($finding.Id)
Tezina: $($metadata.RuleWeight)
Oblast: $($metadata.RiskAreaName)
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
        $saveDialog.FileName = "AD-Security-$($script:GuiState.Summary.ClientName).html"
        if ($saveDialog.ShowDialog() -eq 'OK') {
            Write-HtmlReport -Summary $script:GuiState.Summary -Findings $script:GuiState.Findings -Warnings $script:GuiState.Warnings -Path $saveDialog.FileName
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
        $saveDialog.FileName = "AD-Security-$($script:GuiState.Summary.ClientName).pdf"
        if ($saveDialog.ShowDialog() -eq 'OK') {
            try {
                $tempHtml = Join-Path ([System.IO.Path]::GetTempPath()) ("ad-security-risk-{0}.html" -f ([guid]::NewGuid().ToString('N')))
                Write-HtmlReport -Summary $script:GuiState.Summary -Findings $script:GuiState.Findings -Warnings $script:GuiState.Warnings -Path $tempHtml
                Convert-HtmlReportToPdf -HtmlPath $tempHtml -PdfPath $saveDialog.FileName
                Remove-Item -LiteralPath $tempHtml -ErrorAction SilentlyContinue
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

        Update-GuiSummary -Summary $result.Summary -Cards $cards
        Update-GuiFindingsGrid -Grid $grid -DetailBox $detailBox -Findings $script:GuiState.Findings -Mode 'All' -Value ''
        Update-GuiFilterTree -Tree $tree -Findings $script:GuiState.Findings

        $btnSaveHtml.Enabled = $true
        $btnSavePdf.Enabled = $true
        $btnOpenFolder.Enabled = $true
        $btnClearFilter.Enabled = $true
        Add-GuiLog -TextBox $logBox -Message "Gotovo. Report folder: $($result.ReportPath)"
        $script:GuiState.ActiveRun = $null
    })

    $btnStart.Add_Click({
        if ($null -ne $script:GuiState.ActiveRun -and $null -ne $script:GuiState.ActiveRun.Process -and -not $script:GuiState.ActiveRun.Process.HasExited) {
            return
        }

        if ([string]::IsNullOrWhiteSpace($txtClient.Text)) {
            [System.Windows.Forms.MessageBox]::Show('Polje Domena / klijent je obavezno.', 'Nedostaje vrijednost', 'OK', 'Warning') | Out-Null
            return
        }

        $settings = @{
            ClientName = $txtClient.Text.Trim()
            Server = $txtServer.Text.Trim()
            OutputPath = $txtOutput.Text.Trim()
            ConfigPath = $txtConfig.Text.Trim()
            StaleUserDays = [int]$numericBoxes['StaleUserDays'].Value
            StaleComputerDays = [int]$numericBoxes['StaleComputerDays'].Value
            PrivilegedStaleDays = [int]$numericBoxes['PrivilegedStaleDays'].Value
            MaxPasswordAgeDays = $MaxPasswordAgeDays
            ServiceAccountPasswordAgeDays = $ServiceAccountPasswordAgeDays
            KrbtgtMaxPasswordAgeDays = [int]$numericBoxes['KrbtgtMaxPasswordAgeDays'].Value
            MinPasswordLength = [int]$numericBoxes['MinPasswordLength'].Value
            MinPasswordHistory = $MinPasswordHistory
            MaxDomainAdmins = $MaxDomainAdmins
            MaxEnterpriseAdmins = $MaxEnterpriseAdmins
            FailedLoginLookbackHours = $FailedLoginLookbackHours
            FailedLoginMediumThreshold = $FailedLoginMediumThreshold
            FailedLoginHighThreshold = $FailedLoginHighThreshold
            FailedLoginAccountThreshold = $FailedLoginAccountThreshold
            FailedLoginMaxEventsPerDc = $FailedLoginMaxEventsPerDc
            FailedLoginQueryTimeoutSeconds = $FailedLoginQueryTimeoutSeconds
            SkipFailedLoginAudit = [bool]$SkipFailedLoginAudit
            AuditPasswordExpiration = [bool]$chkAuditExpiration.Checked
            NoCsv = [bool]$chkNoCsv.Checked
        }

        $btnStart.Enabled = $false
        $btnSaveHtml.Enabled = $false
        $btnSavePdf.Enabled = $false
        $btnOpenFolder.Enabled = $false
        $btnClearFilter.Enabled = $false
        $grid.Rows.Clear()
        $tree.Nodes.Clear()
        $detailBox.Text = ''
        Add-GuiLog -TextBox $logBox -Message "Pokrecem scan za $($settings.ClientName)..."
        try {
            $script:GuiState.ActiveRun = Start-GuiAnalyzerProcess -Settings $settings
            Add-GuiLog -TextBox $logBox -Message "Analyzer proces pokrenut. PID: $($script:GuiState.ActiveRun.Process.Id)"
            $timer.Start()
        }
        catch {
            $btnStart.Enabled = $true
            Add-GuiLog -TextBox $logBox -Message "Greska: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Analyzer nije uspio', 'OK', 'Error') | Out-Null
        }
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
        Title="AD Security Risk Analyzer"
        Width="1180" Height="740" MinWidth="820" MinHeight="560"
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
          <TextBlock Text="AD Security Risk Analyzer" FontSize="28" FontWeight="SemiBold"/>
          <TextBlock Text="Read-only AD risk scan, izvjestaji, grupisanje i export" Foreground="{StaticResource Muted}" Margin="1,3,0,0"/>
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

      <ScrollViewer Grid.Column="0" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
        <Border Background="{StaticResource Panel}" CornerRadius="16" Padding="16">
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

            <Button x:Name="StartButton" Content="Pokreni" Background="{StaticResource Accent}" FontWeight="SemiBold" FontSize="15" Margin="0,16,0,0"/>
          </StackPanel>
        </Border>
      </ScrollViewer>

      <GridSplitter Grid.Column="1" Width="4" HorizontalAlignment="Center" Background="#1E293B" ShowsPreview="True"/>

      <Grid Grid.Column="2">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="132"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="{StaticResource Panel}" CornerRadius="16" Padding="14">
          <StackPanel>
            <TextBlock Text="Pregled" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,10"/>
            <UniformGrid Columns="5" Rows="2">
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="RiskValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock Text="Rizik" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="TotalValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock Text="Ukupno" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="CriticalValue" Text="-" FontSize="22" FontWeight="SemiBold" Foreground="#F87171"/><TextBlock Text="Kriticno" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="HighValue" Text="-" FontSize="22" FontWeight="SemiBold" Foreground="#FB7185"/><TextBlock Text="Visoko" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="MediumValue" Text="-" FontSize="22" FontWeight="SemiBold" Foreground="#FBBF24"/><TextBlock Text="Srednje" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="LowValue" Text="-" FontSize="22" FontWeight="SemiBold" Foreground="#60A5FA"/><TextBlock Text="Nisko" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="InfoValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock Text="Info" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="UsersValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock Text="Useri" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="PcsValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock Text="PCs" Foreground="{StaticResource Muted}"/></StackPanel></Border>
              <Border Background="#0B1220" CornerRadius="12" Padding="10" Margin="4"><StackPanel><TextBlock x:Name="DcsValue" Text="-" FontSize="22" FontWeight="SemiBold"/><TextBlock Text="DCs" Foreground="{StaticResource Muted}"/></StackPanel></Border>
            </UniformGrid>
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
                <DataGridTextColumn Header="Tezina" Binding="{Binding Score}" Width="62"/>
                <DataGridTextColumn Header="Oblast" Binding="{Binding RiskAreaName}" Width="135"/>
                <DataGridTextColumn Header="Ozbiljnost" Binding="{Binding SeverityLabel}" Width="92"/>
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
    $startButton = Get-WpfControl 'StartButton'
    $saveHtmlButton = Get-WpfControl 'SaveHtmlButton'
    $savePdfButton = Get-WpfControl 'SavePdfButton'
    $openFolderButton = Get-WpfControl 'OpenFolderButton'
    $clearFilterButton = Get-WpfControl 'ClearFilterButton'
    $filterTree = Get-WpfControl 'FilterTree'
    $findingsGrid = Get-WpfControl 'FindingsGrid'
    $detailText = Get-WpfControl 'DetailText'
    $logText = Get-WpfControl 'LogText'

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
        param([bool]$Enabled)
        $saveHtmlButton.IsEnabled = $Enabled
        $savePdfButton.IsEnabled = $Enabled
        $openFolderButton.IsEnabled = $Enabled
        $clearFilterButton.IsEnabled = $Enabled
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
            $rows.Add([pscustomobject]@{
                Id = $finding.Id
                Score = $metadata.RuleWeight
                RiskAreaName = $metadata.RiskAreaName
                SeverityLabel = Get-SeverityLabel -Severity $finding.Severity
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
        $totalCount = if ($null -ne $Summary -and $Summary.PSObject.Properties['TotalFindings']) { [int]$Summary.TotalFindings } else { $allFindings.Count }
        $filterTree.Items.Add((New-WpfTreeItem -Header "Svi nalazi ($totalCount)" -Mode 'All' -Value '')) | Out-Null

        $severityRoot = New-Object System.Windows.Controls.TreeViewItem
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
        $detailText.Text = @"
ID: $($finding.Id)
Tezina: $($metadata.RuleWeight)
Oblast: $($metadata.RiskAreaName)
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
        $saveDialog.FileName = "AD-Security-$($script:GuiState.Summary.ClientName).html"
        if ($saveDialog.ShowDialog() -eq 'OK') {
            Write-HtmlReport -Summary $script:GuiState.Summary -Findings $script:GuiState.Findings -Warnings $script:GuiState.Warnings -Path $saveDialog.FileName
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
        $saveDialog.FileName = "AD-Security-$($script:GuiState.Summary.ClientName).pdf"
        if ($saveDialog.ShowDialog() -eq 'OK') {
            try {
                $tempHtml = Join-Path ([System.IO.Path]::GetTempPath()) ("ad-security-risk-{0}.html" -f ([guid]::NewGuid().ToString('N')))
                Write-HtmlReport -Summary $script:GuiState.Summary -Findings $script:GuiState.Findings -Warnings $script:GuiState.Warnings -Path $tempHtml
                Convert-HtmlReportToPdf -HtmlPath $tempHtml -PdfPath $saveDialog.FileName
                Remove-Item -LiteralPath $tempHtml -ErrorAction SilentlyContinue
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

        $startButton.IsEnabled = $true
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
            Set-WpfActionsEnabled -Enabled $true
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

    $startButton.Add_Click({
        if ($null -ne $script:GuiState.ActiveRun -and $null -ne $script:GuiState.ActiveRun.Process -and -not $script:GuiState.ActiveRun.Process.HasExited) {
            return
        }

        if ([string]::IsNullOrWhiteSpace($clientText.Text)) {
            [System.Windows.MessageBox]::Show('Polje Domena / klijent je obavezno.', 'Nedostaje vrijednost', 'OK', 'Warning') | Out-Null
            return
        }

        try {
            $settings = @{
                ClientName = $clientText.Text.Trim()
                Server = $serverText.Text.Trim()
                OutputPath = $outputText.Text.Trim()
                ConfigPath = $configText.Text.Trim()
                StaleUserDays = Get-WpfIntValue -TextBox $staleUsersText -Name 'Neaktivni useri'
                StaleComputerDays = Get-WpfIntValue -TextBox $staleComputersText -Name 'Neaktivni PC-evi'
                PrivilegedStaleDays = Get-WpfIntValue -TextBox $privStaleText -Name 'Priv. nalozi'
                MaxPasswordAgeDays = $MaxPasswordAgeDays
                ServiceAccountPasswordAgeDays = $ServiceAccountPasswordAgeDays
                KrbtgtMaxPasswordAgeDays = Get-WpfIntValue -TextBox $krbtgtAgeText -Name 'krbtgt starost'
                MinPasswordLength = Get-WpfIntValue -TextBox $minPasswordText -Name 'Min lozinka'
                MinPasswordHistory = $MinPasswordHistory
                MaxDomainAdmins = $MaxDomainAdmins
                MaxEnterpriseAdmins = $MaxEnterpriseAdmins
                FailedLoginLookbackHours = $FailedLoginLookbackHours
                FailedLoginMediumThreshold = $FailedLoginMediumThreshold
                FailedLoginHighThreshold = $FailedLoginHighThreshold
                FailedLoginAccountThreshold = $FailedLoginAccountThreshold
                FailedLoginMaxEventsPerDc = $FailedLoginMaxEventsPerDc
                FailedLoginQueryTimeoutSeconds = $FailedLoginQueryTimeoutSeconds
                SkipFailedLoginAudit = [bool]$SkipFailedLoginAudit
                AuditPasswordExpiration = [bool]$auditCheck.IsChecked
                NoCsv = [bool]$noCsvCheck.IsChecked
            }

            $startButton.IsEnabled = $false
            Set-WpfActionsEnabled -Enabled $false
            $findingsGrid.ItemsSource = $null
            $filterTree.Items.Clear()
            $detailText.Text = ''
            Add-WpfLog -Message "Pokrecem scan za $($settings.ClientName)..."
            $script:GuiState.ActiveRun = Start-GuiAnalyzerProcess -Settings $settings
            Add-WpfLog -Message "Analyzer proces pokrenut. PID: $($script:GuiState.ActiveRun.Process.Id)"
            $timer.Start()
        }
        catch {
            $startButton.IsEnabled = $true
            Add-WpfLog -Message "Greska: $($_.Exception.Message)"
            [System.Windows.MessageBox]::Show($_.Exception.Message, 'Analyzer nije uspio', 'OK', 'Error') | Out-Null
        }
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
    $fineGrainedPasswordPolicies = @(Get-ADFineGrainedPasswordPolicy @script:AdParams -Filter *)
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
    'TrustedForDelegation',
    'TrustedToAuthForDelegation',
    'whenCreated'
)

$users = @(Get-ADUser @script:AdParams -Filter * -Properties $userProperties)
$computers = @(Get-ADComputer @script:AdParams -Filter * -Properties $computerProperties)
$domainControllers = @(Get-ADDomainController @script:AdParams -Filter *)

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
    @{ Name = 'DnsAdmins'; Sid = "$domainSid-1102"; Category = 'DnsPrivileged'; Severity = 'High' },
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
        ActiveMembers          = @($activeMembers.ToArray())
        DisabledUserMembers    = @($disabledUserMembers.ToArray())
        MemberText             = @($members | ForEach-Object { Get-PrincipalDisplayName -Principal $_ -NetBIOSName $netBIOSName })
        ActiveMemberText       = @($activeMembers.ToArray() | ForEach-Object { Get-PrincipalDisplayName -Principal $_ -NetBIOSName $netBIOSName })
        DisabledUserMemberText = @($disabledUserMembers.ToArray() | ForEach-Object { Get-PrincipalDisplayName -Principal $_ -NetBIOSName $netBIOSName })
    }) | Out-Null

    if ($definition.Category -in @('CorePrivileged', 'BuiltInPrivileged', 'GpoPrivileged', 'DnsPrivileged')) {
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

$privilegedUsers = @($users | Where-Object { $privilegedUserDns.ContainsKey($_.DistinguishedName) })

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
        if ($fgpp.MinPasswordLength -lt $MinPasswordLength -or $fgpp.LockoutThreshold -eq 0) {
            Add-Finding -Id 'AD-POLICY-006' -Severity 'Medium' -Category 'Politika lozinki' -Title 'Detaljna politika lozinki je slabija od referentne vrijednosti' -AffectedObject $fgpp.Name -ObjectType 'Detaljna politika lozinki' -Evidence @{
                MinPasswordLength = $fgpp.MinPasswordLength
                ComplexityEnabled = $fgpp.ComplexityEnabled
                LockoutThreshold = $fgpp.LockoutThreshold
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
        foreach ($member in $groupInfo.Members) {
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
        $privilegedStaleSeverity = if ($isCorePrivileged) { 'High' } else { 'Medium' }
        Add-Finding -Id 'AD-PRIV-005' -Severity $privilegedStaleSeverity -Category 'Privilegovani pristup' -Title 'Privilegovani nalog je zastario ili nema skorasnji logon' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            Enabled = $user.Enabled
            LastLogonDate = $user.LastLogonDate
            DaysSinceLastLogon = $lastLogonDays
            BaselineDays = $PrivilegedStaleDays
            PrivilegedGroups = $privilegedGroups
            PrivilegedCategories = $privilegedCategories
            SeverityReason = if ($privilegedStaleSeverity -eq 'High') { 'Nalog je omogucen i ima Tier-0/core privilegije.' } else { 'Nalog je omogucen i privilegovan, ali nije u najvisim core admin grupama.' }
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
    Add-CollectionWarning -Message 'Nije moguce provjeriti ugradjeni Guest nalog.' -Detail $_.Exception.Message
}

try {
    $krbtgt = Get-ADUser @script:AdParams -Identity 'krbtgt' -Properties PasswordLastSet, Enabled -ErrorAction Stop
    $krbtgtPasswordAgeDays = Get-DaysSince -Date $krbtgt.PasswordLastSet
    if ($null -eq $krbtgtPasswordAgeDays -or $krbtgtPasswordAgeDays -gt $KrbtgtMaxPasswordAgeDays) {
        $krbtgtSeverity = if ($null -eq $krbtgtPasswordAgeDays -or $krbtgtPasswordAgeDays -gt 730) { 'Medium' } else { 'Low' }
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
        $asRepSeverity = if ($userIsCorePrivileged) { 'Critical' } else { 'High' }
        Add-Finding -Id 'AD-USER-006' -Severity $asRepSeverity -Category 'Putanja napada' -Title 'Detektovan AS-REP roastable nalog' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            DoesNotRequirePreAuth = $user.DoesNotRequirePreAuth
            IsPrivileged = $isPrivileged
            PrivilegedGroups = $userPrivilegedGroups
            PrivilegedCategories = $userPrivilegedCategories
            SeverityReason = if ($asRepSeverity -eq 'Critical') { 'Core privilegovani nalog je AS-REP roastable.' } else { 'Omogucen nalog je AS-REP roastable.' }
        } -Recommendation 'Ukljuciti Kerberos pre-authentication za ovaj nalog i rotirati lozinku.'
    }

    if ($user.Enabled -and $user.ServicePrincipalName -and $user.ServicePrincipalName.Count -gt 0) {
        $severity = 'Medium'
        if ($userIsCorePrivileged -and ($user.PasswordNeverExpires -or $null -eq $passwordAgeDays -or $passwordAgeDays -gt $ServiceAccountPasswordAgeDays)) {
            $severity = 'Critical'
        }
        elseif ($isPrivileged -or ($null -ne $passwordAgeDays -and $passwordAgeDays -gt $ServiceAccountPasswordAgeDays)) {
            $severity = 'High'
        }

        Add-Finding -Id 'AD-USER-007' -Severity $severity -Category 'Putanja napada' -Title 'Kerberoastable korisnicki nalog ima SPN zapise' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            ServicePrincipalNames = @($user.ServicePrincipalName)
            PasswordLastSet = $user.PasswordLastSet
            PasswordAgeDays = $passwordAgeDays
            PasswordNeverExpires = $user.PasswordNeverExpires
            IsPrivileged = $isPrivileged
            PrivilegedGroups = $userPrivilegedGroups
            PrivilegedCategories = $userPrivilegedCategories
            SeverityReason = if ($severity -eq 'Critical') { 'Core privilegovani korisnicki servisni nalog ima SPN i staru/neogranicenu lozinku.' } elseif ($severity -eq 'High') { 'Privilegovani ili stari korisnicki servisni nalog ima SPN.' } else { 'Korisnicki servisni nalog ima SPN, ali nije poznato core privilegovan i lozinka nije preko service-account praga.' }
        } -Recommendation 'Koristiti gMSA gdje je moguce, ukloniti nepotrebne SPN zapise, rotirati lozinku i izbjegavati privilegovane servisne naloge.'
    }

    if ($user.Enabled -and $user.TrustedForDelegation) {
        Add-Finding -Id 'AD-USER-008' -Severity 'Critical' -Category 'Putanja napada' -Title 'Korisnicki nalog je trusted for unconstrained delegation' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            TrustedForDelegation = $user.TrustedForDelegation
        } -Recommendation 'Ukloniti unconstrained delegation sa korisnickih naloga. Ako je delegacija potrebna, koristiti constrained delegation po principu najmanjih privilegija.'
    }

    if ($user.Enabled -and $user.TrustedToAuthForDelegation) {
        $protocolTransitionSeverity = if ($userIsCorePrivileged) { 'Critical' } else { 'High' }
        Add-Finding -Id 'AD-USER-009' -Severity $protocolTransitionSeverity -Category 'Putanja napada' -Title 'Korisnicki nalog ima protocol transition delegation' -AffectedObject $principalName -ObjectType 'Korisnik' -Evidence @{
            TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
            IsPrivileged = $isPrivileged
            PrivilegedGroups = $userPrivilegedGroups
            PrivilegedCategories = $userPrivilegedCategories
            SeverityReason = if ($protocolTransitionSeverity -eq 'Critical') { 'Core privilegovani nalog ima protocol transition delegation.' } else { 'Omogucen korisnicki nalog ima protocol transition delegation.' }
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
        Add-Finding -Id 'AD-COMP-003' -Severity $osRisk.Severity -Category 'Operativni sistem' -Title 'Detektovan nepodrzan ili zastario Windows operativni sistem' -AffectedObject $computerName -ObjectType 'Racunar' -Evidence @{
            Enabled = $computer.Enabled
            OperatingSystem = $computer.OperatingSystem
            OperatingSystemVersion = $computer.OperatingSystemVersion
            MatchedPattern = $osRisk.Match
        } -Recommendation 'Planirati upgrade, zamjenu, izolaciju ili dokumentovanu produzenu podrsku. Prioritet dati serverima i privilegovanim radnim stanicama.'
    }

    if ($computer.Enabled -and $computer.TrustedForDelegation -and -not $isDomainController) {
        Add-Finding -Id 'AD-COMP-004' -Severity 'High' -Category 'Putanja napada' -Title 'Racunar je trusted for unconstrained delegation' -AffectedObject $computerName -ObjectType 'Racunar' -Evidence @{
            TrustedForDelegation = $computer.TrustedForDelegation
            IsDomainController = $isDomainController
        } -Recommendation 'Ukloniti unconstrained delegation. Koristiti constrained delegation samo gdje je potrebna i dokumentovati poslovni razlog.'
    }

    if ($computer.Enabled -and $computer.TrustedToAuthForDelegation) {
        Add-Finding -Id 'AD-COMP-005' -Severity 'Medium' -Category 'Putanja napada' -Title 'Racunar ima protocol transition delegation' -AffectedObject $computerName -ObjectType 'Racunar' -Evidence @{
            TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
        } -Recommendation 'Validirati constrained delegation targete i osigurati da je server hardenovan i nadgledan.'
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

$riskScoreAnalysis = Get-RiskScoreAnalysis -Findings $script:Findings
$riskScore = [int]$riskScoreAnalysis.Score

$summary = [pscustomobject][ordered]@{
    ClientName                  = $ClientName
    Author                      = 'Adis Hadzovic'
    DomainDnsRoot               = $domain.DNSRoot
    Forest                      = $forest.Name
    GeneratedAt                 = (Get-Date).ToString('s')
    RiskScore                   = $riskScore
    RiskScoreModel              = $riskScoreAnalysis.Model
    RiskScoreDetails            = $riskScoreAnalysis
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
        Write-HtmlReport -Summary $summary -Findings $sortedFindings -Warnings @($script:CollectionWarnings) -Path (Join-Path $reportRoot 'report.html')
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
