# AD Security Risk Analyzer

Read-only Active Directory sigurnosni skener.

Cilj alata je da napravi koristan prvi sigurnosni pregled on-prem AD DS domene bez bilo kakvih izmjena u domeni. Namijenjen je za onboarding procjene, periodicne provjere te pripreme izvjestaja.

## Sta Provjerava

- Politiku lozinki na domeni i detaljne politike lozinki
- Clanstvo u privilegovanim grupama i higijenu privilegovanih naloga
- Stare admin naloge, stare omogucene korisnike i stare racunarske naloge
- Starost `krbtgt` lozinke
- Status ugradjenog Guest naloga
- Naloge sa eksplicitnim `PasswordNeverExpires`
- Kerberoastable naloge sa SPN zapisima
- AS-REP roastable naloge
- Unconstrained delegation i protocol transition delegation
- DES-only i reverzibilnu enkripciju lozinki
- Zastarjele `adminCount=1` korisnike
- `SIDHistory`
- Nepodrzane ili zastarjele Windows operativne sisteme
- Starost lozinke racunarskog naloga
- Legacy/compliance audit starosti korisnickih lozinki kada se koristi `-AuditPasswordExpiration`

## Gdje i kako se pokrece

Preporucene opcije:

1. **Domain Controller**  
   Najjednostavnije za rucno pokretanje, jer AD PowerShell modul obicno vec postoji. Skripta je read-only, ali izvjestaje treba zapisati na sigurnu lokaciju. Run as Administrator.

2. **Dedicated management / jump server**  
   Najbolja opcija za redovno koristenje. Server treba biti pridruzen na domenu, imati RSAT Active Directory modul i mrezni pristup domenskom kontroleru.


## Zahtjevi

- Windows PowerShell 5.1 ili PowerShell 7+
- RSAT Active Directory PowerShell modul, osim ako se pokrece direktno na DC-u gdje je modul vec prisutan
- Domenski nalog sa read pristupom klijentskoj AD domeni
- Mrezna konekcija prema domenskom kontroleru


Ako se koristi management / jump server i RSAT nije instaliran:

```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

## Brzi Start

Default pokretanje otvara GUI:

```powershell
.\Invoke-ADSecurityRiskAnalyzer.ps1
```

GUI automatski pokusava pronaci domenu i domain controller. Polja se mogu urediti, tako da je moguce promijeniti domain/client ime, DC, output folder i config fajl prije klika na **Start**.

Pokretanje direktno na Domain Controlleru:

```powershell
.\Invoke-ADSecurityRiskAnalyzer.ps1
```

CLI / RMM pokretanje bez GUI-a:

```powershell
.\Invoke-ADSecurityRiskAnalyzer.ps1 -NoGui -ClientName "Klijent A" -Server "dc01.client.local" -Verbose
```

Pokretanje sa drugim kredencijalima u CLI modu:

```powershell
$cred = Get-Credential
.\Invoke-ADSecurityRiskAnalyzer.ps1 -NoGui -ClientName "Klijent A" -Server "dc01.client.local" -Credential $cred
```

Pokretanje sa klijentskim referentnim konfiguracijskim fajlom u CLI modu:

```powershell
.\Invoke-ADSecurityRiskAnalyzer.ps1 -NoGui -ClientName "Klijent A" -ConfigPath .\config.klijent-a.json
```

Izvjestaji se zapisuju u:

```text
.\reports\<klijent>-yyyyMMdd-HHmmss\
```

Svako pokretanje generise:

- `summary.json`
- `findings.json`
- `findings.csv`
- `collection-warnings.json`

## GUI Funkcije

- Domain/client polje
- Domain controller, output folder i config path
- **Start** dugme za pokretanje skena
- Summary kartice nakon zavrsetka: risk, total, severity counts, users, PCs, DCs
- Klikabilno stablo za filtere po severity, category, object type i konkretnom objektu/uredjaju
- Tabela nalaza sa klikom na red za detalje i preporuku
- **Save as HTML** export sa donut chartom, category barovima i grupisanim nalazima (preporučeno)
- **Save as PDF** export sa istim chartovima
- **Open report folder** dugme

PDF export koristi Microsoft Edge ili Google Chrome u headless modu. Ako nijedan nije instaliran na serveru, nece raditi. HTML export ce i dalje raditi.

## Standardni Baseline Pragovi

Alat po defaultu koristi praktican baseline iz NIST, Microsoft Defender for Identity i CIS preporuka. GUI prikazuje ove vrijednosti radi transparentnosti, ali ih treba mijenjati samo ako klijent ima odobrenu sigurnosnu politiku ili compliance izuzetak.

Default vrijednosti:

- Stale users: 90 dana, po Microsoft Defender for Identity stale AD account procjeni.
- Stale computers: 45 dana, kao strozi CIS-style dormant account prag gdje je primjenjivo.
- Privileged stale/sensitive accounts: 180 dana, po Microsoft Defender for Identity dormant sensitive entity procjeni.
- `krbtgt` password age: 180 dana, po Microsoft Defender for Identity procjeni.
- Minimalna duzina lozinke: 15 karaktera, strozi NIST SP 800-63B Rev. 4 single-factor baseline. CIS i dalje navodi 14 kao pragmatican minimum za naloge bez MFA.

Ako moras napraviti klijentski izuzetak, osjetljivost skenera mozes podesiti parametrima:

```powershell
.\Invoke-ADSecurityRiskAnalyzer.ps1 `
  -ClientName "Klijent A" `
  -StaleUserDays 120 `
  -StaleComputerDays 60 `
  -PrivilegedStaleDays 180 `
  -ServiceAccountPasswordAgeDays 180 `
  -KrbtgtMaxPasswordAgeDays 180 `
  -MinPasswordLength 15 `
  -MinPasswordHistory 24 `
  -MaxDomainAdmins 3
```

Po defaultu alat ne tretira "lozinka nikad ne istice" kao automatski sigurnosni problem, jer moderne NIST i Microsoft smjernice ne preporucuju arbitrarni periodican istek lozinki. Fokus je na dugim jedinstvenim lozinkama/passphrase, blocklisti cestih i kompromitovanih lozinki, lockout/rate limiting, monitoringu i promjeni lozinke pri sumnji na kompromitaciju.

Ako za nekog klijenta moras raditi legacy/compliance provjeru starosti lozinki, ukljuci:

```powershell
.\Invoke-ADSecurityRiskAnalyzer.ps1 `
  -ClientName "Klijent A" `
  -AuditPasswordExpiration `
  -MaxPasswordAgeDays 365
```

## Referentna Konfiguracija

Kopiraj `config.example.json` u klijentski fajl i upisi odobrene clanove privilegovanih grupa:

```powershell
Copy-Item .\config.example.json .\config.klijent-a.json
```

Referentna konfiguracija podrzava wildcard matching:

```json
{
  "AllowedPrivilegedGroupMembers": {
    "Domain Admins": [
      "CLIENTA\\adm-*",
      "CLIENTA\\Administrator"
    ]
  }
}
```

Ako grupa ima referentne unose, svaki clan koji se ne poklapa sa njima bice prijavljen kao neocekivan privilegovani clan.


## Primjer Scheduled Task Akcije

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Tools\ad-security-risk-analyzer\Invoke-ADSecurityRiskAnalyzer.ps1" -NoGui -ClientName "Klijent A" -OutputPath "C:\Reports\ADSecurity"
```

## Napomene

- Skener je read-only.
- Ne radi penetracijsko testiranje.
- `LastLogonDate` je repliciran, ali priblizan podatak. Dobar je za hygiene reporting, ali nije precizan forenzicki izvor.
- Windows 10 se prijavljuje kao srednji rizik jer je zastario ili nepodrzan u mnogim okruzenjima od 2026. godine. Filtriraj ili prilagodi ovaj nalaz ako klijent ima produzenu podrsku.
