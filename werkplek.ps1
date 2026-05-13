#Requires -Version 5.1
<#
.SYNOPSIS
    Werkplekconcept Pentest - Automatische Controles
    Gebaseerd op OneXillium Werkplekconcept Pentest Guideline V1.0

.DESCRIPTION
    Dit script voert automatisch de technische checks uit die in de
    werkplekconcept checklist staan. Per check wordt het resultaat
    (PASS / WARN / FAIL / INFO) getoond inclusief de ruwe output.

    Geen credential dumping, geen exploitatie, geen wijzigingen aan het systeem.

.NOTES
    Draaien als de reguliere eindgebruiker (geen admin nodig).
    Sommige checks tonen meer detail met admin rechten.
#>

# ─────────────────────────────────────────────────────────────────────
#  OUTPUT HELPERS
# ─────────────────────────────────────────────────────────────────────
$script:AllResults = [System.Collections.Generic.List[PSObject]]::new()

function Write-SectionHeader([string]$Title) {
    $pad = "=" * 70
    Write-Host "`n$pad" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$pad" -ForegroundColor Cyan
}

function Write-CheckHeader([string]$ID, [string]$Name) {
    Write-Host ("`n  [{0}] {1}" -f $ID, $Name) -ForegroundColor Yellow
    Write-Host ("  " + "-" * 60) -ForegroundColor DarkGray
}

function Write-Pass([string]$Msg)  { Write-Host "  [PASS] $Msg" -ForegroundColor Green   }
function Write-Fail([string]$Msg)  { Write-Host "  [FAIL] $Msg" -ForegroundColor Red     }
function Write-Warn([string]$Msg)  { Write-Host "  [WARN] $Msg" -ForegroundColor Magenta }
function Write-Info([string]$Msg)  { Write-Host "  [INFO] $Msg" -ForegroundColor White   }
function Write-Data([string]$Msg)  { Write-Host "        $Msg"  -ForegroundColor Gray    }

function Save-Result([string]$ID, [string]$Name, [string]$Status, [string]$Detail) {
    $script:AllResults.Add([PSCustomObject]@{
        ID     = $ID
        Name   = $Name
        Status = $Status
        Detail = $Detail
    })
}

function IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [System.Security.Principal.WindowsPrincipal]$id
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ─────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host @"

  ╔══════════════════════════════════════════════════════════════════╗
  ║   Werkplekconcept Pentest - Automatische Controles               ║
  ║   OneXillium Werkplekconcept Pentest Guideline V1.0              ║
  ╚══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "  Computer  : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Gebruiker  : $env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
Write-Host "  Datum/Tijd : $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')" -ForegroundColor White
Write-Host "  Admin      : $(if (IsAdmin) { 'JA' } else { 'Nee (beperkte output op sommige checks)' })" -ForegroundColor $(if (IsAdmin) { 'Green' } else { 'Yellow' })
Write-Host ""


# ══════════════════════════════════════════════════════════════════════
#  SECTIE: SYSTEM SECURITY
# ══════════════════════════════════════════════════════════════════════
Write-SectionHeader "SYSTEM SECURITY"

# ─── RT-SS-01 - Local Administrator Rights ───────────────────────────
Write-CheckHeader "RT-SS-01" "Local Administrator Rights"
try {
    $isAdmin = IsAdmin

    # Vertaal elke SID individueel - sla over als vertaling mislukt (bijv. offline domeingroepen)
    $groups = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups |
              ForEach-Object {
                  try   { $_.Translate([System.Security.Principal.NTAccount]).Value }
                  catch { $_.Value }   # fallback: toon de SID als naam niet oplosbaar is
              }

    $inAdminGroup = $groups -match "Administrators"

    if ($isAdmin) {
        Write-Fail "Huidige gebruiker draait MET administrator rechten (elevated process)."
        Save-Result "RT-SS-01" "Local Admin Rights" "FAIL" "Elevated admin sessie actief"
    } elseif ($inAdminGroup) {
        Write-Warn "Gebruiker zit in de lokale Administrators groep, maar process is niet elevated."
        Write-Info "UAC kan escalatie nog tegenhouden; controleer UAC niveau (zie RT-SM-02)."
        Save-Result "RT-SS-01" "Local Admin Rights" "WARN" "Lid van Administrators groep, niet elevated"
    } else {
        Write-Pass "Gebruiker heeft GEEN lokale administrator rechten."
        Save-Result "RT-SS-01" "Local Admin Rights" "PASS" "Geen lokale admin"
    }
    Write-Info "Groepslidmaatschappen:"
    $groups | ForEach-Object { Write-Data $_ }
} catch {
    Write-Fail "Fout: $_"
    Save-Result "RT-SS-01" "Local Admin Rights" "FAIL" $_.ToString()
}


# ─── RT-SS-02 - BitLocker / Disk Encryption ──────────────────────────
Write-CheckHeader "RT-SS-02" "Disk Encryption (BitLocker)"
try {
    $volumes = Get-BitLockerVolume -ErrorAction Stop
    $allEncrypted = $true
    foreach ($vol in $volumes) {
        $status = "$($vol.MountPoint) - Status: $($vol.ProtectionStatus) | VolumeStatus: $($vol.VolumeStatus) | EncryptionPct: $($vol.EncryptionPercentage)%"
        Write-Info $status
        if ($vol.ProtectionStatus -ne "On" -or $vol.VolumeStatus -ne "FullyEncrypted") {
            $allEncrypted = $false
            Write-Warn "Volume $($vol.MountPoint) is NIET volledig versleuteld of bescherming staat UIT."
        }
    }
    if ($allEncrypted) {
        Write-Pass "Alle volumes zijn volledig versleuteld en BitLocker bescherming staat AAN."
        Save-Result "RT-SS-02" "Disk Encryption" "PASS" "Alle volumes versleuteld"
    } else {
        Save-Result "RT-SS-02" "Disk Encryption" "FAIL" "Een of meer volumes niet volledig versleuteld"
    }
} catch {
    Write-Warn "BitLocker cmdlets niet beschikbaar of fout: $_"
    Write-Info "Probeer handmatig: manage-bde -status"
    $bde = manage-bde -status 2>&1
    Write-Data ($bde | Out-String)
    Save-Result "RT-SS-02" "Disk Encryption" "WARN" "Handmatige controle vereist"
}


# ─── RT-SS-04 - CMD / PowerShell toegang ─────────────────────────────
Write-CheckHeader "RT-SS-04" "Command Line Access (CMD / PowerShell)"
try {
    # Check AppLocker / Software Restriction Policies voor CMD en PS
    $cmdBlocked = $false
    $psBlocked  = $false

    # AppLocker via registry
    $alKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
    if (Test-Path $alKey) {
        Write-Warn "AppLocker policies zijn geconfigureerd (SrpV2 registry key aanwezig)."
        $rules = Get-ChildItem $alKey -ErrorAction SilentlyContinue
        Write-Info "AppLocker rule categorieën:"
        $rules | ForEach-Object { Write-Data $_.PSChildName }
    } else {
        Write-Info "Geen AppLocker SrpV2 policies gevonden."
    }

    # PowerShell execution policy
    $execPolicies = Get-ExecutionPolicy -List
    Write-Info "PowerShell Execution Policies:"
    $execPolicies | ForEach-Object { Write-Data ("  {0,-20} : {1}" -f $_.Scope, $_.ExecutionPolicy) }

    $effectivePolicy = Get-ExecutionPolicy
    if ($effectivePolicy -in @("Restricted", "AllSigned")) {
        Write-Warn "Effectieve ExecutionPolicy is '$effectivePolicy' - scripts worden geblokkeerd."
        Save-Result "RT-SS-04" "CMD/PS Toegang" "WARN" "ExecutionPolicy: $effectivePolicy"
    } else {
        Write-Fail "ExecutionPolicy is '$effectivePolicy' - scripts kunnen worden uitgevoerd."
        Save-Result "RT-SS-04" "CMD/PS Toegang" "FAIL" "ExecutionPolicy: $effectivePolicy (te permissief)"
    }

    # Check of CMD geblokkeerd is via Group Policy
    $cmdDisabled = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Name "DisableCMD" -ErrorAction SilentlyContinue).DisableCMD
    if ($cmdDisabled -eq 1 -or $cmdDisabled -eq 2) {
        Write-Pass "CMD is geblokkeerd via Group Policy (DisableCMD=$cmdDisabled)."
    } else {
        Write-Fail "CMD is NIET geblokkeerd via Group Policy."
    }
} catch {
    Write-Fail "Fout: $_"
    Save-Result "RT-SS-04" "CMD/PS Toegang" "FAIL" $_.ToString()
}


# ─── RT-SS-05 - Windows Update Status ────────────────────────────────
Write-CheckHeader "RT-SS-05" "Windows Updates Status"
try {
    $updateSvc = Get-Service -Name wuauserv -ErrorAction Stop
    Write-Info "Windows Update service status: $($updateSvc.Status) | StartType: $($updateSvc.StartType)"

    # Controleer via registry of Automatic Updates aan staat
    $wuPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
    $noAU     = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue

    if ($wuPolicy.NoAutoUpdate -eq 1) {
        Write-Fail "Automatische updates zijn UITGESCHAKELD via Group Policy."
        Save-Result "RT-SS-05" "Windows Updates" "FAIL" "NoAutoUpdate=1 via GPO"
    } else {
        Write-Pass "Automatische updates lijken INGESCHAKELD."
        Save-Result "RT-SS-05" "Windows Updates" "PASS" "Automatische updates aan"
    }

    # Laatste succesvolle update
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $history  = $searcher.QueryHistory(0, 5)
    Write-Info "Laatste 5 geïnstalleerde updates:"
    $history | ForEach-Object {
        Write-Data ("  [{0}] {1}" -f $_.Date.ToString("dd-MM-yyyy"), $_.Title)
    }
} catch {
    Write-Warn "Kon update history niet ophalen via COM: $_"
    # Fallback via Get-HotFix
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
    Write-Info "Laatste 10 hotfixes (Get-HotFix):"
    $hotfixes | ForEach-Object { Write-Data ("  [{0}] {1} - {2}" -f $_.InstalledOn, $_.HotFixID, $_.Description) }
    Save-Result "RT-SS-05" "Windows Updates" "INFO" "Controleer hotfix lijst"
}


# ══════════════════════════════════════════════════════════════════════
#  SECTIE: NETWORK AND ACCESS SECURITY
# ══════════════════════════════════════════════════════════════════════
Write-SectionHeader "NETWORK AND ACCESS SECURITY"

# ─── RT-NA-02 - Endpoint Protection ──────────────────────────────────
Write-CheckHeader "RT-NA-02" "Endpoint Protection Status"
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop

    Write-Info "Windows Defender:"
    Write-Data "  RealTimeProtection   : $($defenderStatus.RealTimeProtectionEnabled)"
    Write-Data "  AntivirusEnabled     : $($defenderStatus.AntivirusEnabled)"
    Write-Data "  AntiSpywareEnabled   : $($defenderStatus.AntispywareEnabled)"
    Write-Data "  BehaviorMonitor      : $($defenderStatus.BehaviorMonitorEnabled)"
    Write-Data "  TamperProtection     : $($defenderStatus.IsTamperProtected)"
    Write-Data "  AMSIEnabled          : $($defenderStatus.AmsEnabled)"
    Write-Data "  SignatureVersion     : $($defenderStatus.AntivirusSignatureVersion)"
    Write-Data "  SignatureAge (dagen) : $($defenderStatus.AntivirusSignatureAge)"

    if (-not $defenderStatus.RealTimeProtectionEnabled) {
        Write-Fail "Real-Time Protection is UITGESCHAKELD."
        Save-Result "RT-NA-02" "Endpoint Protection" "FAIL" "RealTimeProtection uitgeschakeld"
    } elseif ($defenderStatus.AntivirusSignatureAge -gt 7) {
        Write-Warn "Signaturen zijn $($defenderStatus.AntivirusSignatureAge) dagen oud (>7 dagen)."
        Save-Result "RT-NA-02" "Endpoint Protection" "WARN" "Signatures $($defenderStatus.AntivirusSignatureAge) dagen oud"
    } else {
        Write-Pass "Endpoint protection actief en up-to-date."
        Save-Result "RT-NA-02" "Endpoint Protection" "PASS" "Defender actief, signatures $($defenderStatus.AntivirusSignatureAge) dag(en) oud"
    }

    # Controleer exclusies (indicatief - volledige lijst vereist admin)
    try {
        $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
        if ($exclusions) {
            Write-Warn "Defender exclusies gevonden ($($exclusions.Count)):"
            $exclusions | ForEach-Object { Write-Data "    $_" }
        } else {
            Write-Pass "Geen Defender pad-exclusies geconfigureerd."
        }
    } catch { Write-Info "Kon exclusies niet ophalen (mogelijk admin vereist)." }
} catch {
    Write-Warn "Windows Defender cmdlets niet beschikbaar: $_"
    Save-Result "RT-NA-02" "Endpoint Protection" "WARN" "Handmatige controle vereist"
}


# ─── RT-NA-04 - Local Firewall Settings ──────────────────────────────
Write-CheckHeader "RT-NA-04" "Local Firewall Settings"
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $allOn = $true
    foreach ($p in $profiles) {
        $state = if ($p.Enabled) { "AAN" } else { "UIT" }
        $color = if ($p.Enabled) { "Green" } else { "Red" }
        Write-Host ("  [INFO]   Profiel {0,-15}: {1} | DefaultInbound: {2} | DefaultOutbound: {3}" -f `
            $p.Name, $state, $p.DefaultInboundAction, $p.DefaultOutboundAction) -ForegroundColor $color
        if (-not $p.Enabled) { $allOn = $false }
    }

    if ($allOn) {
        Write-Pass "Firewall is AAN voor alle profielen."
        Save-Result "RT-NA-04" "Firewall" "PASS" "Alle profielen actief"
    } else {
        Write-Fail "Een of meer firewall profielen zijn UITGESCHAKELD."
        Save-Result "RT-NA-04" "Firewall" "FAIL" "Profiel(en) uitgeschakeld"
    }

    # Open inbound rules
    $openRules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
                 Where-Object { $_.Profile -ne "Domain" } |
                 Select-Object DisplayName, Profile, @{n="LocalPort";e={($_ | Get-NetFirewallPortFilter).LocalPort}} |
                 Where-Object { $_.LocalPort -ne "Any" -and $_.LocalPort -ne $null }

    if ($openRules) {
        Write-Warn "Open inbound firewall regels (niet-Domain profiel, specifieke poorten):"
        $openRules | ForEach-Object { Write-Data ("  {0} | Profiel: {1} | Poort: {2}" -f $_.DisplayName, $_.Profile, $_.LocalPort) }
    } else {
        Write-Pass "Geen opvallende open inbound regels gevonden."
    }
} catch {
    Write-Fail "Fout bij ophalen firewall instellingen: $_"
    Save-Result "RT-NA-04" "Firewall" "FAIL" $_.ToString()
}


# ══════════════════════════════════════════════════════════════════════
#  SECTIE: SYSTEM MANIPULATIONS
# ══════════════════════════════════════════════════════════════════════
Write-SectionHeader "SYSTEM MANIPULATIONS"

# ─── RT-SM-03 - PowerShell 2.0 ───────────────────────────────────────
Write-CheckHeader "RT-SM-03" "PowerShell 2.0 Availability"
try {
    $ps2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction Stop
    Write-Info "Windows Feature status: $($ps2Feature.State)"
    if ($ps2Feature.State -eq "Enabled") {
        Write-Fail "PowerShell 2.0 is INGESCHAKELD. Dit kan AMSI en logging omzeilen (downgrade attack)."
        Save-Result "RT-SM-03" "PowerShell 2.0" "FAIL" "PS2 is ingeschakeld - downgrade mogelijk"
    } else {
        Write-Pass "PowerShell 2.0 is UITGESCHAKELD."
        Save-Result "RT-SM-03" "PowerShell 2.0" "PASS" "PS2 uitgeschakeld"
    }
} catch {
    # Fallback: probeer PS2 te detecteren via registry
    $ps2Key = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" -ErrorAction SilentlyContinue
    if ($ps2Key) {
        Write-Fail "PowerShell 2.0 registry key aanwezig - mogelijk beschikbaar."
        Save-Result "RT-SM-03" "PowerShell 2.0" "WARN" "Registry key aanwezig, handmatige check aanbevolen"
    } else {
        Write-Warn "Kon PowerShell 2.0 status niet bepalen (vereist admin): $_"
        Save-Result "RT-SM-03" "PowerShell 2.0" "WARN" "Admin vereist voor controle"
    }
}


# ══════════════════════════════════════════════════════════════════════
#  SECTIE: SECURITY CHECKS
# ══════════════════════════════════════════════════════════════════════
Write-SectionHeader "SECURITY CHECKS"

# ─── RT-SC-01 - IPv6 Enablement ──────────────────────────────────────
Write-CheckHeader "RT-SC-01" "IPv6 Enablement"
try {
    $adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop
    $ipv6Enabled = $adapters | Where-Object { $_.Enabled -eq $true }
    Write-Info "IPv6 binding per adapter:"
    $adapters | ForEach-Object {
        Write-Data ("  {0,-30} : {1}" -f $_.Name, $(if ($_.Enabled) { "INGESCHAKELD" } else { "uitgeschakeld" }))
    }
    if ($ipv6Enabled) {
        Write-Warn "IPv6 is INGESCHAKELD op $($ipv6Enabled.Count) adapter(s). Risico: MiTM6 aanvallen mogelijk."
        Save-Result "RT-SC-01" "IPv6" "WARN" "IPv6 actief op: $($ipv6Enabled.Name -join ', ')"
    } else {
        Write-Pass "IPv6 is uitgeschakeld op alle adapters."
        Save-Result "RT-SC-01" "IPv6" "PASS" "IPv6 uitgeschakeld"
    }
} catch {
    Write-Fail "Fout: $_"
    Save-Result "RT-SC-01" "IPv6" "FAIL" $_.ToString()
}


# ─── RT-SC-02 - LLMNR / NetBIOS / mDNS ──────────────────────────────
Write-CheckHeader "RT-SC-02" "LLMNR, NetBIOS, mDNS"

# LLMNR
try {
    $llmnrKey = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    if ($llmnrKey.EnableMulticast -eq 0) {
        Write-Pass "LLMNR is UITGESCHAKELD via Group Policy."
        Save-Result "RT-SC-02-LLMNR" "LLMNR" "PASS" "LLMNR uitgeschakeld"
    } else {
        Write-Fail "LLMNR is INGESCHAKELD (of niet geconfigureerd). Risico: LLMNR poisoning."
        Save-Result "RT-SC-02-LLMNR" "LLMNR" "FAIL" "LLMNR ingeschakeld"
    }
} catch {
    Write-Warn "Kon LLMNR status niet bepalen."
}

# NetBIOS
try {
    $adaptersConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
    $netbiosEnabled = $adaptersConfig | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
    Write-Info "NetBIOS status per adapter:"
    $adaptersConfig | ForEach-Object {
        $nbStatus = switch ($_.TcpipNetbiosOptions) {
            0 { "Via DHCP" }
            1 { "INGESCHAKELD" }
            2 { "Uitgeschakeld" }
            default { "Onbekend ($_)" }
        }
        Write-Data ("  {0,-30} : {1}" -f $_.Description, $nbStatus)
    }
    if ($netbiosEnabled) {
        Write-Fail "NetBIOS is INGESCHAKELD op een of meer adapters. Risico: NBT-NS poisoning."
        Save-Result "RT-SC-02-NetBIOS" "NetBIOS" "FAIL" "NetBIOS ingeschakeld"
    } else {
        Write-Pass "NetBIOS is uitgeschakeld op alle adapters."
        Save-Result "RT-SC-02-NetBIOS" "NetBIOS" "PASS" "NetBIOS uitgeschakeld"
    }
} catch {
    Write-Warn "Kon NetBIOS status niet bepalen: $_"
}

# mDNS
try {
    $mdnsKey = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue
    if ($null -eq $mdnsKey -or $mdnsKey.EnableMDNS -ne 0) {
        Write-Fail "mDNS is INGESCHAKELD (standaard in Windows). Risico: mDNS poisoning."
        Save-Result "RT-SC-02-mDNS" "mDNS" "FAIL" "mDNS ingeschakeld"
    } else {
        Write-Pass "mDNS is UITGESCHAKELD."
        Save-Result "RT-SC-02-mDNS" "mDNS" "PASS" "mDNS uitgeschakeld"
    }
} catch {
    Write-Warn "Kon mDNS status niet bepalen."
}


# ─── RT-SC-03 - Open Services / SMB Shares ───────────────────────────
Write-CheckHeader "RT-SC-03" "Open Services & SMB Shares"
try {
    # Luisterende TCP poorten
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
                 Select-Object LocalAddress, LocalPort, OwningProcess |
                 Sort-Object LocalPort

    Write-Info "Luisterende TCP poorten:"
    foreach ($l in $listeners) {
        try {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.Name } else { "PID $($l.OwningProcess)" }
        } catch { $procName = "PID $($l.OwningProcess)" }
        Write-Data ("  {0,-20} :{1,-6} [{2}]" -f $l.LocalAddress, $l.LocalPort, $procName)
    }

    # Opvallende/risicovolle poorten
    $riskyPorts = @{445="SMB"; 139="NetBIOS-SSN"; 135="RPC"; 5985="WinRM-HTTP"; 5986="WinRM-HTTPS"; 3389="RDP"; 21="FTP"; 23="Telnet"}
    $found = @()
    foreach ($port in $riskyPorts.Keys) {
        if ($listeners.LocalPort -contains $port) {
            $found += "$port ($($riskyPorts[$port]))"
        }
    }
    if ($found) {
        Write-Warn "Risicovolle luisterende poorten gevonden: $($found -join ', ')"
        Save-Result "RT-SC-03" "Open Services" "WARN" "Poorten: $($found -join ', ')"
    } else {
        Write-Pass "Geen opvallende risicovolle poorten luisteren."
        Save-Result "RT-SC-03" "Open Services" "PASS" "Geen risicopoorten"
    }

    # SMB shares
    $shares = Get-SmbShare -ErrorAction SilentlyContinue
    Write-Info "SMB Shares:"
    $shares | ForEach-Object {
        Write-Data ("  {0,-20} | Pad: {1} | Type: {2}" -f $_.Name, $_.Path, $_.ShareType)
    }
    $nonDefaultShares = $shares | Where-Object { $_.Name -notmatch "^(ADMIN\$|C\$|IPC\$|NETLOGON|SYSVOL|print\$)$" }
    if ($nonDefaultShares) {
        Write-Warn "Niet-standaard SMB shares aanwezig: $($nonDefaultShares.Name -join ', ')"
    } else {
        Write-Pass "Alleen standaard SMB shares aanwezig."
    }
} catch {
    Write-Fail "Fout: $_"
    Save-Result "RT-SC-03" "Open Services" "FAIL" $_.ToString()
}


# ─── RT-SC-04 - Startup Programs ─────────────────────────────────────
Write-CheckHeader "RT-SC-04" "Startup Programs"
try {
    $startupLocations = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";        Scope = "HKLM Run" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";        Scope = "HKCU Run" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";    Scope = "HKLM RunOnce" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";    Scope = "HKCU RunOnce" },
        @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"; Scope = "HKLM Run (x86)" }
    )

    $allEntries = @()
    foreach ($loc in $startupLocations) {
        if (Test-Path $loc.Path) {
            $keys = Get-ItemProperty $loc.Path -ErrorAction SilentlyContinue
            $keys.PSObject.Properties |
                Where-Object { $_.Name -notmatch "^PS" } |
                ForEach-Object {
                    $allEntries += [PSCustomObject]@{ Scope = $loc.Scope; Name = $_.Name; Value = $_.Value }
                }
        }
    }

    if ($allEntries) {
        Write-Info "Startup entries gevonden ($($allEntries.Count)):"
        $allEntries | ForEach-Object { Write-Data ("  [{0}] {1} = {2}" -f $_.Scope, $_.Name, $_.Value) }
        Save-Result "RT-SC-04" "Startup Programs" "INFO" "$($allEntries.Count) entries gevonden"
    } else {
        Write-Pass "Geen opvallende startup entries via registry."
        Save-Result "RT-SC-04" "Startup Programs" "PASS" "Geen afwijkende entries"
    }

    # Startup map
    $startupFolder = [System.Environment]::GetFolderPath("Startup")
    $startupFiles  = Get-ChildItem $startupFolder -ErrorAction SilentlyContinue
    if ($startupFiles) {
        Write-Warn "Bestanden in Startup map ($startupFolder):"
        $startupFiles | ForEach-Object { Write-Data "  $($_.FullName)" }
    } else {
        Write-Pass "Startup map ($startupFolder) is leeg."
    }
} catch {
    Write-Fail "Fout: $_"
    Save-Result "RT-SC-04" "Startup Programs" "FAIL" $_.ToString()
}


# ─── RT-SC-05 - Gevoelige data in omgevingsvariabelen ─────────────────
Write-CheckHeader "RT-SC-05" "Sensitive Data in Environment Variables"
try {
    # Haal variabelen per scope op en voeg samen in een hashtable (laatste waarde wint bij duplicaat)
    $envVars = @{}
    foreach ($scope in @(
        [System.EnvironmentVariableTarget]::Machine,
        [System.EnvironmentVariableTarget]::User,
        [System.EnvironmentVariableTarget]::Process
    )) {
        $scopeVars = [System.Environment]::GetEnvironmentVariables($scope)
        foreach ($key in $scopeVars.Keys) {
            $envVars[$key] = $scopeVars[$key]   # duplicate keys worden stilletjes overschreven
        }
    }

    # Verdachte sleutelwoorden
    $sensitiveKeys   = @("password","passwd","pwd","secret","token","apikey","api_key","key","credential","cred","auth","connectionstring","connstr","privat")
    $sensitiveValues = @("password","passwd","secret","token","BEGIN","-----","eyJ")  # JWT, PEM beginnen zo

    $hits = @()
    foreach ($key in $envVars.Keys) {
        $val = $envVars[$key]
        $keyHit = $sensitiveKeys | Where-Object { $key -match $_ }
        $valHit = $sensitiveValues | Where-Object { $val -match $_ }
        if ($keyHit -or $valHit) {
            $hits += [PSCustomObject]@{ Variable = $key; Value = ($val -replace ".", "*") }  # gemaskerd
        }
    }

    Write-Info "Alle omgevingsvariabelen (naam):"
    $envVars.Keys | Sort-Object | ForEach-Object { Write-Data "  $_" }

    if ($hits) {
        Write-Fail "Mogelijk gevoelige omgevingsvariabelen gevonden ($($hits.Count)):"
        $hits | ForEach-Object { Write-Data ("  {0} = [GEMASKERD]" -f $_.Variable) }
        Save-Result "RT-SC-05" "Env Variables" "FAIL" "Gevoelige keys: $($hits.Variable -join ', ')"
    } else {
        Write-Pass "Geen opvallend gevoelige omgevingsvariabelen gevonden."
        Save-Result "RT-SC-05" "Env Variables" "PASS" "Geen verdachte variabelen"
    }
} catch {
    Write-Fail "Fout: $_"
    Save-Result "RT-SC-05" "Env Variables" "FAIL" $_.ToString()
}


# ─── RT-SC-07 - Recent Security Patches ──────────────────────────────
Write-CheckHeader "RT-SC-07" "Recent Security Patches"
try {
    $os         = Get-WmiObject Win32_OperatingSystem
    $buildStr   = "$($os.Caption) Build $($os.BuildNumber)"
    Write-Info "OS: $buildStr"

    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
    $lastPatch = $hotfixes | Select-Object -First 1

    Write-Info "Laatste patch: $($lastPatch.HotFixID) geïnstalleerd op $($lastPatch.InstalledOn)"
    Write-Info "Alle recente patches:"
    $hotfixes | Select-Object -First 15 | ForEach-Object {
        Write-Data ("  [{0}] {1} - {2}" -f $_.InstalledOn.ToString("dd-MM-yyyy"), $_.HotFixID, $_.Description)
    }

    $daysSince = (Get-Date) - $lastPatch.InstalledOn
    if ($daysSince.Days -gt 60) {
        Write-Fail "Laatste patch is $($daysSince.Days) dagen geleden - systeem mogelijk verouderd."
        Save-Result "RT-SC-07" "Security Patches" "FAIL" "Laatste patch: $($daysSince.Days) dagen geleden"
    } elseif ($daysSince.Days -gt 30) {
        Write-Warn "Laatste patch is $($daysSince.Days) dagen geleden."
        Save-Result "RT-SC-07" "Security Patches" "WARN" "Laatste patch: $($daysSince.Days) dagen geleden"
    } else {
        Write-Pass "Laatste patch is $($daysSince.Days) dag(en) geleden."
        Save-Result "RT-SC-07" "Security Patches" "PASS" "Recent gepatcht"
    }
} catch {
    Write-Fail "Fout: $_"
    Save-Result "RT-SC-07" "Security Patches" "FAIL" $_.ToString()
}


# ══════════════════════════════════════════════════════════════════════
#  SECTIE: SYSTEM HARDENING
# ══════════════════════════════════════════════════════════════════════
Write-SectionHeader "SYSTEM HARDENING"

# ─── RT-SH-02 - SMB Security ─────────────────────────────────────────
Write-CheckHeader "RT-SH-02" "SMB Security (SMBv1 / SMB Signing)"
try {
    # SMBv1
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
    Write-Info "SMBv1 Feature status: $($smbv1.State)"
    if ($smbv1.State -eq "Enabled") {
        Write-Fail "SMBv1 is INGESCHAKELD. Dit is een ernstig beveiligingsrisico (EternalBlue etc.)."
        Save-Result "RT-SH-02-SMBv1" "SMBv1" "FAIL" "SMBv1 ingeschakeld"
    } else {
        Write-Pass "SMBv1 is UITGESCHAKELD."
        Save-Result "RT-SH-02-SMBv1" "SMBv1" "PASS" "SMBv1 uitgeschakeld"
    }
} catch {
    # Fallback
    $smbv1reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
    if ($smbv1reg.SMB1 -eq 0) {
        Write-Pass "SMBv1 uitgeschakeld via registry."
        Save-Result "RT-SH-02-SMBv1" "SMBv1" "PASS" "SMBv1 uitgeschakeld (registry)"
    } else {
        Write-Warn "Kon SMBv1 status niet volledig bepalen: $_"
        Save-Result "RT-SH-02-SMBv1" "SMBv1" "WARN" "Handmatige check vereist"
    }
}

try {
    # SMB Signing
    $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
    Write-Info "SMB Server configuratie:"
    Write-Data "  RequireSecuritySignature : $($smbConfig.RequireSecuritySignature)"
    Write-Data "  EnableSecuritySignature  : $($smbConfig.EnableSecuritySignature)"
    Write-Data "  EncryptData              : $($smbConfig.EncryptData)"

    if (-not $smbConfig.RequireSecuritySignature) {
        Write-Fail "SMB Signing is NIET verplicht (RequireSecuritySignature=False). Risico: SMB relay aanvallen."
        Save-Result "RT-SH-02-Signing" "SMB Signing" "FAIL" "SMB Signing niet verplicht"
    } else {
        Write-Pass "SMB Signing is verplicht."
        Save-Result "RT-SH-02-Signing" "SMB Signing" "PASS" "SMB Signing verplicht"
    }

    # SMB Client signing
    $smbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
    if ($smbClient) {
        Write-Info "SMB Client signing:"
        Write-Data "  RequireSecuritySignature : $($smbClient.RequireSecuritySignature)"
        if (-not $smbClient.RequireSecuritySignature) {
            Write-Warn "SMB Client signing niet verplicht - relay naar dit systeem mogelijk."
        }
    }
} catch {
    Write-Warn "Kon SMB configuratie niet ophalen: $_"
}


# ══════════════════════════════════════════════════════════════════════
#  SAMENVATTINGS RAPPORT
# ══════════════════════════════════════════════════════════════════════
Write-SectionHeader "SAMENVATTING"

$pass  = $script:AllResults | Where-Object { $_.Status -eq "PASS" }
$warn  = $script:AllResults | Where-Object { $_.Status -eq "WARN" }
$fail  = $script:AllResults | Where-Object { $_.Status -eq "FAIL" }
$info  = $script:AllResults | Where-Object { $_.Status -eq "INFO" }

Write-Host ""
Write-Host ("  PASS  : {0,3}" -f $pass.Count) -ForegroundColor Green
Write-Host ("  WARN  : {0,3}" -f $warn.Count) -ForegroundColor Magenta
Write-Host ("  FAIL  : {0,3}" -f $fail.Count) -ForegroundColor Red
Write-Host ("  INFO  : {0,3}" -f $info.Count) -ForegroundColor White
Write-Host ""

if ($fail) {
    Write-Host "  BEVINDINGEN - FAIL:" -ForegroundColor Red
    $fail | ForEach-Object { Write-Host ("    [{0}] {1}: {2}" -f $_.ID, $_.Name, $_.Detail) -ForegroundColor Red }
}
if ($warn) {
    Write-Host "`n  BEVINDINGEN - WARN:" -ForegroundColor Magenta
    $warn | ForEach-Object { Write-Host ("    [{0}] {1}: {2}" -f $_.ID, $_.Name, $_.Detail) -ForegroundColor Magenta }
}

# Export CSV
$csvPath = ".\Werkplekconcept_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$script:AllResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Host "`n  Resultaten opgeslagen in: $csvPath" -ForegroundColor Cyan
Write-Host ("  " + "=" * 68) -ForegroundColor Cyan
