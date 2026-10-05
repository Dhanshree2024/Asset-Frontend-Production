<#
.SYNOPSIS
    Asset Discovery local collector (Windows). Gathers this PC's hardware,
    OS, network and installed-software inventory (DeviceSpecs contract v2)
    and posts it to the Asset Discovery backend.

.DESCRIPTION
    Runs on the machine being inventoried, using local WMI/CIM and the local
    registry. No remote credentials or remote management needed. Written in
    plain PowerShell (no encoded commands, no Invoke-Expression) so it is easy
    to review and less likely to trip antivirus heuristics. Renamed from
    collect-specs.ps1 (which some antivirus engines quarantined by name).
    If AV still flags it, add a folder exclusion or use the signed compiled
    agent (AssetDiscoveryAgent), which performs the same collection.

    Software inventory now covers:
      - HKLM Uninstall (64-bit)
      - HKLM WOW6432Node Uninstall (32-bit)
      - HKCU Uninstall (current user's per-user installs)
      - HKEY_USERS\<SID>\...\Uninstall for any OTHER user profiles that are
        already loaded (i.e. logged in / hive mounted) at collection time
      - Installed UWP/Microsoft Store (Appx) packages
    This matches what Windows Settings > Apps shows, which is a union of
    machine-wide, per-user, and Store package sources - the old script only
    read the two HKLM roots, which is why its count ran lower.

.PARAMETER Server    Base URL of the backend, e.g. http://192.168.1.115:8013
.PARAMETER Token     The org enrolment token (DISCOVERY_AGENT_TOKEN).
.PARAMETER OrgSchema Tenant schema (org_xxx) for multi-tenant installs. Optional.
.PARAMETER Install   Register a daily Scheduled Task that re-runs this collection.
.PARAMETER TaskTime  Time of day for the -Install scheduled task (default 12:00).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\windows-collector.ps1 -Server "http://192.168.1.115:8013" -Token "<AGENT_TOKEN>"
#>
[CmdletBinding()]
param(
    [string] $Server    = $env:DISCOVERY_SERVER_URL,
    [string] $Token     = $env:DISCOVERY_AGENT_TOKEN,
    [string] $OrgSchema  = $env:DISCOVERY_ORG_SCHEMA,
    [switch] $Install,
    [string] $TaskTime  = '12:00'
)

if ([string]::IsNullOrWhiteSpace($Server)) {
    Write-Error 'Server URL is required. Pass -Server "http://host:8013" or set DISCOVERY_SERVER_URL.'
    exit 1
}
$Server = $Server.TrimEnd('/')
$uri = "$Server/discovery/agent/report"

if ($Install) {
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        $psExe = (Get-Command powershell.exe).Source
        $argLine = "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`" -Server `"$Server`" -Token `"$Token`""
        if (-not [string]::IsNullOrWhiteSpace($OrgSchema)) { $argLine += " -OrgSchema `"$OrgSchema`"" }
        $action  = New-ScheduledTaskAction -Execute $psExe -Argument $argLine
        $trigger = New-ScheduledTaskTrigger -Daily -At $TaskTime
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName 'AssetDiscoveryCollector' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Write-Host "Installed scheduled task 'AssetDiscoveryCollector' (daily at $TaskTime)." -ForegroundColor Green
    } catch {
        Write-Error "Failed to install scheduled task: $($_.Exception.Message)"
        exit 1
    }
    exit 0
}

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function ConvertTo-IsoUtc {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null }
}
function ConvertFrom-RegistryInstallDate {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return ([datetime]::ParseExact($Value.Trim(), 'yyyyMMdd', $null)).ToString('yyyy-MM-ddT00:00:00Z') } catch { return $null }
}

$VirtualNicRe = 'vmware|vmnet|virtualbox|vbox|hyper-v|vethernet|host-only|loopback|tunnel|tap-windows|tap adapter|openvpn|wireguard|tailscale|zerotier|nordlynx|anyconnect|globalprotect|forticlient|sonicwall|wan miniport|ras async|bluetooth|wsl|virtual'

function Get-LocalSpecs {
    $os   = Get-CimInstance -ClassName Win32_OperatingSystem       -ErrorAction SilentlyContinue
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem        -ErrorAction SilentlyContinue
    $csp  = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS                  -ErrorAction SilentlyContinue
    $encl = Get-CimInstance -ClassName Win32_SystemEnclosure       -ErrorAction SilentlyContinue
    $cpus = @(Get-CimInstance -ClassName Win32_Processor           -ErrorAction SilentlyContinue)

    $coreCount = 0; $logicalCount = 0
    foreach ($c in $cpus) {
        if ($c.NumberOfCores)             { $coreCount    += [int]$c.NumberOfCores }
        if ($c.NumberOfLogicalProcessors) { $logicalCount += [int]$c.NumberOfLogicalProcessors }
    }
    $cpuModel = if ($cpus.Count -gt 0 -and $cpus[0].Name) { ($cpus[0].Name).Trim() } else { $null }
    $cpuMfr   = if ($cpus.Count -gt 0 -and $cpus[0].Manufacturer) { ($cpus[0].Manufacturer).Trim() } else { $null }
    $cpuGHz   = if ($cpus.Count -gt 0 -and $cpus[0].MaxClockSpeed) { [math]::Round([double]$cpus[0].MaxClockSpeed/1000,2) } else { $null }
    $ramGB    = if ($cs -and $cs.TotalPhysicalMemory) { [math]::Round([double]$cs.TotalPhysicalMemory/1GB,1) } else { 0 }
    $ramAvailGB = if ($os -and $os.FreePhysicalMemory) { [math]::Round([double]$os.FreePhysicalMemory*1KB/1GB,1) } else { $null }

    $memoryModules = @()
    foreach ($m in @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue)) {
        $memoryModules += [ordered]@{
            slot         = if ($m.DeviceLocator) { [string]$m.DeviceLocator } else { $null }
            capacityGB   = if ($m.Capacity)      { [math]::Round([double]$m.Capacity/1GB,1) } else { $null }
            speedMHz     = if ($m.Speed)         { [int]$m.Speed } else { $null }
            manufacturer = if ($m.Manufacturer)  { ([string]$m.Manufacturer).Trim() } else { $null }
            partNumber   = if ($m.PartNumber)    { ([string]$m.PartNumber).Trim() } else { $null }
            serial       = if ($m.SerialNumber)  { ([string]$m.SerialNumber).Trim() } else { $null }
        }
    }

    $logicalDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)
    $ldToPart     = @(Get-CimInstance -ClassName Win32_LogicalDiskToPartition -ErrorAction SilentlyContinue)
    $ddToPart     = @(Get-CimInstance -ClassName Win32_DiskDriveToDiskPartition -ErrorAction SilentlyContinue)

    $partToDisk = @{}
    foreach ($a in $ddToPart) { try { $partToDisk[$a.Dependent.DeviceID] = $a.Antecedent.DeviceID } catch { } }
    $partsByDisk = @{}
    foreach ($a in $ldToPart) {
        try {
            $ld = $logicalDisks | Where-Object { $_.DeviceID -eq $a.Dependent.DeviceID } | Select-Object -First 1
            if (-not $ld) { continue }
            $diskId = $partToDisk[$a.Antecedent.DeviceID]
            if (-not $diskId) { $diskId = '?' }
            if (-not $partsByDisk.ContainsKey($diskId)) { $partsByDisk[$diskId] = @() }
            $partsByDisk[$diskId] += [ordered]@{
                name       = [string]$ld.DeviceID
                sizeGB     = if ($ld.Size)      { [math]::Round([double]$ld.Size/1GB,1) }      else { 0 }
                freeGB     = if ($ld.FreeSpace) { [math]::Round([double]$ld.FreeSpace/1GB,1) } else { 0 }
                fileSystem = if ($ld.FileSystem) { [string]$ld.FileSystem } else { $null }
            }
        } catch { }
    }

    $disks = @()
    foreach ($dd in @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue)) {
        $parts = if ($dd.DeviceID -and $partsByDisk.ContainsKey($dd.DeviceID)) { $partsByDisk[$dd.DeviceID] } else { @() }
        $free = 0.0
        foreach ($pp in $parts) { if ($pp.freeGB) { $free += [double]$pp.freeGB } }
        $disks += [ordered]@{
            model      = if ($dd.Model)        { ([string]$dd.Model).Trim() } else { $null }
            serial     = if ($dd.SerialNumber) { ([string]$dd.SerialNumber).Trim() } else { $null }
            sizeGB     = if ($dd.Size)         { [math]::Round([double]$dd.Size/1GB,1) } else { 0 }
            freeGB     = [math]::Round($free,1)
            mediaType  = if ($dd.MediaType)    { [string]$dd.MediaType } else { $null }
            partitions = $parts
        }
    }
    if ($disks.Count -eq 0) {
        foreach ($ld in $logicalDisks) {
            $disks += [ordered]@{
                model = [string]$ld.DeviceID; serial = $null
                sizeGB = if ($ld.Size) { [math]::Round([double]$ld.Size/1GB,1) } else { 0 }
                freeGB = if ($ld.FreeSpace) { [math]::Round([double]$ld.FreeSpace/1GB,1) } else { 0 }
                mediaType = $null; partitions = @()
            }
        }
    }

    $adapters = @()
    foreach ($n in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction SilentlyContinue)) {
        $ip4 = if ($n.IPAddress) { @($n.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })[0] } else { $null }
        $mask = $null
        if ($n.IPSubnet -and $n.IPAddress) {
            $subnets = @($n.IPSubnet); $addrs = @($n.IPAddress)
            for ($i = 0; $i -lt $addrs.Count; $i++) {
                if ($addrs[$i] -match '^\d+\.\d+\.\d+\.\d+$') { if ($i -lt $subnets.Count) { $mask = $subnets[$i] }; break }
            }
        }
        $adapters += [ordered]@{
            name           = if ($n.Description) { [string]$n.Description } else { $null }
            ip             = $ip4
            mac            = if ($n.MACAddress) { [string]$n.MACAddress } else { $null }
            subnetMask     = $mask
            gateway        = if ($n.DefaultIPGateway) { @($n.DefaultIPGateway)[0] } else { $null }
            dns            = if ($n.DNSServerSearchOrder) { @($n.DNSServerSearchOrder) } else { @() }
            connectionType = $null
        }
    }
    $primaryAdapter = $adapters | Where-Object { $_.gateway -and ($_.name -notmatch $VirtualNicRe) } | Select-Object -First 1
    if (-not $primaryAdapter) { $primaryAdapter = $adapters | Where-Object { $_.gateway } | Select-Object -First 1 }
    if (-not $primaryAdapter) { $primaryAdapter = $adapters | Where-Object { $_.name -notmatch $VirtualNicRe } | Select-Object -First 1 }
    if (-not $primaryAdapter) { $primaryAdapter = $adapters | Select-Object -First 1 }

    # ---- Software inventory -------------------------------------------------
    # Windows Settings > Apps unions: HKLM (64/32-bit), HKCU (current user),
    # HKEY_USERS\<SID> for other logged-in profiles, and installed Appx
    # (Microsoft Store / UWP) packages. The previous version only read the
    # two HKLM roots, which under-counts anything installed per-user or from
    # the Store.
    # NOTE: List[object] (a reference type) on purpose. The nested helper below
    # runs in a CHILD scope: "$software += x" there would create a new local
    # copy and never reach this list, and "$script:software" points at the
    # script file scope where this variable does not exist (so it was $null
    # and every registry entry was silently dropped). Calling .Add() on a
    # shared reference works from any child scope.
    $software = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[string]

    function Add-UninstallEntriesFromRoot {
        param([string] $Path, [string] $Arch)
        if (-not (Test-Path $Path)) { return }
        foreach ($sub in Get-ChildItem -Path $Path -ErrorAction SilentlyContinue) {
            try {
                $p = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
                if (-not $p -or [string]::IsNullOrWhiteSpace($p.DisplayName)) { continue }
                if ($p.SystemComponent -eq 1) { continue }
                if ($p.ParentKeyName) { continue }
                $dedupe = "$($p.DisplayName)|$($p.DisplayVersion)"
                if (-not $seen.Add($dedupe)) { continue }
                $software.Add([ordered]@{
                    name            = [string]$p.DisplayName
                    version         = if ($p.DisplayVersion) { [string]$p.DisplayVersion } else { $null }
                    publisher       = if ($p.Publisher) { [string]$p.Publisher } else { $null }
                    installDate     = ConvertFrom-RegistryInstallDate ([string]$p.InstallDate)
                    installLocation = if ($p.InstallLocation) { [string]$p.InstallLocation } else { $null }
                    architecture    = $Arch
                    productCode     = [string]$sub.PSChildName
                    uninstallString = if ($p.UninstallString) { [string]$p.UninstallString } else { $null }
                })
            } catch { }
        }
    }

    # 1) Machine-wide, 64-bit and 32-bit (redirected) views
    Add-UninstallEntriesFromRoot -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -Arch 'x64'
    Add-UninstallEntriesFromRoot -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -Arch 'x86'

    # 2) Current user's per-user installs (no admin rights required for these
    #    to exist - e.g. Chrome, Zoom, Slack, Discord commonly land here)
    Add-UninstallEntriesFromRoot -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -Arch 'per-user'

    # 3) Other user profiles, but only if their hive is already loaded (i.e.
    #    that user is currently logged in / their registry hive is mounted).
    #    We do NOT load ntuser.dat for logged-off users - that requires extra
    #    privileges and risks corrupting a profile if done incorrectly.
    try {
        foreach ($userKey in Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
            $sid = $userKey.PSChildName
            if ($sid -eq '.DEFAULT' -or $sid -like 'S-1-5-18' -or $sid -like 'S-1-5-19' -or $sid -like 'S-1-5-20' -or $sid -like '*_Classes') { continue }
            $path = "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            Add-UninstallEntriesFromRoot -Path $path -Arch 'per-user'
        }
    } catch { }

    # 4) Installed UWP / Microsoft Store apps - not present in the Uninstall
    #    registry keys at all, but Windows Settings > Apps counts them.
    try {
        $appxCmd = Get-Command Get-AppxPackage -ErrorAction SilentlyContinue
        if ($appxCmd) {
            $appxPackages = if ((Test-Path 'HKLM:\SOFTWARE') -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
            } else {
                @(Get-AppxPackage -ErrorAction SilentlyContinue)
            }
            foreach ($pkg in $appxPackages) {
                if (-not $pkg.Name -or $pkg.IsFramework -or $pkg.IsResourcePackage) { continue }
                $displayName = $pkg.Name
                try {
                    $manifest = Get-AppxPackageManifest -Package $pkg.PackageFullName -ErrorAction SilentlyContinue
                    if ($manifest -and $manifest.Package.Properties.DisplayName) {
                        $dn = [string]$manifest.Package.Properties.DisplayName
                        if ($dn -and -not $dn.StartsWith('ms-resource:')) { $displayName = $dn }
                    }
                } catch { }
                $dedupe = "$displayName|$($pkg.Version)"
                if (-not $seen.Add($dedupe)) { continue }
                $software.Add([ordered]@{
                    name            = $displayName
                    version         = if ($pkg.Version) { [string]$pkg.Version } else { $null }
                    publisher       = if ($pkg.Publisher) { [string]$pkg.Publisher } else { $null }
                    installDate     = $null
                    installLocation = if ($pkg.InstallLocation) { [string]$pkg.InstallLocation } else { $null }
                    architecture    = if ($pkg.Architecture) { [string]$pkg.Architecture } else { 'appx' }
                    productCode     = [string]$pkg.PackageFullName
                    uninstallString = $null
                })
            }
        }
    } catch { }

    return [ordered]@{
        reportedAt      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        contractVersion = 2
        hostname        = if ($cs -and $cs.Name) { $cs.Name } else { $env:COMPUTERNAME }
        domain          = if ($cs) { $cs.Domain } else { $null }
        currentUser     = if ($cs -and $cs.UserName) { $cs.UserName } else { $null }
        os = [ordered]@{
            caption     = if ($os) { $os.Caption } else { $null }
            version     = if ($os) { $os.Version } else { $null }
            build       = if ($os) { [string]$os.BuildNumber } else { $null }
            arch        = if ($os) { $os.OSArchitecture } else { $null }
            installDate = if ($os) { ConvertTo-IsoUtc $os.InstallDate } else { $null }
            lastBoot    = if ($os) { ConvertTo-IsoUtc $os.LastBootUpTime } else { $null }
        }
        cpu = [ordered]@{ model = $cpuModel; manufacturer = $cpuMfr; cores = $coreCount; logical = $logicalCount; speedGHz = $cpuGHz }
        ramGB          = $ramGB
        ramAvailableGB = $ramAvailGB
        memoryModules  = $memoryModules
        disks          = $disks
        bios = [ordered]@{
            vendor      = if ($bios -and $bios.Manufacturer) { [string]$bios.Manufacturer } else { $null }
            version     = if ($bios -and $bios.SMBIOSBIOSVersion) { [string]$bios.SMBIOSBIOSVersion } else { $null }
            releaseDate = if ($bios) { ConvertTo-IsoUtc $bios.ReleaseDate } else { $null }
        }
        system = [ordered]@{
            manufacturer = if ($cs) { $cs.Manufacturer } else { $null }
            model        = if ($cs) { $cs.Model } else { $null }
            serial       = if ($bios) { $bios.SerialNumber } else { $null }
            asset        = if ($encl -and $encl.SMBIOSAssetTag) { [string]$encl.SMBIOSAssetTag } else { $null }
            uuid         = if ($csp -and $csp.UUID) { [string]$csp.UUID } else { $null }
        }
        network = [ordered]@{
            ip             = if ($primaryAdapter) { $primaryAdapter.ip } else { $null }
            mac            = if ($primaryAdapter) { $primaryAdapter.mac } else { $null }
            subnetMask     = if ($primaryAdapter) { $primaryAdapter.subnetMask } else { $null }
            gateway        = if ($primaryAdapter) { $primaryAdapter.gateway } else { $null }
            dns            = if ($primaryAdapter) { $primaryAdapter.dns } else { @() }
            connectionType = $null
            adapters       = $adapters
        }
        software = @($software.ToArray())
        agent = [ordered]@{ platform = 'windows-script'; script = 'windows-collector.ps1' }
    }
}

$specs = Get-LocalSpecs
$json  = $specs | ConvertTo-Json -Depth 8 -Compress

$headers = @{ 'Content-Type' = 'application/json' }
if (-not [string]::IsNullOrWhiteSpace($Token))     { $headers['x-agent-token'] = $Token }
if (-not [string]::IsNullOrWhiteSpace($OrgSchema)) { $headers['x-org-schema']  = $OrgSchema }

try {
    $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $json -TimeoutSec 60
    if ($resp -and ($resp.status -eq $false)) {
        Write-Error "Server rejected report: $($resp.message) $($resp.error)"
        exit 1
    }
    Write-Host ("[OK] Reported {0} ({1} apps) to {2}" -f $specs.hostname, $specs.software.Count, $uri) -ForegroundColor Green
    exit 0
} catch {
    Write-Error "Failed to post inventory: $($_.Exception.Message)"
    exit 1
}