<#
.SYNOPSIS
    Agent Discovery remote collector - pulls deep specs from a list of remote
    Windows hosts over WinRM/CIM using ONE admin credential, and reports each
    to the Agent Discovery backend. No per-endpoint install needed.

.DESCRIPTION
    Runs from a single admin workstation. For every target host it opens a
    CIM session (WSMan/WinRM, DCOM fallback) with the supplied credential,
    gathers the same DeviceSpecs shape collect-specs.ps1 produces, then POSTs
    it from THIS workstation to {Server}/discovery/agent/report. Only the
    admin box needs to reach the server; the endpoints only need WinRM/DCOM
    reachable from the admin box.

    Prereqs on targets: WinRM enabled (`winrm quickconfig` / GPO) OR DCOM/RPC
    (135 + dynamic) reachable, and the credential must be a local admin on them.

.PARAMETER Server
    Base URL of the Agent Discovery API, e.g. http://192.168.1.115:8013.
    Falls back to $env:DISCOVERY_SERVER_URL.

.PARAMETER Token
    Shared agent token -> x-agent-token header. Falls back to $env:DISCOVERY_AGENT_TOKEN.

.PARAMETER OrgSchema
    Tenant schema (org_xxx) -> x-org-schema header. Falls back to $env:DISCOVERY_ORG_SCHEMA.

.PARAMETER ComputerName
    One or more target hostnames/IPs.

.PARAMETER HostFile
    Path to a text file with one hostname/IP per line (blank lines and #comments ignored).
    Combined with -ComputerName if both are given.

.PARAMETER Credential
    Admin credential for the targets. If omitted you're prompted (Get-Credential).

.PARAMETER Protocol
    CIM session transport: Auto (default: try Wsman then Dcom fallback), Wsman, or Dcom.

.EXAMPLE
    .\remote-collect.ps1 -Server "http://192.168.1.115:8013" -Token "<AGENT_TOKEN>" -HostFile .\hosts.txt

.EXAMPLE
    .\remote-collect.ps1 -Server "http://192.168.1.115:8013" -ComputerName PC-01,PC-02 -Protocol Auto
#>
[CmdletBinding()]
param(
    [string]   $Server    = $env:DISCOVERY_SERVER_URL,
    [string]   $Token     = $env:DISCOVERY_AGENT_TOKEN,
    [string]   $OrgSchema = $env:DISCOVERY_ORG_SCHEMA,
    [string[]] $ComputerName = @(),
    [string]   $HostFile,
    [System.Management.Automation.PSCredential] $Credential,
    [ValidateSet('Wsman','Dcom','Auto')]
    [string]   $Protocol = 'Auto'
)

$ErrorActionPreference = 'Stop'
# StrictMode intentionally left off - remote registry/CIM values are frequently
# absent and must read back as $null rather than throwing per host.
$script:lastCimError = $null

if ([string]::IsNullOrWhiteSpace($Server)) {
    Write-Error "Server URL is required. Pass -Server ""http://host:8013"" or set DISCOVERY_SERVER_URL."
    exit 1
}
$Server = $Server.TrimEnd('/')
$uri = "$Server/discovery/agent/report"

# ---- Build target list -----------------------------------------------------
$targets = New-Object System.Collections.Generic.List[string]
foreach ($c in $ComputerName) { if (-not [string]::IsNullOrWhiteSpace($c)) { $targets.Add($c.Trim()) } }
if ($HostFile) {
    if (-not (Test-Path $HostFile)) { Write-Error "HostFile not found: $HostFile"; exit 1 }
    foreach ($line in Get-Content -Path $HostFile) {
        $t = $line.Trim()
        if ($t -and -not $t.StartsWith('#')) { $targets.Add($t) }
    }
}
$targets = @($targets | Select-Object -Unique)
if ($targets.Count -eq 0) {
    Write-Error "No targets. Pass -ComputerName and/or -HostFile."
    exit 1
}

if (-not $Credential) { $Credential = Get-Credential -Message "Admin credential for the remote Windows hosts" }

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$headers = @{ 'Content-Type' = 'application/json' }
if (-not [string]::IsNullOrWhiteSpace($Token))     { $headers['x-agent-token'] = $Token }
if (-not [string]::IsNullOrWhiteSpace($OrgSchema)) { $headers['x-org-schema']  = $OrgSchema }

function ConvertTo-IsoUtc {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null }
}

function New-TargetCimSession {
    param([string] $Target, [System.Management.Automation.PSCredential] $Cred, [string] $Proto)
    $order = switch ($Proto) {
        'Wsman' { @('Wsman') }
        'Dcom'  { @('Dcom') }
        default { @('Wsman','Dcom') }   # Auto
    }
    foreach ($p in $order) {
        try {
            $opt = New-CimSessionOption -Protocol $p
            return New-CimSession -ComputerName $Target -Credential $Cred -SessionOption $opt -OperationTimeoutSec 30 -ErrorAction Stop
        } catch {
            $script:lastCimError = $_.Exception.Message
        }
    }
    return $null
}

function ConvertFrom-RegistryInstallDate {
    # Registry InstallDate is 'yyyyMMdd' (string) when present.
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        return ([datetime]::ParseExact($Value.Trim(), 'yyyyMMdd', $null)).ToString('yyyy-MM-ddT00:00:00Z')
    } catch { return $null }
}

function Get-RemoteSpecs {
    param([Microsoft.Management.Infrastructure.CimSession] $Session, [string] $Target)

    $os   = Get-CimInstance -CimSession $Session -ClassName Win32_OperatingSystem       -ErrorAction SilentlyContinue
    $cs   = Get-CimInstance -CimSession $Session -ClassName Win32_ComputerSystem        -ErrorAction SilentlyContinue
    $csp  = Get-CimInstance -CimSession $Session -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -CimSession $Session -ClassName Win32_BIOS                  -ErrorAction SilentlyContinue
    $encl = Get-CimInstance -CimSession $Session -ClassName Win32_SystemEnclosure       -ErrorAction SilentlyContinue
    $cpus = @(Get-CimInstance -CimSession $Session -ClassName Win32_Processor            -ErrorAction SilentlyContinue)

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

    # Per-module memory (spec 12)
    $memoryModules = @()
    foreach ($m in @(Get-CimInstance -CimSession $Session -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue)) {
        $memoryModules += [ordered]@{
            slot         = if ($m.DeviceLocator) { [string]$m.DeviceLocator } else { $null }
            capacityGB   = if ($m.Capacity)      { [math]::Round([double]$m.Capacity/1GB,1) } else { $null }
            speedMHz     = if ($m.Speed)         { [int]$m.Speed } else { $null }
            manufacturer = if ($m.Manufacturer)  { ([string]$m.Manufacturer).Trim() } else { $null }
            partNumber   = if ($m.PartNumber)    { ([string]$m.PartNumber).Trim() } else { $null }
            serial       = if ($m.SerialNumber)  { ([string]$m.SerialNumber).Trim() } else { $null }
        }
    }

    # Physical disks w/ serials, mapped to logical partitions via the two
    # association classes (2 extra queries total, no per-disk round trips).
    $logicalDisks = @(Get-CimInstance -CimSession $Session -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)
    $ldToPart     = @(Get-CimInstance -CimSession $Session -ClassName Win32_LogicalDiskToPartition -ErrorAction SilentlyContinue)
    $ddToPart     = @(Get-CimInstance -CimSession $Session -ClassName Win32_DiskDriveToDiskPartition -ErrorAction SilentlyContinue)

    # partition DeviceID -> physical disk DeviceID
    $partToDisk = @{}
    foreach ($a in $ddToPart) {
        try { $partToDisk[$a.Dependent.DeviceID] = $a.Antecedent.DeviceID } catch { }
    }
    # physical disk DeviceID -> [logical partition entries]
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
    foreach ($dd in @(Get-CimInstance -CimSession $Session -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue)) {
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
        # Fallback to the v1 logical-disk shape so the report is never empty.
        foreach ($ld in $logicalDisks) {
            $disks += [ordered]@{
                model  = [string]$ld.DeviceID
                serial = $null
                sizeGB = if ($ld.Size)      { [math]::Round([double]$ld.Size/1GB,1) }      else { 0 }
                freeGB = if ($ld.FreeSpace) { [math]::Round([double]$ld.FreeSpace/1GB,1) } else { 0 }
                mediaType = $null
                partitions = @()
            }
        }
    }

    # Network: every enabled adapter; primary = the one with a gateway.
    $adapters = @()
    $netCfgs = @(Get-CimInstance -CimSession $Session -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction SilentlyContinue)
    foreach ($n in $netCfgs) {
        $ip4  = if ($n.IPAddress) { @($n.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })[0] } else { $null }
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
    $vNic = 'vmware|vmnet|virtualbox|vbox|hyper-v|vethernet|host-only|loopback|tunnel|tap-windows|tap adapter|openvpn|wireguard|tailscale|zerotier|nordlynx|anyconnect|globalprotect|forticlient|sonicwall|wan miniport|ras async|bluetooth|wsl|virtual'
    $primaryAdapter = $adapters | Where-Object { $_.gateway -and ($_.name -notmatch $vNic) } | Select-Object -First 1
    if (-not $primaryAdapter) { $primaryAdapter = $adapters | Where-Object { $_.gateway } | Select-Object -First 1 }
    if (-not $primaryAdapter) { $primaryAdapter = $adapters | Select-Object -First 1 }

    # Installed software via remote registry (StdRegProv over CIM).
    # Parity with windows-collector.ps1: HKLM x64 + x86 views, every LOADED
    # user hive under HKEY_USERS (per-user installs of logged-in users), and
    # Appx / Microsoft Store packages read from their registry repositories
    # (Get-AppxPackage cannot run over a CIM session). Contract v2 fields.
    $software = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $HKLM = [uint32]2147483650
    $HKU  = [uint32]2147483651

    $regEnumKey = {
        param([uint32] $Hive, [string] $Path)
        $r = Invoke-CimMethod -CimSession $Session -Namespace 'root\default' -ClassName 'StdRegProv' `
               -MethodName 'EnumKey' -Arguments @{ hDefKey = $Hive; sSubKeyName = $Path } -ErrorAction SilentlyContinue
        if ($r -and $r.ReturnValue -eq 0 -and $r.sNames) { return @($r.sNames) } else { return @() }
    }
    $regGetStr = {
        param([uint32] $Hive, [string] $Path, [string] $Name)
        $r = Invoke-CimMethod -CimSession $Session -Namespace 'root\default' -ClassName 'StdRegProv' `
               -MethodName 'GetStringValue' -Arguments @{ hDefKey = $Hive; sSubKeyName = $Path; sValueName = $Name } -ErrorAction SilentlyContinue
        if ($r -and $r.ReturnValue -eq 0) { return $r.sValue } else { return $null }
    }
    $regGetDword = {
        param([uint32] $Hive, [string] $Path, [string] $Name)
        $r = Invoke-CimMethod -CimSession $Session -Namespace 'root\default' -ClassName 'StdRegProv' `
               -MethodName 'GetDWORDValue' -Arguments @{ hDefKey = $Hive; sSubKeyName = $Path; sValueName = $Name } -ErrorAction SilentlyContinue
        if ($r -and $r.ReturnValue -eq 0) { return $r.uValue } else { return $null }
    }

    $addUninstallRoot = {
        param([uint32] $Hive, [string] $Root, [string] $Arch)
        foreach ($k in (& $regEnumKey $Hive $Root)) {
            $keyPath = "$Root\$k"
            $name = & $regGetStr $Hive $keyPath 'DisplayName'
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $sysComp = & $regGetDword $Hive $keyPath 'SystemComponent'
            if ($sysComp -eq 1) { continue }
            $parent = & $regGetStr $Hive $keyPath 'ParentKeyName'
            if ($parent) { continue }
            $ver = & $regGetStr $Hive $keyPath 'DisplayVersion'
            if (-not $seen.Add("$name|$ver")) { continue }
            $software.Add([ordered]@{
                name            = [string]$name
                version         = if ($ver) { [string]$ver } else { $null }
                publisher       = & $regGetStr $Hive $keyPath 'Publisher'
                installDate     = ConvertFrom-RegistryInstallDate (& $regGetStr $Hive $keyPath 'InstallDate')
                installLocation = & $regGetStr $Hive $keyPath 'InstallLocation'
                architecture    = $Arch
                productCode     = [string]$k
                uninstallString = & $regGetStr $Hive $keyPath 'UninstallString'
            })
        }
    }

    # 1. Machine-wide 64-bit and 32-bit (redirected) views
    & $addUninstallRoot $HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' 'x64'
    & $addUninstallRoot $HKLM 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' 'x86'

    # 2. Per-user installs for every user hive currently loaded on the target
    $userSids = @()
    foreach ($sid in (& $regEnumKey $HKU '')) {
        if ($sid -eq '.DEFAULT' -or $sid -eq 'S-1-5-18' -or $sid -eq 'S-1-5-19' -or $sid -eq 'S-1-5-20' -or $sid -like '*_Classes') { continue }
        $userSids += $sid
        & $addUninstallRoot $HKU "$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" 'per-user'
    }

    # 3. Appx / Store packages from their registry repositories. Key name is the
    #    PackageFullName (Name_Version_Arch_ResourceId_PublisherId), so the
    #    identity is parsed from it - Get-AppxPackage is not available over CIM.
    $addAppxRoot = {
        param([uint32] $Hive, [string] $Root)
        foreach ($pkg in (& $regEnumKey $Hive $Root)) {
            $parts = $pkg -split '_'
            if ($parts.Count -lt 3) { continue }
            $pName = $parts[0]; $pVer = $parts[1]; $pArch = $parts[2]
            if ($pName -match '^Microsoft\.(VCLibs|NET\.|UI\.Xaml|Services\.Store|Advertising)') { continue }
            if (-not $seen.Add("$pName|$pVer")) { continue }
            $software.Add([ordered]@{
                name            = [string]$pName
                version         = [string]$pVer
                publisher       = $null
                installDate     = $null
                installLocation = $null
                architecture    = [string]$pArch
                productCode     = [string]$pkg
                uninstallString = $null
            })
        }
    }
    & $addAppxRoot $HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications'
    foreach ($sid in $userSids) {
        & $addAppxRoot $HKU "$sid\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
    }
    $software = @($software.ToArray())

    $hostName    = if ($cs -and $cs.Name) { $cs.Name } else { $Target }
    $currentUser = if ($cs -and $cs.UserName) { $cs.UserName } else { $null }

    return [ordered]@{
        reportedAt      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        contractVersion = 2
        hostname        = $hostName
        domain          = if ($cs) { $cs.Domain } else { $null }
        currentUser     = $currentUser
        os = [ordered]@{
            caption     = if ($os) { $os.Caption }        else { $null }
            version     = if ($os) { $os.Version }        else { $null }
            build       = if ($os) { [string]$os.BuildNumber } else { $null }
            arch        = if ($os) { $os.OSArchitecture }  else { $null }
            installDate = if ($os) { ConvertTo-IsoUtc $os.InstallDate }   else { $null }
            lastBoot    = if ($os) { ConvertTo-IsoUtc $os.LastBootUpTime } else { $null }
        }
        cpu = [ordered]@{
            model        = $cpuModel
            manufacturer = $cpuMfr
            cores        = $coreCount
            logical      = $logicalCount
            speedGHz     = $cpuGHz
        }
        ramGB          = $ramGB
        ramAvailableGB = $ramAvailGB
        memoryModules  = $memoryModules
        disks          = $disks
        bios = [ordered]@{
            vendor      = if ($bios -and $bios.Manufacturer)      { [string]$bios.Manufacturer } else { $null }
            version     = if ($bios -and $bios.SMBIOSBIOSVersion) { [string]$bios.SMBIOSBIOSVersion } else { $null }
            releaseDate = if ($bios) { ConvertTo-IsoUtc $bios.ReleaseDate } else { $null }
        }
        system  = [ordered]@{
            manufacturer = if ($cs)   { $cs.Manufacturer } else { $null }
            model        = if ($cs)   { $cs.Model }        else { $null }
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
        software = $software
        agent   = [ordered]@{ platform = 'windows-remote'; script = 'remote-collect.ps1' }
    }
}

# ---- Main loop -------------------------------------------------------------
$ok = 0; $fail = 0
Write-Host "Collecting from $($targets.Count) host(s) -> $uri`n"

foreach ($target in $targets) {
    $session = $null
    try {
        $session = New-TargetCimSession -Target $target -Cred $Credential -Proto $Protocol
        if (-not $session) {
            throw ("could not open a CIM session ($Protocol) to $target. " +
                   "Last error: $script:lastCimError. " +
                   "On the TARGET, enable remote management: run 'winrm quickconfig' " +
                   "(and allow WinRM through its firewall), or ensure DCOM/RPC (TCP 135 " +
                   "+ dynamic range) is reachable for the -Protocol Dcom fallback. " +
                   "Also confirm the -Credential is a local admin on the target.")
        }

        $specs = Get-RemoteSpecs -Session $session -Target $target
        $json  = $specs | ConvertTo-Json -Depth 8 -Compress

        $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $json -TimeoutSec 30
        if ($resp -and ($resp.status -eq $false)) {
            throw "server rejected report: $($resp.message) $($resp.error)"
        }
        Write-Host ("  [OK]   {0,-20} {1} apps" -f $target, $specs.software.Count) -ForegroundColor Green
        $ok++
    } catch {
        Write-Host ("  [FAIL] {0,-20} {1}" -f $target, $_.Exception.Message) -ForegroundColor Red
        $fail++
    } finally {
        if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

Write-Host "`nDone. Reported: $ok   Failed: $fail   Total: $($targets.Count)"
if ($fail -gt 0 -and $ok -eq 0) { exit 1 }
exit 0