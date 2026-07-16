#Requires -Version 5.1
<#
.SYNOPSIS
    PC Inspector - Portable Windows hardware inspection utility.

.DESCRIPTION
    Inspects every relevant hardware component of a Windows PC and presents
    the information needed to evaluate a computer (for example before buying
    a second-hand machine).

    Collects: System, CPU, Motherboard, RAM, Storage, GPU, Network, USB,
    PCI devices, Display, Battery, Audio and Sensors. Generates a health
    check (warnings) and an objective buyer analysis, plus JSON/TXT export.

    Design goals:
      - Windows 10 / Windows 11, PowerShell 5.1+ and PowerShell 7+.
      - Single portable script. No installation. No registry modifications.
      - No administrator rights required; privileged data degrades to
        "Unknown (requires Administrator)".
      - Never terminates unexpectedly; every query is guarded and unknown
        values are reported as "Unknown".

.PARAMETER Json
    Export the full report as JSON (also accepted as --json).

.PARAMETER Txt
    Export the full report as plain text (also accepted as --txt).

.PARAMETER OutputPath
    Directory where export files are written. Defaults to the script folder.

.PARAMETER NoColor
    Disable colored console output (also accepted as --nocolor).
    The NO_COLOR environment variable is honored as well.

.PARAMETER Ascii
    Use plain ASCII borders instead of Unicode box drawing (also --ascii).

.EXAMPLE
    .\PC-Inspector.ps1
    Run a full inspection with console output only.

.EXAMPLE
    .\PC-Inspector.ps1 -Json -Txt
    Run a full inspection and export JSON and TXT reports.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\PC-Inspector.ps1 --json
    GNU-style flags are accepted for convenience.

.NOTES
    Name    : PC Inspector
    Version : 1.0.0
    License : MIT
    Exit    : 0 on success, 1 on fatal failure.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Json,
    [switch]$Txt,
    [string]$OutputPath,
    [switch]$NoColor,
    [switch]$Ascii,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# ============================================================================
#  GNU-style argument compatibility (--json, --txt, --nocolor, --ascii)
# ============================================================================
foreach ($arg in @($ExtraArgs)) {
    if ([string]::IsNullOrWhiteSpace($arg)) { continue }
    switch -Regex ($arg) {
        '^--?json$'            { $Json = $true }
        '^--?txt$'             { $Txt = $true }
        '^--?no-?color$'       { $NoColor = $true }
        '^--?ascii$'           { $Ascii = $true }
        '^--?(help|\?)$'       { Get-Help -Detailed $MyInvocation.MyCommand.Path; exit 0 }
        default                { Write-Warning "Unknown argument ignored: $arg" }
    }
}

# ============================================================================
#  Script-wide state
# ============================================================================
$Script:Version    = '1.0.0'
$Script:NoColor    = [bool]($NoColor -or $env:NO_COLOR)
$Script:TxtBuffer  = New-Object System.Text.StringBuilder
$Script:Raw        = @{}            # machine-readable facts for health/analysis
$Script:IsCore     = $PSVersionTable.PSVersion.Major -ge 6
$Script:DriverIndex = $null         # lazy cache of Win32_PnPSignedDriver
$Script:ProgressId = 1

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# Box-drawing glyphs are built from char codes so the script file itself stays
# pure ASCII and can never be corrupted by file-encoding round trips.
if ($Ascii) {
    $Script:G = @{ TL = '+'; TR = '+'; BL = '+'; BR = '+'; H = '-'; V = '|'; Deg = ' deg' }
} else {
    $Script:G = @{
        TL  = [string][char]0x2554; TR = [string][char]0x2557
        BL  = [string][char]0x255A; BR = [string][char]0x255D
        H   = [string][char]0x2550; V  = [string][char]0x2551
        Deg = [string][char]0x00B0
    }
}

# ============================================================================
#  Core helpers
# ============================================================================

function Test-IsAdmin {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Invoke-Safe {
    <# Runs a script block; returns $Default on any failure. #>
    param([scriptblock]$Script, $Default = $null)
    try { & $Script } catch { $Default }
}

function Get-CimSafe {
    <# CIM query with WMI fallback. Returns $null on total failure. #>
    param(
        [Parameter(Mandatory)][string]$Class,
        [string]$Namespace = 'root/cimv2',
        [string]$Filter
    )
    try {
        $p = @{ ClassName = $Class; Namespace = $Namespace; ErrorAction = 'Stop' }
        if ($Filter) { $p.Filter = $Filter }
        return @(Get-CimInstance @p)
    } catch {
        try {
            if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
                $p = @{ Class = $Class; Namespace = $Namespace; ErrorAction = 'Stop' }
                if ($Filter) { $p.Filter = $Filter }
                return @(Get-WmiObject @p)
            }
        } catch { }
        return $null
    }
}

function Get-PropValue {
    <# First non-empty value among candidate property names. Null-safe. #>
    param($Object, [string[]]$Names)
    if ($null -eq $Object) { return $null }
    foreach ($n in $Names) {
        try {
            $prop = $Object.PSObject.Properties[$n]
            if ($null -ne $prop -and $null -ne $prop.Value -and "$($prop.Value)".Trim() -ne '') {
                return $prop.Value
            }
        } catch { }
    }
    return $null
}

function Format-Value {
    <# Converts any raw value into a trustworthy display string. #>
    param($Value, [string]$Unit = '')
    if ($null -eq $Value) { return 'Unknown' }
    $s = "$Value".Trim()
    if ($s -eq '') { return 'Unknown' }
    # Common OEM placeholder junk found in SMBIOS tables.
    $junk = '^(To Be Filled.*|System Serial Number|System Product Name|System manufacturer|' +
            'Default string|Default_string|O\.?E\.?M\.?|OEM.*|Not Specified|Not Available|' +
            'Not Applicable|None|Unknown|Undefined|empty|N/?A|0{6,}|1234567890?|InsydeH2O Version)$'
    if ($s -match $junk) { return 'Unknown' }
    if ($Unit) { return "$s $Unit" }
    return $s
}

function Format-Bytes {
    param($Bytes)
    try {
        $b = [double]$Bytes
        if ($b -le 0) { return 'Unknown' }
        if ($b -ge 1TB) { return ('{0:N2} TB' -f ($b / 1TB)) }
        if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) }
        if ($b -ge 1MB) { return ('{0:N0} MB' -f ($b / 1MB)) }
        return ('{0:N0} KB' -f ($b / 1KB))
    } catch { return 'Unknown' }
}

function ConvertTo-DateTimeSafe {
    <# Accepts DateTime or DMTF strings (WMI fallback path). #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    try { return [Management.ManagementDateTimeConverter]::ToDateTime("$Value") } catch { }
    try { return [datetime]$Value } catch { }
    return $null
}

function Format-Date {
    param($Value)
    $dt = ConvertTo-DateTimeSafe $Value
    if ($null -eq $dt) { return 'Unknown' }
    return $dt.ToString('yyyy-MM-dd')
}

function Format-Uptime {
    param([timespan]$Span)
    try {
        return ('{0}d {1}h {2}m' -f [int]$Span.Days, $Span.Hours, $Span.Minutes)
    } catch { return 'Unknown' }
}

function Get-Ordinal {
    param([int]$n)
    $suffix = 'th'
    if (($n % 100) -lt 11 -or ($n % 100) -gt 13) {
        switch ($n % 10) { 1 { $suffix = 'st' } 2 { $suffix = 'nd' } 3 { $suffix = 'rd' } }
    }
    return "$n$suffix"
}

# ============================================================================
#  Console/TXT output pipeline
#  Every visible line flows through Out-Line, which mirrors it into the TXT
#  export buffer - console and TXT reports can never drift apart.
# ============================================================================

function Out-Line {
    param([string]$Text = '', [ConsoleColor]$Color = [ConsoleColor]::Gray)
    [void]$Script:TxtBuffer.AppendLine($Text)
    if ($Script:NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}

function Get-ValueColor {
    param([string]$Value)
    if ($Value -match '^(Unknown|Not available|Not detected|None detected|Not present)') { return [ConsoleColor]::DarkGray }
    if ($Value -match '^(Healthy|OK\b|Good|Enabled|Supported|Yes\b|Licensed|Activated|Active|Up\b|Compatible|Meets)') { return [ConsoleColor]::Green }
    if ($Value -match '^(Warning|Degraded|Suspended|Notification|Grace)') { return [ConsoleColor]::Yellow }
    if ($Value -match '^(Critical|Unhealthy|Failure|Failed|Not activated|Unlicensed|Disabled|Does not meet)') { return [ConsoleColor]::Red }
    return [ConsoleColor]::White
}

function Out-KV {
    param([string]$Label, $Value, [int]$Indent = 2)
    $display = Format-Value $Value
    $pad     = [Math]::Max(28 - $Indent, 10)
    $prefix  = (' ' * $Indent) + $Label.PadRight($pad) + ' '
    [void]$Script:TxtBuffer.AppendLine($prefix + $display)
    if ($Script:NoColor) {
        Write-Host ($prefix + $display)
    } else {
        Write-Host $prefix -NoNewline -ForegroundColor DarkGray
        Write-Host $display -ForegroundColor (Get-ValueColor $display)
    }
}

function Out-SectionHeader {
    param([string]$Title)
    $inner = 76
    Out-Line ''
    Out-Line ($Script:G.TL + ($Script:G.H * $inner) + $Script:G.TR) DarkCyan
    $text = ('  ' + $Title.ToUpperInvariant())
    if ($text.Length -gt $inner) { $text = $text.Substring(0, $inner) }
    Out-Line ($Script:G.V + $text.PadRight($inner) + $Script:G.V) Cyan
    Out-Line ($Script:G.BL + ($Script:G.H * $inner) + $Script:G.BR) DarkCyan
}

function Get-SingularLabel {
    param([string]$Key)
    $map = @{
        'Modules' = 'Module'; 'Disks' = 'Disk'; 'Volumes' = 'Volume'; 'GPUs' = 'GPU'
        'Adapters' = 'Adapter'; 'Controllers' = 'Controller'; 'Devices' = 'Device'
        'Monitors' = 'Monitor'; 'Thermal Zones' = 'Thermal Zone'; 'Fans' = 'Fan'
        'Batteries' = 'Battery'; 'Checks' = 'Check'
    }
    if ($map.ContainsKey($Key)) { return $map[$Key] }
    return $Key.TrimEnd('s')
}

function Write-KVBlock {
    <# Generic renderer for a section's ordered dictionary. #>
    param($Data, [int]$Indent = 2)
    if ($null -eq $Data) { return }
    foreach ($key in @($Data.Keys)) {
        $val = $Data[$key]
        if ($val -is [System.Collections.IDictionary]) {
            Out-Line ((' ' * $Indent) + $key) Yellow
            Write-KVBlock $val ($Indent + 2)
        }
        elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
            $items = @($val)
            if ($items.Count -eq 0) {
                Out-KV $key 'None detected' $Indent
            }
            elseif ($items[0] -is [System.Collections.IDictionary]) {
                $label = Get-SingularLabel $key
                for ($i = 0; $i -lt $items.Count; $i++) {
                    Out-Line ''
                    Out-Line ((' ' * $Indent) + $label + ' ' + ($i + 1)) Yellow
                    Write-KVBlock $items[$i] ($Indent + 2)
                }
            }
            else {
                Out-KV $key (@($items | ForEach-Object { "$_" }) -join ', ') $Indent
            }
        }
        else {
            Out-KV $key $val $Indent
        }
    }
}

# ============================================================================
#  Lazy shared caches
# ============================================================================

function Get-DriverIndex {
    <# One-time Win32_PnPSignedDriver snapshot indexed by device id. #>
    if ($null -ne $Script:DriverIndex) { return $Script:DriverIndex }
    $index = @{}
    $drivers = Get-CimSafe 'Win32_PnPSignedDriver'
    foreach ($d in @($drivers)) {
        $id = Get-PropValue $d @('DeviceID')
        if ($id) { $index[$id.ToUpperInvariant()] = $d }
    }
    $Script:DriverIndex = $index
    return $index
}

function Get-DriverInfoFor {
    param([string]$PnpDeviceId)
    $result = @{ Version = $null; Date = $null; Provider = $null }
    if (-not $PnpDeviceId) { return $result }
    $idx = Get-DriverIndex
    $d = $idx[$PnpDeviceId.ToUpperInvariant()]
    if ($d) {
        $result.Version  = Get-PropValue $d @('DriverVersion')
        $result.Date     = ConvertTo-DateTimeSafe (Get-PropValue $d @('DriverDate'))
        $result.Provider = Get-PropValue $d @('DriverProviderName')
    }
    return $result
}

# ============================================================================
#  SECTION COLLECTORS
# ============================================================================

function Get-SecureBootState {
    # Confirm-SecureBootUEFI needs admin; the registry mirror does not.
    $viaCmdlet = Invoke-Safe { if (Confirm-SecureBootUEFI) { 'Enabled' } else { 'Disabled' } }
    if ($viaCmdlet) { return $viaCmdlet }
    $reg = Invoke-Safe {
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop).UEFISecureBootEnabled
    }
    if ($reg -eq 1) { return 'Enabled' }
    if ($reg -eq 0) { return 'Disabled' }
    return 'Not available (Legacy BIOS or unsupported)'
}

function Get-FirmwareMode {
    $type = Invoke-Safe {
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction Stop).PEFirmwareType
    }
    if ($type -eq 2) { return 'UEFI' }
    if ($type -eq 1) { return 'Legacy BIOS' }
    if (Invoke-Safe { Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' } $false) { return 'UEFI' }
    return 'Unknown'
}

function Get-TpmInfo {
    # Preferred: Win32_Tpm (usually admin-only). Fallback: PnP device name.
    $tpm = Get-CimSafe 'Win32_Tpm' 'root/cimv2/Security/MicrosoftTpm'
    if ($tpm) {
        $t = @($tpm)[0]
        $ver = Get-PropValue $t @('SpecVersion')
        if ($ver) {
            $major = ("$ver" -split ',')[0].Trim()
            $enabled = Get-PropValue $t @('IsEnabled_InitialValue')
            $state = 'present'
            if ($enabled -eq $true) { $state = 'enabled' } elseif ($enabled -eq $false) { $state = 'disabled' }
            return "$major ($state)"
        }
    }
    $pnp = Get-CimSafe 'Win32_PnPEntity' -Filter "PNPClass='SecurityDevices'"
    foreach ($d in @($pnp)) {
        $name = Get-PropValue $d @('Name')
        if ($name -match 'Trusted Platform Module\s+([\d\.]+)') { return "$($Matches[1]) (present)" }
    }
    if (Invoke-Safe { Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM' } $false) {
        return 'Present (version unknown; run as Administrator for details)'
    }
    return 'Not detected'
}

function Get-BitLockerState {
    # Get-BitLockerVolume needs admin; the Shell COM property does not.
    $sysDrive = $env:SystemDrive
    if (-not $sysDrive) { $sysDrive = 'C:' }
    $bl = Invoke-Safe {
        $v = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
        "$($v.ProtectionStatus) ($($v.VolumeStatus), $($v.EncryptionPercentage)% encrypted)"
    }
    if ($bl) { return ($bl -replace '^On\b', 'Enabled' -replace '^Off\b', 'Disabled') }
    $com = Invoke-Safe {
        $shell = New-Object -ComObject Shell.Application
        $shell.NameSpace($sysDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
    }
    switch ($com) {
        1 { return "Enabled (system drive $sysDrive)" }
        2 { return "Disabled (system drive $sysDrive)" }
        3 { return 'Encryption in progress' }
        4 { return 'Decryption in progress' }
        5 { return 'Suspended' }
        6 { return 'Enabled (locked)' }
        0 { return 'Off (BitLocker not in use or not available on this volume)' }
    }
    return 'Unknown (requires Administrator)'
}

function Get-ActivationStatus {
    $lic = Get-CimSafe 'SoftwareLicensingProduct' -Filter (
        "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'")
    foreach ($l in @($lic)) {
        $status = Get-PropValue $l @('LicenseStatus')
        switch ([int]$status) {
            1 { return 'Activated' }
            2 { return 'Grace period (OOB)' }
            3 { return 'Grace period (OOT)' }
            4 { return 'Grace period (non-genuine)' }
            5 { return 'Notification (not activated)' }
            6 { return 'Grace period (extended)' }
            0 { return 'Not activated' }
        }
    }
    return 'Unknown'
}

function Test-Win11Compatibility {
    param($Os, $Cpu, [double]$RamGB, [double]$SysDiskGB)
    $checks = [ordered]@{}
    $build = 0
    [void][int]::TryParse((Get-PropValue $Os @('BuildNumber')), [ref]$build)
    if ($build -ge 22000) {
        $Script:Raw.Win11Verdict = 'AlreadyWin11'
        return [ordered]@{ 'Verdict' = 'Already running Windows 11' }
    }
    $tpmOk  = $Script:Raw.TpmVersion -match '^2\.'
    $uefiOk = $Script:Raw.FirmwareMode -eq 'UEFI'
    $sbKnown = $Script:Raw.SecureBoot -match '^(Enabled|Disabled)$'
    $cores  = 0; [void][int]::TryParse("$(Get-PropValue $Cpu @('NumberOfCores'))", [ref]$cores)
    $mhz    = 0; [void][int]::TryParse("$(Get-PropValue $Cpu @('MaxClockSpeed'))", [ref]$mhz)
    $arch64 = (Get-PropValue $Os @('OSArchitecture')) -match '64'

    $checks['TPM 2.0']            = if ($tpmOk) { 'Pass' } elseif ($Script:Raw.TpmVersion -match '^\d') { "Fail ($($Script:Raw.TpmVersion))" } else { 'Unknown' }
    $checks['UEFI firmware']      = if ($uefiOk) { 'Pass' } elseif ($Script:Raw.FirmwareMode -eq 'Legacy BIOS') { 'Fail (Legacy BIOS)' } else { 'Unknown' }
    $checks['Secure Boot capable'] = if ($sbKnown) { 'Pass' } else { 'Unknown' }
    $checks['CPU (2+ cores, 1+ GHz)'] = if ($cores -ge 2 -and $mhz -ge 1000) { 'Pass' } elseif ($cores -gt 0) { 'Fail' } else { 'Unknown' }
    $checks['64-bit capable']     = if ($arch64) { 'Pass' } else { 'Fail (32-bit OS)' }
    $checks['RAM (4+ GB)']        = if ($RamGB -ge 4) { 'Pass' } elseif ($RamGB -gt 0) { "Fail ($([Math]::Round($RamGB,1)) GB)" } else { 'Unknown' }
    $checks['Storage (64+ GB)']   = if ($SysDiskGB -ge 64) { 'Pass' } elseif ($SysDiskGB -gt 0) { 'Fail' } else { 'Unknown' }

    $vals = @($checks.Values)
    $fails    = @($vals | Where-Object { $_ -like 'Fail*' })
    $unknowns = @($vals | Where-Object { $_ -eq 'Unknown' })
    if ($fails.Count -gt 0) {
        $checks['Verdict'] = "Does not meet baseline requirements ($($fails.Count) check(s) failed)"
        $Script:Raw.Win11Verdict = 'Fail'
    } elseif ($unknowns.Count -gt 0) {
        $checks['Verdict'] = 'Undetermined (some checks need Administrator rights)'
        $Script:Raw.Win11Verdict = 'Unknown'
    } else {
        $checks['Verdict'] = 'Meets baseline requirements (CPU model list not evaluated)'
        $Script:Raw.Win11Verdict = 'Pass'
    }
    return $checks
}

function Get-SystemInfo {
    $cs   = @(Get-CimSafe 'Win32_ComputerSystem')[0]
    $csp  = @(Get-CimSafe 'Win32_ComputerSystemProduct')[0]
    $os   = @(Get-CimSafe 'Win32_OperatingSystem')[0]
    $bios = @(Get-CimSafe 'Win32_BIOS')[0]
    $cpu  = @(Get-CimSafe 'Win32_Processor')[0]

    $ntCV = Invoke-Safe { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop }
    $displayVersion = Get-PropValue $ntCV @('DisplayVersion', 'ReleaseId')
    $build = Get-PropValue $os @('BuildNumber')
    $ubr   = Get-PropValue $ntCV @('UBR')
    $buildFull = $build
    if ($build -and $null -ne $ubr) { $buildFull = "$build.$ubr" }

    $boot = ConvertTo-DateTimeSafe (Get-PropValue $os @('LastBootUpTime'))
    $uptime = 'Unknown'
    if ($boot) { $uptime = Format-Uptime ((Get-Date) - $boot) }

    $Script:Raw.SecureBoot   = Get-SecureBootState
    $Script:Raw.FirmwareMode = Get-FirmwareMode
    $Script:Raw.TpmVersion   = Get-TpmInfo
    $Script:Raw.Activation   = Get-ActivationStatus
    $Script:Raw.OsCaption    = Get-PropValue $os @('Caption')
    $Script:Raw.OsBuild      = $build

    $totalRamGB = 0
    $ramBytes = Get-PropValue $cs @('TotalPhysicalMemory')
    if ($ramBytes) { $totalRamGB = [Math]::Round([double]$ramBytes / 1GB, 1) }
    $sysDiskGB = 0
    $sysVol = Get-CimSafe 'Win32_LogicalDisk' -Filter "DeviceID='$($env:SystemDrive)'"
    if ($sysVol) {
        $size = Get-PropValue @($sysVol)[0] @('Size')
        if ($size) { $sysDiskGB = [double]$size / 1GB }
        $free = Get-PropValue @($sysVol)[0] @('FreeSpace')
        if ($size -and $free) {
            $Script:Raw.SysFreeGB  = [Math]::Round([double]$free / 1GB, 1)
            $Script:Raw.SysFreePct = [Math]::Round(100.0 * [double]$free / [double]$size, 1)
        }
    }

    $user = $env:USERNAME
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { $user = "$($env:USERDOMAIN)\$user" }

    return [ordered]@{
        'Manufacturer'      = Format-Value (Get-PropValue $cs @('Manufacturer'))
        'Model'             = Format-Value (Get-PropValue $cs @('Model'))
        'Serial Number'     = Format-Value (Get-PropValue $bios @('SerialNumber'))
        'SKU'               = Format-Value (Get-PropValue $cs @('SystemSKUNumber'))
        'System Family'     = Format-Value (Get-PropValue $cs @('SystemFamily'))
        'UUID'              = Format-Value (Get-PropValue $csp @('UUID'))
        'Hostname'          = Format-Value $env:COMPUTERNAME
        'Current User'      = Format-Value $user
        'Windows Edition'   = Format-Value (Get-PropValue $os @('Caption'))
        'Version'           = Format-Value $displayVersion
        'Build'             = Format-Value $buildFull
        'Architecture'      = Format-Value (Get-PropValue $os @('OSArchitecture'))
        'Install Date'      = Format-Date (Get-PropValue $os @('InstallDate'))
        'Activation Status' = $Script:Raw.Activation
        'Uptime'            = $uptime
        'Last Boot'         = Format-Date (Get-PropValue $os @('LastBootUpTime'))
        'Firmware Mode'     = $Script:Raw.FirmwareMode
        'Secure Boot'       = $Script:Raw.SecureBoot
        'TPM Version'       = $Script:Raw.TpmVersion
        'BitLocker (system drive)' = Get-BitLockerState
        'Windows 11 Compatibility' = Test-Win11Compatibility $os $cpu $totalRamGB $sysDiskGB
    }
}

# ----------------------------------------------------------------------------

function Get-CpuGeneration {
    param([string]$Name)
    if (-not $Name) { return 'Unknown' }
    if ($Name -match 'Core\(TM\)\s+Ultra|Core\s+Ultra') {
        if ($Name -match 'Ultra\s+[3579]\s+(\d)\d{2}') { return "Intel Core Ultra (Series $($Matches[1]))" }
        return 'Intel Core Ultra'
    }
    if ($Name -match 'i[3579]-(\d{5})') { return ('Intel ' + (Get-Ordinal ([int]$Matches[1].Substring(0, 2))) + ' Gen (estimated)') }
    if ($Name -match 'i[3579]-(\d{4})')  { return ('Intel ' + (Get-Ordinal ([int]$Matches[1].Substring(0, 1))) + ' Gen (estimated)') }
    if ($Name -match 'i[3579]\s+CPU\s+\d{3}') { return 'Intel 1st Gen (estimated)' }
    if ($Name -match 'Ryzen\s+(?:[3579]|Threadripper)\s+(?:PRO\s+)?(\d)\d{3}') {
        $series = $Matches[1]
        $zen = @{ '1' = 'Zen'; '2' = 'Zen+'; '3' = 'Zen 2'; '4' = 'Zen 2/3'; '5' = 'Zen 3'; '6' = 'Zen 3+'; '7' = 'Zen 4'; '8' = 'Zen 4/5'; '9' = 'Zen 5' }
        $arch = $zen[$series]
        if ($arch) { return "AMD Ryzen $($series)000 series ($arch, estimated)" }
        return "AMD Ryzen $($series)000 series"
    }
    if ($Name -match 'Ryzen\s+AI')   { return 'AMD Ryzen AI series' }
    if ($Name -match 'EPYC')         { return 'AMD EPYC (server)' }
    if ($Name -match 'Xeon')         { return 'Intel Xeon (workstation/server)' }
    if ($Name -match 'Celeron|Pentium|Atom') { return 'Intel entry-level series' }
    if ($Name -match 'Snapdragon')   { return 'Qualcomm Snapdragon (ARM)' }
    return 'Unknown'
}

function Get-CpuFeatureSet {
    <#
        PowerShell 7+: .NET hardware intrinsics give exact answers.
        PowerShell 5.1: kernel32!IsProcessorFeaturePresent covers SSE/AVX
        (feature constants 36-41 require Windows 10 20H1+); AES-NI has no
        Win32 feature constant, so it reports Unknown on 5.1.
    #>
    $f = @{ SSE = $null; SSE2 = $null; SSE3 = $null; SSSE3 = $null; SSE41 = $null
            SSE42 = $null; AVX = $null; AVX2 = $null; AVX512 = $null; AES = $null }
    if ($Script:IsCore) {
        $probe = {
            param($TypeName)
            $t = $TypeName -as [type]
            if ($null -eq $t) { return $null }
            try { return [bool]$t::IsSupported } catch { return $null }
        }
        $f.SSE    = & $probe 'System.Runtime.Intrinsics.X86.Sse'
        $f.SSE2   = & $probe 'System.Runtime.Intrinsics.X86.Sse2'
        $f.SSE3   = & $probe 'System.Runtime.Intrinsics.X86.Sse3'
        $f.SSSE3  = & $probe 'System.Runtime.Intrinsics.X86.Ssse3'
        $f.SSE41  = & $probe 'System.Runtime.Intrinsics.X86.Sse41'
        $f.SSE42  = & $probe 'System.Runtime.Intrinsics.X86.Sse42'
        $f.AVX    = & $probe 'System.Runtime.Intrinsics.X86.Avx'
        $f.AVX2   = & $probe 'System.Runtime.Intrinsics.X86.Avx2'
        $f.AVX512 = & $probe 'System.Runtime.Intrinsics.X86.Avx512F'
        $f.AES    = & $probe 'System.Runtime.Intrinsics.X86.Aes'
    } else {
        $native = Invoke-Safe {
            Add-Type -Namespace PCInspector -Name Native -MemberDefinition @'
[DllImport("kernel32.dll")]
public static extern bool IsProcessorFeaturePresent(int ProcessorFeature);
'@ -PassThru -ErrorAction Stop
        }
        if ($native) {
            $probe = { param($id) Invoke-Safe { [PCInspector.Native]::IsProcessorFeaturePresent($id) } }
            $f.SSE   = & $probe 6
            $f.SSE2  = & $probe 10
            $f.SSE3  = & $probe 13
            $f.SSSE3 = & $probe 36
            $f.SSE41 = & $probe 37
            $f.SSE42 = & $probe 38
            $f.AVX   = & $probe 39
            $f.AVX2  = & $probe 40
            $f.AVX512 = & $probe 41
        }
    }
    return $f
}

function Format-Support {
    param($Flag, [string]$UnknownText = 'Unknown')
    if ($Flag -eq $true) { return 'Supported' }
    if ($Flag -eq $false) { return 'Not supported' }
    return $UnknownText
}

function Get-MicrocodeRevision {
    # Read directly (no helper) so the byte[] type survives - returning an
    # array through a function unrolls it into object[] in PowerShell.
    $bytes = $null
    try {
        $props = Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop
        $bytes = $props.'Update Revision'
        if ($null -eq $bytes) { $bytes = $props.'Update Signature' }
    } catch { }
    try {
        # Intel stores an 8-byte value (revision in the high dword);
        # AMD typically stores a 4-byte revision.
        if ($bytes -is [byte[]] -and $bytes.Length -ge 8) {
            $value = [BitConverter]::ToUInt64($bytes, 0)
            $hi = [uint32]($value -shr 32)
            $lo = [uint32]($value -band 0xFFFFFFFF)
            if ($hi -ne 0) { return ('0x{0:X}' -f $hi) }
            if ($lo -ne 0) { return ('0x{0:X}' -f $lo) }
        }
        elseif ($bytes -is [byte[]] -and $bytes.Length -ge 4) {
            $lo = [BitConverter]::ToUInt32($bytes, 0)
            if ($lo -ne 0) { return ('0x{0:X}' -f $lo) }
        }
    } catch { }
    return 'Unknown'
}

function Get-CpuInfo {
    $cpu = @(Get-CimSafe 'Win32_Processor')[0]
    if ($null -eq $cpu) { return [ordered]@{ 'Status' = 'Unknown (CPU query failed)' } }

    $archMap = @{ 0 = 'x86'; 1 = 'MIPS'; 2 = 'Alpha'; 3 = 'PowerPC'; 5 = 'ARM'; 6 = 'ia64'; 9 = 'x64'; 12 = 'ARM64' }
    $archVal = Get-PropValue $cpu @('Architecture')
    $arch = 'Unknown'
    if ($null -ne $archVal -and $archMap.ContainsKey([int]$archVal)) { $arch = $archMap[[int]$archVal] }

    $name = Format-Value (Get-PropValue $cpu @('Name'))
    $cores = Get-PropValue $cpu @('NumberOfCores')
    $threads = Get-PropValue $cpu @('NumberOfLogicalProcessors', 'ThreadCount')
    $maxMhz = Get-PropValue $cpu @('MaxClockSpeed')
    $curMhz = Get-PropValue $cpu @('CurrentClockSpeed')

    $Script:Raw.CpuName = $name
    if ($cores) { $Script:Raw.CpuCores = [int]$cores }

    # L1 is only exposed through Win32_CacheMemory (CacheType/Level vary by
    # vendor, so classify by Purpose first, then Level).
    $l1 = $null; $l2 = $null; $l3 = $null
    foreach ($c in @(Get-CimSafe 'Win32_CacheMemory')) {
        $purpose = "$(Get-PropValue $c @('Purpose'))"
        $size = Get-PropValue $c @('InstalledSize')  # KB
        if ($null -eq $size) { continue }
        if ($purpose -match 'L1' -or (Get-PropValue $c @('Level')) -eq 3) { $l1 = [double]$l1 + [double]$size }
        elseif ($purpose -match 'L2' -or (Get-PropValue $c @('Level')) -eq 4) { $l2 = [double]$l2 + [double]$size }
        elseif ($purpose -match 'L3' -or (Get-PropValue $c @('Level')) -eq 5) { $l3 = [double]$l3 + [double]$size }
    }
    if ($null -eq $l2) { $l2 = Get-PropValue $cpu @('L2CacheSize') }
    if ($null -eq $l3) { $l3 = Get-PropValue $cpu @('L3CacheSize') }
    $fmtCache = {
        param($kb)
        if ($null -eq $kb -or [double]$kb -le 0) { return 'Unknown' }
        $v = [double]$kb
        if ($v -ge 1024) { return ('{0:N1} MB' -f ($v / 1024)) }
        return ('{0:N0} KB' -f $v)
    }

    $virt = Get-PropValue $cpu @('VirtualizationFirmwareEnabled')
    $slat = Get-PropValue $cpu @('SecondLevelAddressTranslationExtensions')
    $vmx  = Get-PropValue $cpu @('VMMonitorModeExtensions')
    # If Hyper-V is running, the hypervisor hides the firmware flag; detect it.
    $cs = @(Get-CimSafe 'Win32_ComputerSystem')[0]
    $hvPresent = Get-PropValue $cs @('HypervisorPresent')
    $virtDisplay = 'Unknown'
    if ($virt -eq $true) { $virtDisplay = 'Enabled in firmware' }
    elseif ($hvPresent -eq $true) { $virtDisplay = 'Enabled (hypervisor running)' }
    elseif ($virt -eq $false) { $virtDisplay = 'Disabled in firmware' }
    $Script:Raw.VirtEnabled = ($virt -eq $true -or $hvPresent -eq $true)
    if ($virt -ne $false -and $virt -ne $true -and $hvPresent -ne $true) { $Script:Raw.VirtEnabled = $null }

    # WMI reports SLAT/VMX as False on many modern systems where Hyper-V or
    # core isolation masks the CPU flags; treat False as unreliable when
    # virtualization is known to be on.
    $maskedNote = 'Unknown'
    if ($Script:Raw.VirtEnabled -eq $true) {
        $maskedNote = 'Not reported (often masked when Hyper-V/core isolation is active)'
        if ($slat -eq $false) { $slat = $null }
        if ($vmx -eq $false)  { $vmx = $null }
    }

    $features = Get-CpuFeatureSet
    $sseList = [System.Collections.Generic.List[string]]::new()
    if ($features.SSE   -eq $true) { $sseList.Add('SSE') }
    if ($features.SSE2  -eq $true) { $sseList.Add('SSE2') }
    if ($features.SSE3  -eq $true) { $sseList.Add('SSE3') }
    if ($features.SSSE3 -eq $true) { $sseList.Add('SSSE3') }
    if ($features.SSE41 -eq $true) { $sseList.Add('SSE4.1') }
    if ($features.SSE42 -eq $true) { $sseList.Add('SSE4.2') }
    $sse = 'Unknown'
    if ($sseList.Count -gt 0) { $sse = $sseList -join ', ' }

    $aesUnknown = 'Unknown'
    if (-not $Script:IsCore) { $aesUnknown = 'Unknown (not detectable on PowerShell 5.1)' }

    return [ordered]@{
        'Manufacturer'      = Format-Value (Get-PropValue $cpu @('Manufacturer'))
        'Model'             = $name
        'Generation'        = Get-CpuGeneration $name
        'Architecture'      = $arch
        'Socket'            = Format-Value (Get-PropValue $cpu @('SocketDesignation'))
        'Family/Stepping'   = Format-Value (Get-PropValue $cpu @('Description', 'Caption'))
        'Cores'             = Format-Value $cores
        'Threads'           = Format-Value $threads
        'Base Clock'        = Format-Value $maxMhz 'MHz (nominal)'
        'Current Clock'     = Format-Value $curMhz 'MHz'
        'Max Boost Clock'   = 'Unknown (turbo limits are not exposed via WMI)'
        'L1 Cache (total)'  = & $fmtCache $l1
        'L2 Cache (total)'  = & $fmtCache $l2
        'L3 Cache'          = & $fmtCache $l3
        'TDP'               = 'Unknown (not exposed via WMI)'
        'Virtualization'    = $virtDisplay
        'SLAT'              = Format-Support $slat $maskedNote
        'VMX/SVM Extensions' = Format-Support $vmx $maskedNote
        'AES-NI'            = Format-Support $features.AES $aesUnknown
        'AVX'               = Format-Support $features.AVX
        'AVX2'              = Format-Support $features.AVX2
        'AVX-512'           = Format-Support $features.AVX512
        'SSE Versions'      = $sse
        'Microcode Revision' = Get-MicrocodeRevision
    }
}

# ----------------------------------------------------------------------------

function Get-ChipsetGuess {
    param([string]$BoardProduct, [string]$BoardManufacturer)
    $text = "$BoardProduct $BoardManufacturer"
    # Recognized chipset tokens commonly embedded in board product strings.
    if ($text -match '\b([XZBHQW]\d{3}[A-Z]?[EMI]?)\b') { return "$($Matches[1]) (from board model)" }
    if ($text -match '\b([AXB]\d{2}0[EM]?)\b')          { return "$($Matches[1]) (from board model)" }
    if ($text -match '\b(TRX\d0|WRX\d0)\b')             { return "$($Matches[1]) (from board model)" }
    return 'Unknown (not exposed via WMI)'
}

function Get-MotherboardInfo {
    $board = @(Get-CimSafe 'Win32_BaseBoard')[0]
    $bios  = @(Get-CimSafe 'Win32_BIOS')[0]

    $biosDate = ConvertTo-DateTimeSafe (Get-PropValue $bios @('ReleaseDate'))
    if ($biosDate) { $Script:Raw.BiosDate = $biosDate }

    $product = "$(Get-PropValue $board @('Product'))"
    $maker   = "$(Get-PropValue $board @('Manufacturer'))"

    $smbios = Get-PropValue $bios @('SMBIOSBIOSVersion')
    $biosVer = Get-PropValue $bios @('Name', 'Version')
    $biosDisplay = Format-Value $smbios
    if ($biosVer -and "$biosVer" -ne "$smbios") { $biosDisplay = (Format-Value $smbios) + " ($biosVer)" }

    return [ordered]@{
        'Manufacturer'   = Format-Value $maker
        'Model'          = Format-Value $product
        'Version'        = Format-Value (Get-PropValue $board @('Version'))
        'Serial Number'  = Format-Value (Get-PropValue $board @('SerialNumber'))
        'Chipset'        = Get-ChipsetGuess $product $maker
        'BIOS Vendor'    = Format-Value (Get-PropValue $bios @('Manufacturer'))
        'BIOS Version'   = $biosDisplay
        'BIOS Date'      = Format-Date (Get-PropValue $bios @('ReleaseDate'))
        'SMBIOS Version' = Format-Value ("$(Get-PropValue $bios @('SMBIOSMajorVersion')).$(Get-PropValue $bios @('SMBIOSMinorVersion'))")
        'PCIe Generation' = 'Unknown (not exposed via WMI; check board specifications)'
    }
}

# ----------------------------------------------------------------------------

function Get-DdrGeneration {
    param($Module)
    $smbiosType = Get-PropValue $Module @('SMBIOSMemoryType')
    $memType    = Get-PropValue $Module @('MemoryType')
    $map = @{
        20 = 'DDR'; 21 = 'DDR2'; 22 = 'DDR2 FB-DIMM'; 24 = 'DDR3'; 26 = 'DDR4'
        27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5'
    }
    foreach ($candidate in @($smbiosType, $memType)) {
        if ($null -ne $candidate) {
            $key = [int]$candidate
            if ($map.ContainsKey($key)) { return $map[$key] }
        }
    }
    # Fall back to speed heuristics (JEDEC standard speed grades).
    $speed = Get-PropValue $Module @('Speed')
    if ($speed) {
        $s = [int]$speed
        if ($s -ge 4800) { return 'DDR5 (estimated from speed)' }
        if ($s -ge 2133) { return 'DDR4 (estimated from speed)' }
        if ($s -ge 1066) { return 'DDR3 (estimated from speed)' }
    }
    return 'Unknown'
}

function Get-RamInfo {
    $modules = @(Get-CimSafe 'Win32_PhysicalMemory')
    $array   = @(Get-CimSafe 'Win32_PhysicalMemoryArray' -Filter "Use=3")
    if ($array.Count -eq 0) { $array = @(Get-CimSafe 'Win32_PhysicalMemoryArray') }
    $arr = $null
    if ($array.Count -gt 0) { $arr = $array[0] }

    $slotCount = Get-PropValue $arr @('MemoryDevices')
    $maxKB = Get-PropValue $arr @('MaxCapacityEx')
    if ($null -eq $maxKB) { $maxKB = Get-PropValue $arr @('MaxCapacity') }
    $maxDisplay = 'Unknown'
    if ($maxKB) {
        $maxGB = [Math]::Round([double]$maxKB / 1MB, 0)   # KB -> GB
        $maxDisplay = "$maxGB GB (as reported by SMBIOS)"
        $Script:Raw.MaxRamGB = $maxGB
    }

    $eccMap = @{ 0 = 'Unknown'; 1 = 'Other'; 2 = 'None'; 3 = 'None'; 4 = 'Parity'; 5 = 'Single-bit ECC'; 6 = 'Multi-bit ECC'; 7 = 'CRC' }
    $eccVal = Get-PropValue $arr @('MemoryErrorCorrection')
    $ecc = 'Unknown'
    if ($null -ne $eccVal -and $eccMap.ContainsKey([int]$eccVal)) { $ecc = $eccMap[[int]$eccVal] }

    $totalBytes = 0.0
    $moduleList = [System.Collections.Generic.List[object]]::new()
    $channels   = [System.Collections.Generic.List[string]]::new()
    $minSpeed   = $null
    $ddrGen     = 'Unknown'

    foreach ($m in $modules) {
        $capacity = Get-PropValue $m @('Capacity')
        if ($capacity) { $totalBytes += [double]$capacity }

        $rankVal = Get-PropValue $m @('Attributes')
        $rank = 'Unknown'
        if ($rankVal) {
            switch ([int]$rankVal) { 1 { $rank = 'Single rank' } 2 { $rank = 'Dual rank' } 4 { $rank = 'Quad rank' } default { $rank = "$rankVal" } }
        }

        $totalWidth = Get-PropValue $m @('TotalWidth')
        $dataWidth  = Get-PropValue $m @('DataWidth')
        $modEcc = 'Unknown'
        if ($totalWidth -and $dataWidth) {
            if ([int]$totalWidth -gt [int]$dataWidth) { $modEcc = 'Yes (ECC module)' } else { $modEcc = 'No' }
        } elseif ($ecc -ne 'Unknown') {
            if ($ecc -match 'ECC') { $modEcc = 'Yes' } else { $modEcc = 'No' }
        }

        $voltage = Get-PropValue $m @('ConfiguredVoltage')
        $voltDisplay = 'Unknown'
        if ($voltage -and [double]$voltage -gt 0) { $voltDisplay = ('{0:N2} V' -f ([double]$voltage / 1000)) }

        $ffMap = @{ 0 = 'Unknown'; 1 = 'Other'; 2 = 'SIP'; 3 = 'DIP'; 4 = 'ZIP'; 5 = 'SOJ'; 6 = 'Proprietary'
                    7 = 'SIMM'; 8 = 'DIMM'; 9 = 'TSOP'; 10 = 'PGA'; 11 = 'RIMM'; 12 = 'SODIMM'; 13 = 'SRIMM'; 14 = 'SMD' }
        $ffVal = Get-PropValue $m @('FormFactor')
        $formFactor = 'Unknown'
        if ($null -ne $ffVal) {
            if ($ffMap.ContainsKey([int]$ffVal)) { $formFactor = $ffMap[[int]$ffVal] } else { $formFactor = "$ffVal" }
        }

        $gen = Get-DdrGeneration $m
        if ($gen -ne 'Unknown') { $ddrGen = $gen }

        $configured = Get-PropValue $m @('ConfiguredClockSpeed')
        if ($configured -and ($null -eq $minSpeed -or [int]$configured -lt $minSpeed)) { $minSpeed = [int]$configured }

        $bank = "$(Get-PropValue $m @('BankLabel'))"
        $loc  = "$(Get-PropValue $m @('DeviceLocator'))"
        foreach ($src in @($bank, $loc)) {
            if ($src -match 'Channel\s*-?\s*([A-H0-9])') {
                if (-not $channels.Contains($Matches[1])) { $channels.Add($Matches[1]) }
            }
        }

        $moduleList.Add([ordered]@{
            'Slot'             = Format-Value $loc
            'Bank'             = Format-Value $bank
            'Manufacturer'     = Format-Value (Get-PropValue $m @('Manufacturer'))
            'Part Number'      = Format-Value (Get-PropValue $m @('PartNumber'))
            'Serial Number'    = Format-Value (Get-PropValue $m @('SerialNumber'))
            'Capacity'         = Format-Bytes $capacity
            'Type'             = $gen
            'Rated Speed'      = Format-Value (Get-PropValue $m @('Speed')) 'MT/s'
            'Configured Speed' = Format-Value $configured 'MT/s'
            'Voltage'          = $voltDisplay
            'Rank'             = $rank
            'ECC'              = $modEcc
            'Form Factor'      = $formFactor
        })
    }

    $usedSlots = $modules.Count
    $slotsDisplay = 'Unknown'
    $freeDisplay = 'Unknown'
    if ($slotCount) {
        $free = [int]$slotCount - $usedSlots
        if ($free -lt 0) { $free = 0 }
        $slotsDisplay = "$slotCount"
        $freeDisplay = "$free"
        $Script:Raw.TotalSlots = [int]$slotCount
        $Script:Raw.FreeSlots  = $free
    }

    $channelDisplay = 'Unknown'
    if ($channels.Count -gt 1) { $channelDisplay = "$($channels.Count) channels detected (multi-channel)" }
    elseif ($channels.Count -eq 1 -and $usedSlots -eq 1) { $channelDisplay = 'Single channel' }
    elseif ($usedSlots -eq 1) { $channelDisplay = 'Single channel (one module installed)' }
    elseif ($usedSlots -ge 2) { $channelDisplay = 'Likely multi-channel (estimated from module count)' }

    $Script:Raw.RamGB = [Math]::Round($totalBytes / 1GB, 1)
    $Script:Raw.MemoryModules = $usedSlots
    $Script:Raw.RamSpeed = $minSpeed
    $Script:Raw.DdrGen = $ddrGen

    return [ordered]@{
        'Total Installed'      = Format-Bytes $totalBytes
        'Maximum Supported'    = $maxDisplay
        'Memory Type'          = $ddrGen
        'Error Correction'     = $ecc
        'Total Slots'          = $slotsDisplay
        'Used Slots'           = "$usedSlots"
        'Free Slots'           = $freeDisplay
        'Channel Configuration' = $channelDisplay
        'Modules'              = $moduleList
    }
}

# ----------------------------------------------------------------------------

function Get-TrimState {
    $out = Invoke-Safe { & "$env:SystemRoot\System32\fsutil.exe" behavior query DisableDeleteNotify 2>$null }
    if ($out) {
        $text = @($out) -join ' '
        if ($text -match 'NTFS\s+DisableDeleteNotify\s*=\s*0|DisableDeleteNotify\s*=\s*0') { return 'Enabled' }
        if ($text -match 'DisableDeleteNotify\s*=\s*1') { return 'Disabled' }
    }
    return 'Unknown (query requires Administrator on some systems)'
}

function Get-StorageInfo {
    $wmiDisks = @(Get-CimSafe 'Win32_DiskDrive')
    $physicalDisks = Invoke-Safe { @(Get-PhysicalDisk -ErrorAction Stop) } @()
    $getDisks      = Invoke-Safe { @(Get-Disk -ErrorAction Stop) } @()
    $reliability = @{}
    foreach ($pd in @($physicalDisks)) {
        $r = Invoke-Safe { $pd | Get-StorageReliabilityCounter -ErrorAction Stop }
        if ($r) { $reliability["$($pd.DeviceId)"] = $r }
    }
    $predict = @(Get-CimSafe 'MSStorageDriver_FailurePredictStatus' 'root/wmi')

    # System-drive disk number, used by the buyer analysis.
    $bootDiskNumber = Invoke-Safe {
        $letter = ($env:SystemDrive).TrimEnd(':')
        (Get-Partition -DriveLetter $letter -ErrorAction Stop).DiskNumber
    }

    $diskList = [System.Collections.Generic.List[object]]::new()
    $Script:Raw.HasSSD = $false
    $Script:Raw.HasNVMe = $false
    $Script:Raw.SmartIssues = [System.Collections.Generic.List[string]]::new()
    $Script:Raw.DiskTempMax = $null

    foreach ($d in $wmiDisks) {
        $index = Get-PropValue $d @('Index')
        $model = Format-Value (Get-PropValue $d @('Model'))
        $pd = $null
        foreach ($cand in @($physicalDisks)) {
            if ("$($cand.DeviceId)" -eq "$index") { $pd = $cand; break }
        }
        $gd = $null
        foreach ($cand in @($getDisks)) {
            if ("$($cand.Number)" -eq "$index") { $gd = $cand; break }
        }

        # --- classification -------------------------------------------------
        $busType = $null; $mediaType = $null; $spindle = $null; $health = $null
        if ($pd) {
            $busType   = Get-PropValue $pd @('BusType')
            $mediaType = Get-PropValue $pd @('MediaType')
            $spindle   = Get-PropValue $pd @('SpindleSpeed')
            $health    = Get-PropValue $pd @('HealthStatus')
        }
        if (-not $busType) { $busType = Get-PropValue $d @('InterfaceType') }

        $kind = 'Unknown'
        if ("$busType" -match 'NVMe') { $kind = 'NVMe SSD' }
        elseif ("$mediaType" -match 'SSD') { $kind = 'SSD' }
        elseif ("$mediaType" -match 'HDD') { $kind = 'HDD' }
        elseif ($null -ne $spindle -and [int64]$spindle -eq 0 -and "$mediaType" -notmatch 'Unspecified') { $kind = 'SSD' }
        elseif ($null -ne $spindle -and [int64]$spindle -gt 0) { $kind = 'HDD' }
        elseif ($model -match 'SSD|NVMe|M\.2') { $kind = 'SSD (estimated from model name)' }

        if ($kind -match 'SSD') { $Script:Raw.HasSSD = $true }
        if ($kind -match 'NVMe') { $Script:Raw.HasNVMe = $true }
        if ($null -ne $index -and "$index" -eq "$bootDiskNumber") { $Script:Raw.BootDiskType = $kind; $Script:Raw.BootDiskModel = $model }

        $rpm = 'Not applicable'
        if ($kind -match 'HDD') {
            if ($null -ne $spindle -and [int64]$spindle -gt 0) { $rpm = "$spindle RPM" } else { $rpm = 'Unknown' }
        }

        # --- SMART ----------------------------------------------------------
        $smart = Format-Value (Get-PropValue $d @('Status'))     # Win32_DiskDrive.Status ("OK")
        if ($health) { $smart = "$health" }
        $pnpId = "$(Get-PropValue $d @('PNPDeviceID'))"
        foreach ($p in @($predict)) {
            $inst = "$(Get-PropValue $p @('InstanceName'))" -replace '_\d+$', ''
            if ($pnpId -and $inst -and ($inst -ieq $pnpId)) {
                if ((Get-PropValue $p @('PredictFailure')) -eq $true) { $smart = 'Failure predicted (SMART)' }
            }
        }
        if ($smart -match 'Warning|Unhealthy|Failure|Pred Fail') {
            [void]$Script:Raw.SmartIssues.Add("$model : $smart")
        }

        # --- reliability counters -------------------------------------------
        $wear = $null; $poh = $null; $temp = $null
        $rc = $reliability["$index"]
        if ($rc) {
            $wear = Get-PropValue $rc @('Wear')
            $poh  = Get-PropValue $rc @('PowerOnHours')
            $temp = Get-PropValue $rc @('Temperature')
        }
        $privNote = 'Unknown'
        if (-not (Test-IsAdmin) -and $null -eq $rc) { $privNote = 'Unknown (requires Administrator)' }
        $lifeDisplay = $privNote
        if ($null -ne $wear) {
            $remaining = 100 - [int]$wear
            if ($remaining -lt 0) { $remaining = 0 }
            $lifeDisplay = "$remaining % remaining (wear: $wear %)"
        } elseif ($kind -match 'HDD') { $lifeDisplay = 'Not applicable (HDD)' }
        $pohDisplay = $privNote
        if ($null -ne $poh -and [double]$poh -gt 0) {
            $pohDisplay = ('{0:N0} hours ({1:N1} years powered on)' -f [double]$poh, ([double]$poh / 8760))
        }
        $tempDisplay = $privNote
        if ($null -ne $temp -and [double]$temp -gt 0) {
            $tempDisplay = "$temp $($Script:G.Deg)C"
            if ($null -eq $Script:Raw.DiskTempMax -or [double]$temp -gt $Script:Raw.DiskTempMax) { $Script:Raw.DiskTempMax = [double]$temp }
        }

        $health2 = 'Unknown'
        if ($smart -match '^(OK|Healthy)$') {
            if ($null -ne $wear) { $health2 = "Good ($(100 - [int]$wear)% life remaining)" } else { $health2 = 'Good (SMART reports healthy)' }
        } elseif ($smart -ne 'Unknown') { $health2 = "Check disk ($smart)" }

        # --- partitions / letters -------------------------------------------
        $letters = 'Unknown'
        $lettersList = Invoke-Safe {
            @(Get-Partition -DiskNumber ([int]$index) -ErrorAction Stop |
                Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter):" })
        } @()
        if (@($lettersList).Count -gt 0) { $letters = @($lettersList) -join ', ' }
        elseif ($null -eq $index) { $letters = 'Unknown' }
        else { $letters = 'None' }

        $partStyle = 'Unknown'
        if ($gd) { $partStyle = "$(Get-PropValue $gd @('PartitionStyle'))" }

        $diskList.Add([ordered]@{
            'Model'            = $model
            'Manufacturer'     = Format-Value (Get-PropValue $d @('Manufacturer'))
            'Type'             = $kind
            'Bus / Interface'  = Format-Value $busType
            'Capacity'         = Format-Bytes (Get-PropValue $d @('Size'))
            'Firmware'         = Format-Value (Get-PropValue $d @('FirmwareRevision'))
            'Serial Number'    = Format-Value ("$(Get-PropValue $d @('SerialNumber'))".Trim())
            'Partition Style'  = Format-Value $partStyle
            'Partitions'       = Format-Value (Get-PropValue $d @('Partitions'))
            'Drive Letters'    = $letters
            'Rotational Speed' = $rpm
            'SMART Status'     = Format-Value $smart
            'Estimated Health' = $health2
            'SSD Life Remaining' = $lifeDisplay
            'Power-On Hours'   = $pohDisplay
            'Temperature'      = $tempDisplay
        })
    }

    # --- volumes -------------------------------------------------------------
    $volumeList = [System.Collections.Generic.List[object]]::new()
    $volumes = @(Get-CimSafe 'Win32_LogicalDisk' -Filter 'DriveType=3')
    foreach ($v in $volumes) {
        $size = Get-PropValue $v @('Size')
        $free = Get-PropValue $v @('FreeSpace')
        $pct = 'Unknown'
        if ($size -and $null -ne $free -and [double]$size -gt 0) {
            $pct = ('{0:N1} %' -f (100.0 * [double]$free / [double]$size))
        }
        $volumeList.Add([ordered]@{
            'Drive'       = Format-Value (Get-PropValue $v @('DeviceID'))
            'Label'       = Format-Value (Get-PropValue $v @('VolumeName'))
            'File System' = Format-Value (Get-PropValue $v @('FileSystem'))
            'Capacity'    = Format-Bytes $size
            'Free Space'  = "$(Format-Bytes $free) ($pct free)"
        })
    }

    return [ordered]@{
        'Physical Disks' = "$($diskList.Count)"
        'TRIM'           = Get-TrimState
        'Disks'          = $diskList
        'Volumes'        = $volumeList
    }
}

# ----------------------------------------------------------------------------

function Get-GpuVram {
    param($Controller)
    # AdapterRAM is a 32-bit value (caps at 4 GB); the driver registry key
    # HardwareInformation.qwMemorySize is authoritative when present.
    $name = "$(Get-PropValue $Controller @('Name'))"
    $fromRegistry = $null
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    $keys = Invoke-Safe { @(Get-ChildItem $base -ErrorAction SilentlyContinue) } @()
    foreach ($key in @($keys)) {
        if ($key.PSChildName -notmatch '^\d{4}$') { continue }
        try {
            $props = Get-ItemProperty $key.PSPath -ErrorAction Stop
            if ($props -and "$($props.'DriverDesc')" -eq $name) {
                $qw = $props.'HardwareInformation.qwMemorySize'
                if ($qw -is [byte[]] -and $qw.Length -ge 8) { $qw = [BitConverter]::ToUInt64($qw, 0) }
                if ($qw -and [double]$qw -gt 0) { $fromRegistry = [double]$qw; break }
            }
        } catch { continue }
    }
    if ($fromRegistry) { return Format-Bytes $fromRegistry }
    $adapterRam = Get-PropValue $Controller @('AdapterRAM')
    if ($adapterRam -and [double]$adapterRam -gt 0) {
        $display = Format-Bytes ([double]$adapterRam)
        if ([double]$adapterRam -ge 4GB - 1MB) { $display += ' (may be capped by WMI; check vendor tool)' }
        return $display
    }
    return 'Unknown'
}

function Test-GpuIntegrated {
    param([string]$Name, [string]$Vendor)
    $text = "$Vendor $Name"
    if ($text -match 'NVIDIA') { return 'Dedicated' }
    if ($text -match 'Intel') {
        if ($Name -match '\bArc\b') { return 'Dedicated' }
        return 'Integrated'
    }
    if ($text -match 'AMD|ATI|Radeon') {
        if ($Name -match 'Radeon\(TM\)\s*(Vega\s*\d*\s*)?Graphics$|Radeon\s+Graphics$|Vega\s+\d+\s+Graphics') { return 'Integrated' }
        return 'Dedicated'
    }
    if ($text -match 'Qualcomm|Adreno') { return 'Integrated' }
    if ($text -match 'Microsoft Basic') { return 'Unknown (basic display driver active)' }
    return 'Unknown'
}

function Get-GpuInfo {
    $controllers = @(Get-CimSafe 'Win32_VideoController')
    if ($controllers.Count -eq 0) { return [ordered]@{ 'Status' = 'Unknown (GPU query failed)' } }

    $Script:Raw.GpuDriverDates = [System.Collections.Generic.List[object]]::new()
    $gpuList = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $controllers) {
        $name = Format-Value (Get-PropValue $g @('Name'))
        $vendor = Format-Value (Get-PropValue $g @('AdapterCompatibility'))
        $driverDate = ConvertTo-DateTimeSafe (Get-PropValue $g @('DriverDate'))
        if ($driverDate) { [void]$Script:Raw.GpuDriverDates.Add(@{ Name = $name; Date = $driverDate }) }

        $res = 'Unknown'
        $h = Get-PropValue $g @('CurrentHorizontalResolution')
        $v = Get-PropValue $g @('CurrentVerticalResolution')
        $r = Get-PropValue $g @('CurrentRefreshRate')
        if ($h -and $v) {
            $res = "$h x $v"
            if ($r) { $res += " @ $r Hz" }
        }

        $gpuList.Add([ordered]@{
            'Model'           = $name
            'Vendor'          = $vendor
            'Class'           = Test-GpuIntegrated $name $vendor
            'VRAM'            = Get-GpuVram $g
            'Driver Version'  = Format-Value (Get-PropValue $g @('DriverVersion'))
            'Driver Date'     = Format-Date (Get-PropValue $g @('DriverDate'))
            'Current Mode'    = $res
            'Video Processor' = Format-Value (Get-PropValue $g @('VideoProcessor'))
            'Status'          = Format-Value (Get-PropValue $g @('Status'))
        })
    }
    return [ordered]@{ 'GPUs' = $gpuList }
}

# ----------------------------------------------------------------------------

function Get-NetworkInfo {
    $netAdapters = Invoke-Safe { @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.HardwareInterface }) } $null
    $adapterList = [System.Collections.Generic.List[object]]::new()

    if ($netAdapters) {
        foreach ($a in $netAdapters) {
            $desc = "$(Get-PropValue $a @('InterfaceDescription'))"
            $media = "$(Get-PropValue $a @('PhysicalMediaType'))"
            $type = 'Ethernet'
            if ($media -match '802\.11|Native 802' -or $desc -match 'Wi-?Fi|Wireless|802\.11') { $type = 'Wi-Fi' }
            elseif ($media -match 'BlueTooth' -or $desc -match 'Bluetooth') { $type = 'Bluetooth (PAN)' }

            $ipv4 = 'Not assigned'; $ipv6 = 'Not assigned'; $gw = 'Not assigned'; $dns = 'Not assigned'
            $cfg = Invoke-Safe { Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction Stop }
            if ($cfg) {
                $v4 = @(@(Get-PropValue $cfg @('IPv4Address')) | ForEach-Object { Get-PropValue $_ @('IPAddress') } | Where-Object { $_ })
                $v6 = @(@(Get-PropValue $cfg @('IPv6Address')) | ForEach-Object { Get-PropValue $_ @('IPAddress') } | Where-Object { $_ })
                if ($v4.Count -gt 0) { $ipv4 = ($v4 -join ', ') }
                if ($v6.Count -gt 0) { $ipv6 = ($v6 -join ', ') }
                $gwObj = Get-PropValue $cfg @('IPv4DefaultGateway')
                if ($gwObj) { $gw = "$(Get-PropValue @($gwObj)[0] @('NextHop'))" }
                $dnsObj = Get-PropValue $cfg @('DNSServer')
                if ($dnsObj) {
                    $servers = @()
                    foreach ($srv in @($dnsObj)) { $servers += @(Get-PropValue $srv @('ServerAddresses')) }
                    $servers = @($servers | Where-Object { $_ })
                    if ($servers.Count -gt 0) { $dns = ($servers -join ', ') }
                }
            }

            $adapterList.Add([ordered]@{
                'Name'            = Format-Value (Get-PropValue $a @('Name'))
                'Description'     = Format-Value $desc
                'Type'            = $type
                'Status'          = Format-Value (Get-PropValue $a @('Status'))
                'MAC Address'     = Format-Value (Get-PropValue $a @('MacAddress'))
                'Link Speed'      = Format-Value (Get-PropValue $a @('LinkSpeed'))
                'Driver Version'  = Format-Value (Get-PropValue $a @('DriverVersionString', 'DriverVersion'))
                'Driver Date'     = Format-Date (Get-PropValue $a @('DriverDate'))
                'Driver Provider' = Format-Value (Get-PropValue $a @('DriverProvider'))
                'IPv4'            = $ipv4
                'IPv6'            = $ipv6
                'Gateway'         = $gw
                'DNS Servers'     = $dns
            })
        }
    } else {
        # Fallback: CIM only (Get-NetAdapter unavailable).
        foreach ($a in @(Get-CimSafe 'Win32_NetworkAdapter' -Filter 'PhysicalAdapter=TRUE')) {
            $desc = "$(Get-PropValue $a @('Name'))"
            $type = 'Ethernet'
            if ($desc -match 'Wi-?Fi|Wireless|802\.11') { $type = 'Wi-Fi' }
            elseif ($desc -match 'Bluetooth') { $type = 'Bluetooth (PAN)' }
            $ipv4 = 'Unknown'; $ipv6 = 'Unknown'; $gw = 'Unknown'; $dns = 'Unknown'
            $cfg = Get-CimSafe 'Win32_NetworkAdapterConfiguration' -Filter "Index=$(Get-PropValue $a @('Index'))"
            if ($cfg) {
                $c = @($cfg)[0]
                $ips = @(Get-PropValue $c @('IPAddress'))
                $v4 = @($ips | Where-Object { "$_" -match '^\d+\.' })
                $v6 = @($ips | Where-Object { "$_" -match ':' })
                if ($v4.Count -gt 0) { $ipv4 = $v4 -join ', ' }
                if ($v6.Count -gt 0) { $ipv6 = $v6 -join ', ' }
                $gws = @(Get-PropValue $c @('DefaultIPGateway'))
                if ($gws.Count -gt 0) { $gw = $gws -join ', ' }
                $dnss = @(Get-PropValue $c @('DNSServerSearchOrder'))
                if ($dnss.Count -gt 0) { $dns = $dnss -join ', ' }
            }
            $adapterList.Add([ordered]@{
                'Name'        = Format-Value (Get-PropValue $a @('NetConnectionID'))
                'Description' = Format-Value $desc
                'Type'        = $type
                'Status'      = Format-Value (Get-PropValue $a @('NetConnectionStatus'))
                'MAC Address' = Format-Value (Get-PropValue $a @('MACAddress'))
                'Link Speed'  = Format-Value (Get-PropValue $a @('Speed'))
                'IPv4'        = $ipv4
                'IPv6'        = $ipv6
                'Gateway'     = $gw
                'DNS Servers' = $dns
            })
        }
    }

    $btDevices = @(Get-CimSafe 'Win32_PnPEntity' -Filter "PNPClass='Bluetooth'")
    $bt = 'Not detected'
    if ($btDevices.Count -gt 0) {
        # Only the radio adapter itself, not paired devices/profiles.
        $radios = @($btDevices | ForEach-Object { "$(Get-PropValue $_ @('Name'))" } |
            Where-Object { $_ -match 'Bluetooth' -and $_ -notmatch 'Enumerator|Transport|Profile|Service|Gateway|Personal Area|PAN|RFCOMM|LE\b' } |
            Select-Object -Unique -First 3)
        if ($radios.Count -gt 0) { $bt = "Present ($($radios -join '; '))" } else { $bt = 'Present (radio name unknown)' }
    }

    return [ordered]@{
        'Physical Adapters' = "$($adapterList.Count)"
        'Bluetooth'         = $bt
        'Adapters'          = $adapterList
    }
}

# ----------------------------------------------------------------------------

function Get-UsbInfo {
    $controllers = @(Get-CimSafe 'Win32_USBController')
    $controllerList = [System.Collections.Generic.List[object]]::new()
    $versions = [System.Collections.Generic.List[string]]::new()
    foreach ($c in $controllers) {
        $name = "$(Get-PropValue $c @('Name'))"
        $ver = 'Unknown'
        if ($name -match 'USB\s*3\.(\d)') { $ver = "USB 3.$($Matches[1])" }
        elseif ($name -match '3\.\d|xHCI|eXtensible') { $ver = 'USB 3.x' }
        elseif ($name -match 'Enhanced|EHCI') { $ver = 'USB 2.0' }
        elseif ($name -match 'UHCI|OHCI|Universal|Open') { $ver = 'USB 1.1' }
        elseif ($name -match 'USB4') { $ver = 'USB4' }
        if ($ver -ne 'Unknown' -and -not $versions.Contains($ver)) { $versions.Add($ver) }
        $controllerList.Add([ordered]@{
            'Name'    = Format-Value $name
            'Version' = $ver
            'Status'  = Format-Value (Get-PropValue $c @('Status'))
        })
    }

    $deviceList = [System.Collections.Generic.List[object]]::new()
    $usbDevices = @(Get-CimSafe 'Win32_PnPEntity' -Filter "DeviceID LIKE 'USB\\%'")
    foreach ($u in $usbDevices) {
        $name = "$(Get-PropValue $u @('Name'))"
        $id = "$(Get-PropValue $u @('DeviceID'))"
        if (-not $name) { continue }
        if ($name -match 'Root Hub|Host Controller|Composite Device|Generic USB Hub|Hub$') { continue }
        if ($id -match 'ROOT_HUB') { continue }
        $deviceList.Add([ordered]@{
            'Name'   = Format-Value $name
            'Status' = Format-Value (Get-PropValue $u @('Status'))
        })
    }

    $verDisplay = 'Unknown'
    if ($versions.Count -gt 0) { $verDisplay = ($versions | Sort-Object) -join ', ' }

    return [ordered]@{
        'Controllers Found'  = "$($controllerList.Count)"
        'Supported Versions' = $verDisplay
        'Controllers'        = $controllerList
        'Connected Devices'  = $deviceList
    }
}

# ----------------------------------------------------------------------------

function Get-PciInfo {
    $devices = @(Get-CimSafe 'Win32_PnPEntity' -Filter "DeviceID LIKE 'PCI\\%'")
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $devices) {
        $errCode = Get-PropValue $d @('ConfigManagerErrorCode')
        $status = 'OK'
        if ($null -ne $errCode -and [int]$errCode -ne 0) { $status = "Problem (error code $errCode)" }
        elseif ("$(Get-PropValue $d @('Status'))" -notin @('OK', '')) { $status = "$(Get-PropValue $d @('Status'))" }
        $drv = Get-DriverInfoFor "$(Get-PropValue $d @('DeviceID'))"
        $drvDisplay = 'Unknown'
        if ($drv.Version) {
            $drvDisplay = "$($drv.Version)"
            if ($drv.Date) { $drvDisplay += " ($(Format-Date $drv.Date))" }
        }
        $list.Add([ordered]@{
            'Name'         = Format-Value (Get-PropValue $d @('Name'))
            'Manufacturer' = Format-Value (Get-PropValue $d @('Manufacturer'))
            'Class'        = Format-Value (Get-PropValue $d @('PNPClass'))
            'Driver'       = $drvDisplay
            'Status'       = $status
        })
    }
    $problems = @($list | Where-Object { $_['Status'] -like 'Problem*' })
    $Script:Raw.PciProblemCount = $problems.Count
    return [ordered]@{
        'PCI Devices Found' = "$($list.Count)"
        'Devices With Problems' = "$($problems.Count)"
        'Devices'           = $list
    }
}

# ----------------------------------------------------------------------------

function ConvertFrom-MonitorCharArray {
    param($Chars)
    try {
        $s = (@($Chars) | Where-Object { $_ -gt 0 } | ForEach-Object { [char][int]$_ }) -join ''
        return $s.Trim()
    } catch { return $null }
}

function Get-DisplayInfo {
    $monitorList = [System.Collections.Generic.List[object]]::new()
    $ids    = @(Get-CimSafe 'WmiMonitorID' 'root/wmi')
    $params = @(Get-CimSafe 'WmiMonitorBasicDisplayParams' 'root/wmi')

    foreach ($m in $ids) {
        $inst = "$(Get-PropValue $m @('InstanceName'))"
        $name = ConvertFrom-MonitorCharArray (Get-PropValue $m @('UserFriendlyName'))
        $maker = ConvertFrom-MonitorCharArray (Get-PropValue $m @('ManufacturerName'))
        $serial = ConvertFrom-MonitorCharArray (Get-PropValue $m @('SerialNumberID'))
        if ($serial -match '^0+$') { $serial = $null }
        $year = Get-PropValue $m @('YearOfManufacture')

        $sizeDisplay = 'Unknown'
        foreach ($p in @($params)) {
            if ("$(Get-PropValue $p @('InstanceName'))" -eq $inst) {
                $hcm = Get-PropValue $p @('MaxHorizontalImageSize')
                $vcm = Get-PropValue $p @('MaxVerticalImageSize')
                if ($hcm -and $vcm) {
                    $diag = [Math]::Round([Math]::Sqrt([Math]::Pow([double]$hcm, 2) + [Math]::Pow([double]$vcm, 2)) / 2.54, 1)
                    $sizeDisplay = ('{0}" (approx. {1} x {2} cm)' -f $diag, $hcm, $vcm)
                }
                break
            }
        }

        $monitorList.Add([ordered]@{
            'Model'         = Format-Value $name
            'Manufacturer'  = Format-Value $maker
            'Serial Number' = Format-Value $serial
            'Year'          = Format-Value $year
            'Diagonal Size' = $sizeDisplay
        })
    }

    # Active mode(s) from the video controller(s).
    $modes = [System.Collections.Generic.List[string]]::new()
    foreach ($g in @(Get-CimSafe 'Win32_VideoController')) {
        $h = Get-PropValue $g @('CurrentHorizontalResolution')
        $v = Get-PropValue $g @('CurrentVerticalResolution')
        $r = Get-PropValue $g @('CurrentRefreshRate')
        $b = Get-PropValue $g @('CurrentBitsPerPixel')
        if ($h -and $v) {
            $mode = "$h x $v"
            if ($r) { $mode += " @ $r Hz" }
            if ($b) { $mode += ", $b-bit color" }
            $modes.Add($mode)
        }
    }
    $modeDisplay = 'Unknown'
    if ($modes.Count -gt 0) { $modeDisplay = ($modes | Select-Object -Unique) -join ' / ' }

    return [ordered]@{
        'Monitors Detected' = "$($monitorList.Count)"
        'Active Mode'       = $modeDisplay
        'HDR Support'       = 'Unknown (not exposed via WMI; check Settings > Display)'
        'Monitors'          = $monitorList
    }
}

# ----------------------------------------------------------------------------

function Get-BatteryInfo {
    $batteries = @(Get-CimSafe 'Win32_Battery')
    if ($batteries.Count -eq 0) {
        $Script:Raw.IsLaptop = $false
        return [ordered]@{ 'Battery' = 'Not present (desktop system or battery removed)' }
    }
    $Script:Raw.IsLaptop = $true

    $static  = @(Get-CimSafe 'BatteryStaticData' 'root/wmi')
    $full    = @(Get-CimSafe 'BatteryFullChargedCapacity' 'root/wmi')
    $cycles  = @(Get-CimSafe 'BatteryCycleCount' 'root/wmi')

    $list = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $batteries.Count; $i++) {
        $b = $batteries[$i]
        $design = $null; $fullCap = $null; $cycleCount = $null
        if ($i -lt $static.Count)  { $design = Get-PropValue $static[$i] @('DesignedCapacity') }
        if ($i -lt $full.Count)    { $fullCap = Get-PropValue $full[$i] @('FullChargedCapacity') }
        if ($i -lt $cycles.Count)  { $cycleCount = Get-PropValue $cycles[$i] @('CycleCount') }
        if ($null -eq $design) { $design = Get-PropValue $b @('DesignCapacity') }
        if ($null -eq $fullCap) { $fullCap = Get-PropValue $b @('FullChargeCapacity') }

        $wearDisplay = 'Unknown'
        $healthDisplay = 'Unknown'
        if ($design -and $fullCap -and [double]$design -gt 0) {
            $healthPct = [Math]::Round(100.0 * [double]$fullCap / [double]$design, 1)
            if ($healthPct -gt 100) { $healthPct = 100 }
            $wearPct = [Math]::Round(100 - $healthPct, 1)
            $wearDisplay = "$wearPct %"
            $Script:Raw.BatteryWearPct = $wearPct
            if ($wearPct -lt 10) { $healthDisplay = "Good ($healthPct% of design capacity)" }
            elseif ($wearPct -lt 25) { $healthDisplay = "Fair ($healthPct% of design capacity)" }
            else { $healthDisplay = "Worn ($healthPct% of design capacity)" }
        }

        $statusMap = @{ 1 = 'Discharging'; 2 = 'On AC power'; 3 = 'Fully charged'; 4 = 'Low'; 5 = 'Critical'
                        6 = 'Charging'; 7 = 'Charging (high)'; 8 = 'Charging (low)'; 9 = 'Charging (critical)'
                        10 = 'Unknown'; 11 = 'Partially charged' }
        $statusVal = Get-PropValue $b @('BatteryStatus')
        $status = 'Unknown'
        if ($null -ne $statusVal -and $statusMap.ContainsKey([int]$statusVal)) { $status = $statusMap[[int]$statusVal] }

        $chemMap = @{ 1 = 'Other'; 2 = 'Unknown'; 3 = 'Lead acid'; 4 = 'NiCd'; 5 = 'NiMH'; 6 = 'Li-ion'; 7 = 'Zinc air'; 8 = 'Li-polymer' }
        $chemVal = Get-PropValue $b @('Chemistry')
        $chem = 'Unknown'
        if ($null -ne $chemVal -and $chemMap.ContainsKey([int]$chemVal)) { $chem = $chemMap[[int]$chemVal] }

        $cycleDisplay = 'Unknown (not reported by this battery)'
        if ($null -ne $cycleCount -and [int]$cycleCount -gt 0) { $cycleDisplay = "$cycleCount" }

        $designDisplay = 'Unknown'
        if ($design) { $designDisplay = ('{0:N0} mWh' -f [double]$design) }
        $fullDisplay = 'Unknown'
        if ($fullCap) { $fullDisplay = ('{0:N0} mWh' -f [double]$fullCap) }

        $list.Add([ordered]@{
            'Name'                 = Format-Value (Get-PropValue $b @('Name'))
            'Chemistry'            = $chem
            'Status'               = $status
            'Charge Level'         = Format-Value (Get-PropValue $b @('EstimatedChargeRemaining')) '%'
            'Design Capacity'      = $designDisplay
            'Full Charge Capacity' = $fullDisplay
            'Wear Level'           = $wearDisplay
            'Cycle Count'          = $cycleDisplay
            'Health Estimate'      = $healthDisplay
        })
    }
    return [ordered]@{ 'Batteries' = $list }
}

# ----------------------------------------------------------------------------

function Get-AudioInfo {
    $devices = @(Get-CimSafe 'Win32_SoundDevice')
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $devices) {
        $drv = Get-DriverInfoFor "$(Get-PropValue $d @('PNPDeviceID', 'DeviceID'))"
        $drvDisplay = 'Unknown'
        if ($drv.Version) {
            $drvDisplay = "$($drv.Version)"
            if ($drv.Date) { $drvDisplay += " ($(Format-Date $drv.Date))" }
        }
        $list.Add([ordered]@{
            'Name'         = Format-Value (Get-PropValue $d @('Name'))
            'Manufacturer' = Format-Value (Get-PropValue $d @('Manufacturer'))
            'Driver'       = $drvDisplay
            'Status'       = Format-Value (Get-PropValue $d @('Status'))
        })
    }
    if ($list.Count -eq 0) { return [ordered]@{ 'Audio Devices' = 'None detected' } }
    return [ordered]@{ 'Devices' = $list }
}

# ----------------------------------------------------------------------------

function Get-SensorInfo {
    # Thermal zone temperatures (ACPI). Often requires Administrator and is
    # not available on all boards - degrade gracefully.
    $zoneList = [System.Collections.Generic.List[object]]::new()
    $zones = @(Get-CimSafe 'MSAcpi_ThermalZoneTemperature' 'root/wmi')
    foreach ($z in $zones) {
        $raw = Get-PropValue $z @('CurrentTemperature')
        if ($null -eq $raw -or [double]$raw -le 0) { continue }
        $celsius = [Math]::Round(([double]$raw / 10.0) - 273.15, 1)
        if ($celsius -lt -50 -or $celsius -gt 150) { continue }
        if ($null -eq $Script:Raw.CpuTempC -or $celsius -gt $Script:Raw.CpuTempC) { $Script:Raw.CpuTempC = $celsius }
        $inst = "$(Get-PropValue $z @('InstanceName'))"
        $zoneList.Add([ordered]@{
            'Zone'        = Format-Value $inst
            'Temperature' = "$celsius $($Script:G.Deg)C"
        })
    }
    $zoneDisplay = $zoneList
    $zoneNote = 'ACPI thermal zones approximate CPU/system temperature'
    if ($zoneList.Count -eq 0) {
        $zoneNote = 'Not available (requires Administrator, or not exposed by this firmware)'
        if (Test-IsAdmin) { $zoneNote = 'Not available (not exposed by this firmware)' }
    }

    $fanList = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @(Get-CimSafe 'Win32_Fan')) {
        $speed = Get-PropValue $f @('DesiredSpeed')
        $speedDisplay = 'Unknown (RPM not exposed via WMI)'
        if ($speed -and [double]$speed -gt 0) { $speedDisplay = "$speed RPM" }
        $fanList.Add([ordered]@{
            'Fan'    = Format-Value (Get-PropValue $f @('Name', 'Caption'))
            'Status' = Format-Value (Get-PropValue $f @('Status'))
            'Speed'  = $speedDisplay
        })
    }
    $diskTemp = 'Unknown (see per-disk temperatures in the Storage section)'
    if ($null -ne $Script:Raw.DiskTempMax) { $diskTemp = "$($Script:Raw.DiskTempMax) $($Script:G.Deg)C (hottest disk)" }

    $result = [ordered]@{
        'CPU / System Temperature' = $zoneNote
    }
    if ($zoneList.Count -gt 0) { $result['Thermal Zones'] = $zoneDisplay }
    $result['Disk Temperature'] = $diskTemp
    if ($fanList.Count -gt 0) { $result['Fans'] = $fanList }
    else { $result['Fan Speed'] = 'Not exposed via WMI (typical for consumer hardware; use vendor tools)' }
    return $result
}

# ============================================================================
#  HEALTH CHECK + BUYER ANALYSIS
# ============================================================================

function Get-HealthChecks {
    $issues = [System.Collections.Generic.List[object]]::new()
    $add = { param($Severity, $Category, $Message)
        $issues.Add([ordered]@{ 'Severity' = $Severity; 'Category' = $Category; 'Message' = $Message }) }

    # BIOS age
    if ($Script:Raw.BiosDate) {
        $age = ((Get-Date) - $Script:Raw.BiosDate).TotalDays / 365.25
        if ($age -gt 5) { & $add 'WARN' 'BIOS' ('BIOS is {0:N1} years old ({1:yyyy-MM-dd}); check the vendor for firmware updates.' -f $age, $Script:Raw.BiosDate) }
        elseif ($age -gt 3) { & $add 'INFO' 'BIOS' ('BIOS dates from {0:yyyy-MM-dd}; a newer version may be available.' -f $Script:Raw.BiosDate) }
    }

    # RAM
    if ($Script:Raw.MemoryModules -eq 1) { & $add 'WARN' 'RAM' 'Only one memory module installed - RAM is running in single channel, which reduces performance.' }
    if ($Script:Raw.RamSpeed) {
        if ($Script:Raw.DdrGen -match 'DDR4' -and $Script:Raw.RamSpeed -lt 2400) { & $add 'WARN' 'RAM' "DDR4 memory is running at $($Script:Raw.RamSpeed) MT/s, below typical DDR4 speeds (2400+)." }
        if ($Script:Raw.DdrGen -match 'DDR3' -and $Script:Raw.RamSpeed -lt 1333) { & $add 'WARN' 'RAM' "DDR3 memory is running at $($Script:Raw.RamSpeed) MT/s, below typical DDR3 speeds." }
        if ($Script:Raw.DdrGen -match 'DDR5' -and $Script:Raw.RamSpeed -lt 4800) { & $add 'INFO' 'RAM' "DDR5 memory is running at $($Script:Raw.RamSpeed) MT/s; check whether XMP/EXPO is enabled in BIOS." }
    }
    if ($Script:Raw.RamGB -and $Script:Raw.RamGB -lt 8) { & $add 'WARN' 'RAM' "Only $($Script:Raw.RamGB) GB of RAM installed - below the comfortable minimum (8 GB) for modern Windows use." }

    # Storage
    if ($Script:Raw.HasSSD -eq $false) { & $add 'WARN' 'Storage' 'No SSD detected - the system runs entirely on mechanical/unknown storage, which severely limits responsiveness.' }
    if ($Script:Raw.BootDiskType -match 'HDD') { & $add 'WARN' 'Storage' 'The Windows boot drive is a mechanical HDD; an SSD upgrade would drastically improve performance.' }
    foreach ($s in @($Script:Raw.SmartIssues)) { & $add 'CRIT' 'Storage' "SMART reports a problem: $s. Back up data and plan a replacement." }
    if ($null -ne $Script:Raw.SysFreePct) {
        if ($Script:Raw.SysFreePct -lt 10 -or $Script:Raw.SysFreeGB -lt 15) { & $add 'WARN' 'Storage' "System drive is nearly full ($($Script:Raw.SysFreeGB) GB / $($Script:Raw.SysFreePct)% free)." }
    }

    # Temperatures
    if ($null -ne $Script:Raw.CpuTempC -and $Script:Raw.CpuTempC -gt 80) { & $add 'WARN' 'Thermal' "System thermal zone reports $($Script:Raw.CpuTempC) C - high for an idle/light-load inspection; check cooling and dust." }
    if ($null -ne $Script:Raw.DiskTempMax -and $Script:Raw.DiskTempMax -gt 55) { & $add 'WARN' 'Thermal' "A disk reports $($Script:Raw.DiskTempMax) C - above the recommended operating range." }

    # Virtualization
    if ($Script:Raw.VirtEnabled -eq $false) { & $add 'INFO' 'CPU' 'Hardware virtualization is disabled in firmware; enable it in BIOS/UEFI if you plan to use virtual machines or WSL2.' }

    # GPU drivers
    foreach ($g in @($Script:Raw.GpuDriverDates)) {
        if ($g.Date -and ((Get-Date) - $g.Date).TotalDays -gt 900) {
            & $add 'INFO' 'GPU' ('GPU driver for "{0}" dates from {1:yyyy-MM-dd}; a newer driver is likely available.' -f $g.Name, $g.Date)
        }
    }

    # Battery
    if ($null -ne $Script:Raw.BatteryWearPct) {
        if ($Script:Raw.BatteryWearPct -ge 40) { & $add 'CRIT' 'Battery' "Battery has lost $($Script:Raw.BatteryWearPct)% of its design capacity - expect a replacement soon." }
        elseif ($Script:Raw.BatteryWearPct -ge 20) { & $add 'WARN' 'Battery' "Battery wear is $($Script:Raw.BatteryWearPct)% - noticeably reduced runtime compared to new." }
    }

    # OS / firmware
    if ($Script:Raw.Activation -notmatch '^Activated' -and $Script:Raw.Activation -ne 'Unknown') { & $add 'WARN' 'Windows' "Windows is not activated (status: $($Script:Raw.Activation))." }
    if ($Script:Raw.FirmwareMode -eq 'Legacy BIOS') { & $add 'WARN' 'Firmware' 'Windows is installed in Legacy BIOS mode - Secure Boot and Windows 11 upgrade are unavailable without reinstalling in UEFI mode.' }
    if ($Script:Raw.SecureBoot -eq 'Disabled') { & $add 'INFO' 'Firmware' 'Secure Boot is disabled; it can usually be enabled in UEFI settings.' }
    if ($Script:Raw.Win11Verdict -eq 'Fail') { & $add 'INFO' 'Windows' 'This system does not meet the Windows 11 baseline requirements (see the System section).' }

    # PCI device problems
    if ($Script:Raw.PciProblemCount -gt 0) { & $add 'WARN' 'Devices' "$($Script:Raw.PciProblemCount) PCI device(s) report a driver/configuration problem (see PCI Devices section)." }

    if ($issues.Count -eq 0) {
        $issues.Add([ordered]@{ 'Severity' = 'OK'; 'Category' = 'General'; 'Message' = 'No health issues detected by the automated checks.' })
    }
    return $issues
}

function Get-BuyerAnalysis {
    $facts = [System.Collections.Generic.List[string]]::new()

    if ($Script:Raw.TotalSlots) {
        $facts.Add("Motherboard reports $($Script:Raw.TotalSlots) memory slot(s); $($Script:Raw.MemoryModules) in use, $($Script:Raw.FreeSlots) free.")
        if ($Script:Raw.FreeSlots -gt 0) { $facts.Add('RAM can be expanded without removing existing modules.') }
        elseif ($Script:Raw.TotalSlots -gt 0) { $facts.Add('All memory slots are occupied; a RAM upgrade requires replacing existing modules.') }
    }
    if ($Script:Raw.MaxRamGB -and $Script:Raw.RamGB) {
        if ($Script:Raw.MaxRamGB -gt $Script:Raw.RamGB) { $facts.Add("Installed RAM is $($Script:Raw.RamGB) GB of a reported $($Script:Raw.MaxRamGB) GB maximum.") }
    }
    if ($Script:Raw.HasNVMe) { $facts.Add('System already uses NVMe storage.') }
    elseif ($Script:Raw.HasSSD) { $facts.Add('System uses SATA SSD storage (no NVMe detected).') }
    if ($Script:Raw.BootDiskType) {
        $facts.Add("Windows boot drive type: $($Script:Raw.BootDiskType) ($($Script:Raw.BootDiskModel)).")
    }
    if ($Script:Raw.FirmwareMode -eq 'UEFI') { $facts.Add('Windows is installed in UEFI mode.') }
    elseif ($Script:Raw.FirmwareMode -eq 'Legacy BIOS') { $facts.Add('Windows is installed in Legacy BIOS mode.') }
    if ($Script:Raw.TpmVersion -match '^2\.') { $facts.Add('TPM 2.0 is present (required for Windows 11).') }
    if ($Script:Raw.BiosDate) {
        $age = ((Get-Date) - $Script:Raw.BiosDate).TotalDays / 365.25
        if ($age -gt 3) { $facts.Add(('BIOS dates from {0:yyyy-MM-dd}; checking the vendor for an update is recommended.' -f $Script:Raw.BiosDate)) }
    }
    switch ($Script:Raw.Win11Verdict) {
        'AlreadyWin11' { $facts.Add('The system is already running Windows 11.') }
        'Pass'         { $facts.Add('The system meets the Windows 11 baseline hardware requirements.') }
        'Fail'         { $facts.Add('The system does not meet the Windows 11 baseline hardware requirements.') }
    }
    if ($Script:Raw.IsLaptop -eq $true -and $null -ne $Script:Raw.BatteryWearPct) {
        $facts.Add("Battery retains $([Math]::Round(100 - $Script:Raw.BatteryWearPct, 1))% of its original design capacity.")
    }
    if ($Script:Raw.CpuCores) { $facts.Add("CPU provides $($Script:Raw.CpuCores) physical core(s): $($Script:Raw.CpuName).") }

    if ($facts.Count -eq 0) { $facts.Add('Not enough data was collected to generate observations.') }
    return $facts
}

# ============================================================================
#  SUMMARY / EXPORT
# ============================================================================

function Out-HealthSection {
    param($Issues)
    Out-SectionHeader 'Health Check'
    foreach ($i in @($Issues)) {
        $color = [ConsoleColor]::Gray
        switch ($i['Severity']) {
            'OK'   { $color = [ConsoleColor]::Green }
            'INFO' { $color = [ConsoleColor]::Cyan }
            'WARN' { $color = [ConsoleColor]::Yellow }
            'CRIT' { $color = [ConsoleColor]::Red }
        }
        Out-Line ("  [{0,-4}] {1}: {2}" -f $i['Severity'], $i['Category'], $i['Message']) $color
    }
}

function Out-AnalysisSection {
    param($Facts)
    Out-SectionHeader 'Buyer Analysis (objective observations)'
    foreach ($f in @($Facts)) { Out-Line ("  - $f") White }
}

function Out-SummarySection {
    param($Report, $Issues, [timespan]$Elapsed)
    Out-SectionHeader 'Summary'
    $sys = $Report['System']; $cpu = $Report['CPU']; $ram = $Report['RAM']
    Out-KV 'Machine'  ("$($sys['Manufacturer']) $($sys['Model'])")
    Out-KV 'OS'       ("$($sys['Windows Edition']) (build $($sys['Build']))")
    Out-KV 'CPU'      $cpu['Model']
    Out-KV 'RAM'      ("$($ram['Total Installed']) $($ram['Memory Type'])")
    $bootType = 'Unknown'
    if ($Script:Raw.BootDiskType) { $bootType = $Script:Raw.BootDiskType }
    Out-KV 'Boot Drive' $bootType
    $gpuNames = @()
    $gpuSection = $Report['GPU']
    if ($gpuSection -and $gpuSection.Contains('GPUs')) {
        foreach ($g in @($gpuSection['GPUs'])) { $gpuNames += $g['Model'] }
    }
    if ($gpuNames.Count -gt 0) { Out-KV 'GPU' ($gpuNames -join ' / ') } else { Out-KV 'GPU' 'Unknown' }

    $crit = @($Issues | Where-Object { $_['Severity'] -eq 'CRIT' }).Count
    $warn = @($Issues | Where-Object { $_['Severity'] -eq 'WARN' }).Count
    $info = @($Issues | Where-Object { $_['Severity'] -eq 'INFO' }).Count
    $verdictColor = [ConsoleColor]::Green
    $verdict = 'No warnings raised'
    if ($crit -gt 0) { $verdict = "$crit critical, $warn warning(s), $info informational"; $verdictColor = [ConsoleColor]::Red }
    elseif ($warn -gt 0) { $verdict = "$warn warning(s), $info informational"; $verdictColor = [ConsoleColor]::Yellow }
    elseif ($info -gt 0) { $verdict = "$info informational note(s)"; $verdictColor = [ConsoleColor]::Cyan }
    Out-Line ''
    Out-Line ("  Health result: $verdict") $verdictColor
    Out-Line ("  Inspection completed in {0:N1} seconds." -f $Elapsed.TotalSeconds) DarkGray
}

function Export-Reports {
    param($Report, $Issues, $Facts)
    if (-not ($Json -or $Txt)) { return }

    $dir = $OutputPath
    if (-not $dir) {
        $dir = $PSScriptRoot
        if (-not $dir) { $dir = (Get-Location).Path }
    }
    try {
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop }
    } catch {
        Out-Line "  Could not create output directory '$dir'; using current directory." Yellow
        $dir = (Get-Location).Path
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $base = Join-Path $dir ("PC-Inspector_{0}_{1}" -f $env:COMPUTERNAME, $stamp)

    Out-Line ''
    if ($Json) {
        try {
            $payload = [ordered]@{
                'Tool'      = "PC Inspector v$($Script:Version)"
                'Generated' = (Get-Date).ToString('s')
                'Hostname'  = $env:COMPUTERNAME
                'RunAsAdministrator' = Test-IsAdmin
                'Report'    = $Report
                'HealthCheck'    = $Issues
                'BuyerAnalysis'  = $Facts
            }
            $jsonPath = "$base.json"
            $payload | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $jsonPath -Encoding utf8 -ErrorAction Stop
            Out-Line "  JSON report saved: $jsonPath" Green
        } catch {
            Out-Line "  JSON export failed: $($_.Exception.Message)" Red
        }
    }
    if ($Txt) {
        try {
            $txtPath = "$base.txt"
            $Script:TxtBuffer.ToString() | Out-File -LiteralPath $txtPath -Encoding utf8 -ErrorAction Stop
            Write-Host "  TXT report saved: $txtPath" -ForegroundColor Green
        } catch {
            Write-Host "  TXT export failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ============================================================================
#  MAIN
# ============================================================================

function Invoke-PCInspector {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $banner = 'PC INSPECTOR v' + $Script:Version + '  -  Windows Hardware Inspection Utility'
    $inner = 76
    Out-Line ($Script:G.TL + ($Script:G.H * $inner) + $Script:G.TR) Cyan
    Out-Line ($Script:G.V + ('  ' + $banner).PadRight($inner) + $Script:G.V) Cyan
    Out-Line ($Script:G.V + ('  ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  |  Host: ' + $env:COMPUTERNAME + '  |  PowerShell ' + $PSVersionTable.PSVersion).PadRight($inner) + $Script:G.V) DarkCyan
    Out-Line ($Script:G.BL + ($Script:G.H * $inner) + $Script:G.BR) Cyan
    if (-not (Test-IsAdmin)) {
        Out-Line '  Running without Administrator rights - some values will show as Unknown.' DarkYellow
    }

    # Collection plan. Order matters: System first (fills raw facts used later),
    # Storage before Sensors (disk temperatures), sections rendered in the
    # order a buyer reads them.
    $plan = @(
        @{ Key = 'System';      Title = 'System';          Fn = { Get-SystemInfo } }
        @{ Key = 'CPU';         Title = 'CPU';             Fn = { Get-CpuInfo } }
        @{ Key = 'Motherboard'; Title = 'Motherboard';     Fn = { Get-MotherboardInfo } }
        @{ Key = 'RAM';         Title = 'Memory (RAM)';    Fn = { Get-RamInfo } }
        @{ Key = 'Storage';     Title = 'Storage';         Fn = { Get-StorageInfo } }
        @{ Key = 'GPU';         Title = 'Graphics (GPU)';  Fn = { Get-GpuInfo } }
        @{ Key = 'Network';     Title = 'Network';         Fn = { Get-NetworkInfo } }
        @{ Key = 'USB';         Title = 'USB';             Fn = { Get-UsbInfo } }
        @{ Key = 'PCI';         Title = 'PCI Devices';     Fn = { Get-PciInfo } }
        @{ Key = 'Display';     Title = 'Display';         Fn = { Get-DisplayInfo } }
        @{ Key = 'Battery';     Title = 'Battery';         Fn = { Get-BatteryInfo } }
        @{ Key = 'Audio';       Title = 'Audio';           Fn = { Get-AudioInfo } }
        @{ Key = 'Sensors';     Title = 'Sensors';         Fn = { Get-SensorInfo } }
    )

    $report = [ordered]@{}
    for ($i = 0; $i -lt $plan.Count; $i++) {
        $step = $plan[$i]
        $pct = [int](100 * $i / $plan.Count)
        Write-Progress -Id $Script:ProgressId -Activity 'PC Inspector - collecting hardware information' `
            -Status "$($step.Title) ($($i + 1) of $($plan.Count))" -PercentComplete $pct
        try {
            $report[$step.Key] = & $step.Fn
        } catch {
            $report[$step.Key] = [ordered]@{ 'Status' = "Unknown (collection failed: $($_.Exception.Message))" }
        }
    }
    Write-Progress -Id $Script:ProgressId -Activity 'PC Inspector' -Completed

    # Render all sections through the shared console/TXT pipeline.
    for ($i = 0; $i -lt $plan.Count; $i++) {
        $step = $plan[$i]
        Out-SectionHeader $step.Title
        Write-KVBlock $report[$step.Key]
    }

    $issues = @()
    try { $issues = @(Get-HealthChecks) } catch {
        $issues = @([ordered]@{ 'Severity' = 'INFO'; 'Category' = 'General'; 'Message' = 'Health check could not be completed.' })
    }
    $facts = @()
    try { $facts = @(Get-BuyerAnalysis) } catch {
        $facts = @('Buyer analysis could not be completed.')
    }

    Out-HealthSection $issues
    Out-AnalysisSection $facts
    $stopwatch.Stop()
    Out-SummarySection $report $issues $stopwatch.Elapsed
    Export-Reports $report $issues $facts
    Out-Line ''
}

try {
    Invoke-PCInspector
    exit 0
} catch {
    Write-Host ''
    Write-Host "PC Inspector encountered an unexpected fatal error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 1
}
