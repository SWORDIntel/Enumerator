# PowerShell Enumerator

PowerShell script-based version of the Windows System Enumerator for Windows 10 systems. Provides identical functionality to the C version but runs as a PowerShell script, making it easier to deploy in environments where C compilation is not available.

## Features

- **SYSTEM Token Acquisition**: Attempts to acquire SYSTEM privileges via Windows API and service token stealing
- **Defensive Feature Blinding**: Disables Windows Firewall, Defender, Security Center, and WFP (Windows Filtering Platform)
- **MDM Detection & Neutralization**: Detects and neutralizes MDM software (Intune, AirWatch, MobileIron, Workspace ONE) via registry, services, processes, and drivers with callback zeroing and minifilter detachment
- **EDR Detection & Evasion**: Detects 16+ EDR products (CrowdStrike, SentinelOne, Defender, Carbon Black, Trend Micro, Bitdefender, Sophos, Cylance, FireEye, Palo Alto, Elastic, Cybereason, Secureworks, F-Secure, Kaspersky, Symantec) with comprehensive evasion (zero callbacks, detach minifilters, blind ETW, direct syscalls, AMSI bypass, API unhooking)
- **Comprehensive System Enumeration**: OS info, hardware (CPU, RAM, BIOS, disks), processes (with command line), services, registry (important keys), filesystem (important directories), users, LSASS access
- **Network Enumeration**: Interfaces, routing, ARP table, active connections, network discovery
- **Recursive Network Discovery**: W-SLAM-style recursive enumeration with continuous EDR evasion at each depth level
- **VLAN Structure Enumeration**: VLAN IDs, tagged/untagged ports, trunk information
- **Enhanced Enumeration**: 
  - Post-exploitation indicators (AMSI, ETW, WFP, COM hijacking, WMI persistence, Kerberos opportunities, rootkit indicators)
  - AD infrastructure (domain controllers, Netlogon, Certificate Services, ADCS web enrollment, certificate template vulnerabilities)
  - WAF detection (Cloudflare, AWS WAF, Sucuri, Imperva) and web application technology (IIS, Apache)
  - C2 opportunities (outbound connectivity, proxy configuration, SSH tunnels, DNS tunneling)
  - Steganography opportunities (image file enumeration for LSB steganography)
- **Pastebin Upload**: Automatic upload with password protection and fallback services (Hastebin, 0x0.st)
- **Self-Deletion**: Automatically deletes itself after completion

## Requirements

- Windows PowerShell 5.1+ or PowerShell Core 7+
- Administrator privileges (for SYSTEM token acquisition and defensive feature blinding)
- Network access (for Pastebin upload)

## Usage

```powershell
# Basic usage
.\enumerator.ps1

# With custom password
.\enumerator.ps1 -PastebinPassword "custompassword"

# With custom recursion depth
.\enumerator.ps1 -MaxDepth 5

# Skip MDM neutralization
.\enumerator.ps1 -SkipMDM

# Skip EDR evasion
.\enumerator.ps1 -SkipEDR
```

## Output

The enumerator outputs comprehensive enumeration data to Pastebin (or fallback service) with the specified password. The URL is displayed for copying, and the script self-deletes after user confirmation.

## Feature Parity with C Version

The PowerShell enumerator now has **full feature parity** with the C version:

- ✅ Same 16+ EDR products detected
- ✅ Same comprehensive EDR evasion techniques
- ✅ Same MDM detection and neutralization methods
- ✅ Same post-exploitation enumeration patterns (WINCLOAK)
- ✅ Same AD/Certificate Services enumeration (ACTIVEGAME)
- ✅ Same WAF detection (CORTISOL)
- ✅ Same C2 opportunities enumeration (ROCKHAMMER)
- ✅ Same steganography opportunities (SLEEPYMONEY)
- ✅ Same recursive network discovery with continuous EDR evasion
- ✅ Same comprehensive system enumeration (hardware, registry, filesystem, LSASS)

## Differences from C Version

- Uses PowerShell cmdlets instead of direct Windows API calls
- Better integration with PowerShell ecosystem
- Easier to modify and extend
- No compilation required
- Some kernel-level operations use user-mode fallbacks (service/process stopping instead of direct kernel callback zeroing)

## Security Notes

- Requires administrator privileges
- Performs system modifications (firewall, defender)
- Self-deletes after execution
- Uploads sensitive enumeration data to cloud services

## See Also

- `../c_enumerator/` - C version
- `../processor/` - Linux-based processor tools
