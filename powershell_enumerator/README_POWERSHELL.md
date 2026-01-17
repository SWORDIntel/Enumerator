# PowerShell Enumerator

PowerShell version of the Windows System Enumerator for Windows 10 systems. Provides identical functionality to the C version but runs as a PowerShell script, making it easier to deploy in environments where C compilation is not available.

## Features

- **SYSTEM Token Acquisition**: Attempts to acquire SYSTEM privileges via Windows API and service token stealing
- **Defensive Feature Blinding**: Disables Windows Firewall, Defender, and Security Center notifications
- **MDM Detection & Neutralization**: Detects and neutralizes MDM software
- **EDR Detection**: Detects 16+ EDR products during recursive enumeration
- **Comprehensive Enumeration**: System, network, processes, services, users, VLANs
- **Enhanced Enumeration**: Post-exploitation indicators, AD infrastructure, WAF detection, C2 opportunities, steganography
- **Recursive Network Discovery**: W-SLAM-style recursive enumeration with EDR evasion
- **Pastebin Upload**: Automatic upload with password protection and fallback services
- **Self-Deletion**: Automatically deletes itself after completion

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

## Requirements

- Windows PowerShell 5.1+ or PowerShell Core 7+
- Administrator privileges (for SYSTEM token acquisition and defensive feature blinding)
- Network access (for Pastebin upload)

## Output

The enumerator outputs comprehensive enumeration data to Pastebin (or fallback service) with the specified password. The URL is displayed for copying, and the script self-deletes after user confirmation.

## Differences from C Version

- Uses PowerShell cmdlets instead of Windows API calls
- Simpler implementation but same functionality
- Better integration with PowerShell ecosystem
- Easier to modify and extend

## Security Notes

- Requires administrator privileges
- Performs system modifications (firewall, defender)
- Self-deletes after execution
- Uploads sensitive enumeration data to cloud services
