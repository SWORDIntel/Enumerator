# C Enumerator

Full-featured C implementation of the Windows System Enumerator for Windows 10 systems.

## Features

- **SYSTEM Token Acquisition**: Attempts to acquire SYSTEM privileges using multiple methods (PE5-based, Windows API, service token stealing)
- **Defensive Feature Blinding**: Disables Windows Firewall, Defender, and Security Center notifications immediately after SYSTEM token acquisition
- **MDM Detection & Neutralization**: Detects and neutralizes MDM software by zeroing callback pointers
- **EDR Detection & Evasion**: Detects 16+ EDR products and applies continuous evasion techniques during enumeration
- **Comprehensive System Enumeration**: OS info, hardware, processes, services, registry, filesystem, users, security
- **Deep Analysis**: LSASS memory access, protected registry keys, kernel-level information (requires SYSTEM token)
- **Network Enumeration**: Interfaces, routing, ARP table, active connections, network discovery
- **Recursive Network Discovery**: W-SLAM-style recursive enumeration across network with continuous EDR evasion
- **VLAN Structure Enumeration**: VLAN IDs, tagged/untagged ports, trunk information via WMI and network adapters
- **Progress Bar**: Real-time progress display with color-coded status
- **Pastebin Upload**: Automatic upload with password protection and fallback services
- **Self-Deletion**: Automatically deletes itself after completion

## Building

### Windows (MinGW)

```cmd
make
```

Or use the batch file:

```cmd
build.bat
```

### Requirements

- MinGW or MSVC compiler
- Windows SDK
- Required libraries: ws2_32, iphlpapi, advapi32, ole32, oleaut32, wbemuuid, netapi32, crypt32, wldap32

## Usage

```cmd
enumerator.exe
```

The enumerator will:
1. Acquire SYSTEM token via PE5
2. Blind firewall and defensive features
3. Detect and neutralize MDM
4. Perform comprehensive enumeration
5. Upload results to Pastebin
6. Display URL and password
7. Self-delete after user confirmation

## Output

Enumeration data is uploaded to Pastebin (or fallback service) with password "ducknipples" by default. The URL is displayed for copying.

## Architecture

The C enumerator consists of multiple modules:

- `enumerator.c/h` - Main program and orchestration
- `token_acquisition.c/h` - SYSTEM token acquisition (PE5, Windows API, service stealing)
- `defensive_blinding.c/h` - Firewall and defensive feature blinding
- `mdm_detection.c/h` - MDM software detection
- `mdm_neutralization.c/h` - MDM neutralization via callback zeroing
- `edr_detection.c/h` - EDR product detection
- `edr_evasion.c/h` - EDR evasion techniques
- `network_recursive.c/h` - Recursive network discovery with W-SLAM techniques
- `progress.c/h` - Progress bar display
- `pastebin.c/h` - Pastebin upload with fallback services

## See Also

- `../powershell_enumerator/` - PowerShell version
- `../processor/` - Linux-based processor tools
