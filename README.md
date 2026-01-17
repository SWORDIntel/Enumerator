# Windows System Enumerator

A comprehensive Windows C program that automatically enumerates all system and network aspects (including VLAN structure), performs MDM neutralization and EDR evasion, displays a progress bar, uploads results to Pastebin (password: "ducknipples") with API testing and fallback services, and self-deletes after user confirmation.

## Features

### Core Functionality

- **SYSTEM Token Acquisition**: Attempts to acquire SYSTEM privileges using multiple methods (PE5-based, Windows API, service token stealing)
- **MDM Detection & Neutralization**: Detects and neutralizes MDM software immediately after SYSTEM token acquisition by zeroing callback pointers
- **EDR Detection & Evasion**: Detects 16+ EDR products and applies continuous evasion techniques during enumeration
- **Comprehensive System Enumeration**: OS info, hardware, processes, services, registry, filesystem, users, security
- **Deep Analysis**: LSASS memory access, protected registry keys, kernel-level information (requires SYSTEM token)
- **Network Enumeration**: Interfaces, routing, ARP table, active connections, network discovery
- **Recursive Network Discovery**: W-SLAM-style recursive enumeration across network with continuous EDR evasion
- **VLAN Structure Enumeration**: VLAN IDs, tagged/untagged ports, trunk information via WMI and network adapters
- **Progress Bar**: Real-time progress display with color-coded status
- **Pastebin Upload**: Automatic upload with password protection and fallback services
- **Self-Deletion**: Automatically deletes itself after completion

### Advanced Features

#### MDM Neutralization (Phase 1)

Immediately after SYSTEM token acquisition, the enumerator:

- **Detects MDM Software** via:
  - Registry keys (Intune, AirWatch, MobileIron, Workspace ONE)
  - Services (MDM-related services)
  - Processes (MDM agent processes)
  - Kernel drivers (MDM minifilter drivers)

- **Neutralizes MDM** using PE5 kernel techniques:
  - Zeroes MDM callback pointers (process/thread/image/registry/object callbacks)
  - Detaches MDM minifilter drivers
  - Uses PE5's `AsmBlindCrowdStrike` technique adapted for MDM
  - Falls back to user-mode techniques if kernel access unavailable

#### EDR Detection & Evasion (Phase 2)

During recursive network enumeration, the enumerator:

- **Detects 16+ EDR Products**:
  - CrowdStrike Falcon
  - SentinelOne
  - Microsoft Defender for Endpoint
  - Carbon Black (VMware)
  - Trend Micro Apex One
  - Bitdefender GravityZone
  - Sophos Intercept X
  - CylancePROTECT
  - FireEye Endpoint Security
  - Palo Alto Cortex XDR
  - Elastic Endpoint Security
  - Cybereason
  - Secureworks Taegis
  - F-Secure
  - Kaspersky Endpoint Detection
  - Symantec Endpoint Protection

- **Applies Continuous Evasion** before enumerating each discovered host:
  - Kernel callback zeroing (process/thread/image/registry/object callbacks)
  - Minifilter detachment
  - ETW TI telemetry blinding
  - Direct syscalls (bypassing hooked APIs)
  - AMSI bypass (if present)
  - API unhooking

#### Recursive Network Discovery (W-SLAM Techniques)

Enhanced recursive enumeration using multiple discovery methods:

- **SMB Enumeration**: Share enumeration, user enumeration, session enumeration, open file enumeration
- **WMI Remote Enumeration**: Process enumeration, service enumeration, registry enumeration, software enumeration
- **NetBIOS Enumeration**: NetBIOS name resolution and service discovery
- **NetServerEnum**: Domain/workgroup server enumeration
- **NetSessionEnum**: Active session enumeration to discover connected hosts
- **NetFileEnum**: Open file enumeration to discover connected hosts
- **ARP Table Enumeration**: Network neighbor discovery via ARP tables
- **Route Table Enumeration**: Network topology discovery via routing tables
- **DNS Enumeration**: DNS record enumeration and reverse DNS lookups
- **LDAP/AD Enumeration**: Active Directory user/group/computer enumeration, GPO enumeration
- **SNMP Enumeration**: SNMP information gathering (if available)
- **Port Scanning**: Enhanced port scanning for common services (SMB, RDP, WinRM, SSH, etc.)

#### Post-Exploitation Indicators (WINCLOAK Patterns)

- AMSI/ETW/WFP detection
- COM hijacking opportunities
- WMI persistence checks
- Kerberos opportunities
- Rootkit indicators

#### Active Directory & Certificate Services (ACTIVEGAME Patterns)

- AD infrastructure enumeration
- Certificate services enumeration
- Certificate template vulnerability checks
- ADCS misconfiguration detection

#### WAF/Web Application Indicators (CORTISOL Patterns)

- WAF presence detection
- Web application technology enumeration
- Normalization bypass opportunities

#### C2 Infrastructure Opportunities (ROCKHAMMER Patterns)

- C2 opportunity enumeration
- Tunnel/proxy opportunity checks
- DNS tunneling opportunity detection

#### Steganography Opportunities (SLEEPYMONEY Patterns)

- Steganography opportunity enumeration
- File entropy analysis

## Build Requirements

### Compiler Options

**MinGW-w64:**
```bash
gcc --version  # Should be 8.0 or later
```

**MSVC (Visual Studio):**
```bash
cl  # Should be available in Developer Command Prompt
```

### Required Libraries

- `ws2_32` - Windows Sockets
- `iphlpapi` - IP Helper API
- `advapi32` - Advanced Windows 32 Base API
- `ole32` - OLE for Windows
- `oleaut32` - OLE Automation
- `wbemuuid` - WMI
- `wininet` - Windows Internet API
- `netapi32` - Network Management API
- `dnsapi` - DNS Client API
- `wldap32` - LDAP API
- `wsnmp32` - SNMP API
- `ntdsapi` - Active Directory API
- `secur32` - Security Support Provider Interface
- `bcrypt` - Windows Cryptography API

## Building

### Using Makefile (MinGW)

```bash
cd tools/ENUMERATOR
make
```

### Using build.bat (Windows)

```batch
cd tools\ENUMERATOR
build.bat
```

### Manual Build (MinGW)

```bash
gcc -Wall -Wextra -std=c99 -O2 \
    enumerator.c \
    token_acquisition.c \
    progress.c \
    pastebin.c \
    network_recursive.c \
    mdm_detection.c \
    mdm_neutralization.c \
    edr_detection.c \
    edr_evasion.c \
    -o enumerator.exe \
    -lws2_32 -liphlpapi -ladvapi32 -lole32 -loleaut32 -lwbemuuid \
    -lwininet -lnetapi32 -ldnsapi -lwldap32 -lwsnmp32 -lntdsapi \
    -lsecur32 -lbcrypt -lm
```

### Manual Build (MSVC)

```batch
cl /W4 /O2 /Fe:enumerator.exe \
    enumerator.c \
    token_acquisition.c \
    progress.c \
    pastebin.c \
    network_recursive.c \
    mdm_detection.c \
    mdm_neutralization.c \
    edr_detection.c \
    edr_evasion.c \
    ws2_32.lib iphlpapi.lib advapi32.lib ole32.lib oleaut32.lib \
    wbemuuid.lib wininet.lib netapi32.lib dnsapi.lib wldap32.lib \
    wsnmp32.lib ntdsapi.lib secur32.lib bcrypt.lib
```

## Configuration

### Pastebin API Key

Before building, edit `pastebin.c` and replace `DEFAULT_PASTEBIN_API_KEY` with your Pastebin API key:

1. Get API key from: https://pastebin.com/doc_api
2. Edit `pastebin.c` line with `#define DEFAULT_PASTEBIN_API_KEY`
3. Replace `"YOUR_API_KEY_HERE"` with your actual API key

## Usage

### Basic Usage

```bash
enumerator.exe
```

The program will:
1. Attempt to acquire SYSTEM token
2. **Detect and neutralize MDM software** (if SYSTEM token acquired)
3. Enumerate system information
4. Enumerate network information
5. Perform recursive network discovery with continuous EDR evasion
6. Enumerate VLAN structure
7. Display progress bar
8. Upload results to Pastebin (password: "ducknipples")
9. Display URL
10. Self-delete after user confirmation

### Execution Flow

```
┌─────────────────────────────────────┐
│   SYSTEM Token Acquisition          │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   MDM Detection & Neutralization     │
│   (Step 1 - Immediate)               │
│   - Detect MDM via registry/services│
│   - Zero MDM callback pointers      │
│   - Detach MDM minifilter drivers   │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   System Enumeration                 │
│   - OS, hardware, processes, etc.   │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   Network Enumeration                │
│   - Interfaces, routing, ARP, etc.  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   Recursive Network Discovery        │
│   (W-SLAM Techniques)                │
│   ┌──────────────────────────────┐  │
│   │ For each discovered host:    │  │
│   │ 1. Detect EDR products       │  │
│   │ 2. Apply EDR evasion         │  │
│   │ 3. Enumerate host             │  │
│   │ 4. Discover new hosts         │  │
│   │ 5. Recursively enumerate      │  │
│   └──────────────────────────────┘  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   Upload to Pastebin                 │
│   (with fallback services)           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   Self-Deletion                      │
└─────────────────────────────────────┘
```

## Output

The enumeration data is uploaded to Pastebin (or fallback service) with:
- Password: `ducknipples`
- Format: Plain text
- Expiration: 1 week
- Visibility: Unlisted

### Output Format

The enumeration output includes:

1. **System Information**
   - OS version, build number, service pack
   - Computer name, domain/workgroup
   - System architecture
   - Uptime and boot time
   - Current user

2. **MDM Detection & Neutralization Results**
   - Detected MDM products
   - Detection methods
   - Neutralization status (callback zeroing, driver detachment)

3. **EDR Detection & Evasion Results**
   - Detected EDR products (per host during recursive enumeration)
   - Evasion techniques applied
   - Evasion success/failure status

4. **Hardware Information**
   - CPU details
   - RAM (total, available, usage)
   - Disk drives (size, free space)
   - Network adapters

5. **Process Information**
   - All running processes (PID, name, path, command line)
   - Process relationships
   - Process privileges
   - Memory usage

6. **Service Information**
   - All services (name, state, PID)
   - Service dependencies
   - Service accounts

7. **Network Information**
   - Network interfaces (MAC, IP, subnet, gateway, DNS)
   - IP routing table
   - ARP table
   - Active TCP/UDP connections
   - Network discovery results

8. **Recursive Network Discovery Results**
   - Discovered hosts (IP, hostname, OS, services)
   - Discovery depth and method
   - Enumerated shares, users, processes, services
   - Active sessions and open files
   - DNS records and LDAP information

9. **VLAN Information**
   - VLAN adapters
   - VLAN IDs and names
   - Tagged/untagged ports
   - Trunk information

10. **Deep Analysis Results** (SYSTEM token required)
    - LSASS process memory access
    - Protected registry keys (SAM, LSA secrets)
    - Kernel-level information

## Token Acquisition Methods

The program attempts multiple methods to acquire SYSTEM token:

1. **PE5 Method**: Kernel-level token manipulation (falls back to Windows API)
2. **Windows API**: Direct SYSTEM process token duplication
3. **Service Token Stealing**: Steals token from a service running as SYSTEM

If all methods fail, enumeration continues without SYSTEM privileges (graceful degradation). MDM neutralization requires SYSTEM token and will be skipped if unavailable.

## MDM Detection & Neutralization

### Supported MDM Products

- Microsoft Intune
- VMware AirWatch
- MobileIron
- Workspace ONE
- Microsoft MDM

### Detection Methods

1. **Registry Keys**: Checks for MDM enrollment keys in `HKLM\SOFTWARE`
2. **Services**: Enumerates MDM-related services
3. **Processes**: Detects MDM agent processes
4. **Kernel Drivers**: Queries loaded drivers for MDM minifilter drivers

### Neutralization Techniques

1. **Callback Zeroing**: Uses PE5 kernel techniques to zero MDM callback pointers:
   - Process notify callbacks (`PspCreateProcessNotifyRoutine`)
   - Thread notify callbacks (`PspCreateThreadNotifyRoutine`)
   - Image load callbacks (`PspLoadImageNotifyRoutine`)
   - Registry callbacks (`CmRegisterCallback`)
   - Object callbacks (`ObRegisterCallbacks`)

2. **Minifilter Detachment**: Detaches MDM minifilter drivers from the filter manager

3. **Fallback**: If kernel access unavailable, attempts to stop MDM services (user-mode)

## EDR Detection & Evasion

### Detection Methods

For each EDR product, detection is performed via:
- Registry keys (EDR-specific registry locations)
- Services (EDR service names)
- Processes (EDR process names)
- Kernel drivers (EDR kernel drivers)
- File system (EDR installation paths)
- WMI queries (EDR product information)

### Evasion Techniques

Applied continuously during recursive network enumeration:

1. **Kernel Callback Zeroing**: Zeroes EDR callbacks before enumeration
2. **Minifilter Detachment**: Detaches EDR minifilter drivers
3. **ETW TI Blinding**: Blinds ETW telemetry at kernel level
4. **Direct Syscalls**: Uses direct syscalls instead of hooked APIs
5. **AMSI Bypass**: Bypasses AMSI if present
6. **API Unhooking**: Unhooks EDR API hooks

### Integration with W-SLAM

The enumerator integrates with W-SLAM's EDR evasion toolkit:
- Uses PE5 kernel exploitation techniques
- Leverages W-SLAM's callback zeroing functions
- Applies W-SLAM's minifilter detachment methods
- Uses W-SLAM's ETW blinding techniques

## Recursive Network Discovery

### Discovery Techniques

The enumerator uses multiple W-SLAM-inspired techniques for recursive network discovery:

1. **SMB Enumeration** (`discover_hosts_via_smb`)
   - Enumerates SMB shares
   - Enumerates remote users
   - Enumerates active sessions
   - Enumerates open files

2. **WMI Remote Enumeration** (`discover_hosts_via_wmi`)
   - Enumerates remote processes
   - Enumerates remote services
   - Enumerates remote registry
   - Enumerates installed software

3. **NetBIOS Enumeration** (`discover_hosts_via_netbios`)
   - NetBIOS name resolution
   - Service discovery

4. **NetServerEnum** (`discover_hosts_via_netserver`)
   - Domain/workgroup server enumeration
   - Server type identification

5. **NetSessionEnum** (`discover_hosts_via_netsession`)
   - Active session enumeration
   - Session user identification

6. **NetFileEnum** (`discover_hosts_via_netfile`)
   - Open file enumeration
   - File access identification

7. **ARP Table Enumeration** (`discover_hosts_via_arp_table`)
   - Network neighbor discovery
   - MAC address resolution

8. **Route Table Enumeration** (`discover_hosts_via_routes`)
   - Network topology discovery
   - Gateway identification

9. **DNS Enumeration** (`discover_hosts_via_dns`)
   - DNS record enumeration
   - Reverse DNS lookups

10. **LDAP/AD Enumeration** (`discover_hosts_via_ldap`)
    - Active Directory user enumeration
    - Group enumeration
    - Computer enumeration
    - GPO enumeration

11. **SNMP Enumeration** (`discover_hosts_via_snmp`)
    - SNMP information gathering
    - Network device discovery

### Recursion Depth

- Default maximum depth: 3
- Configurable via `enumerate_network_recursive()` parameter
- Prevents infinite loops with visited IP tracking

## Parser Toolkit

The enumerator includes a comprehensive Python-based parser toolkit (`parser/`) for post-processing enumeration data:

### Features

- **VLAN Diagram Generation**: Creates visual diagrams of VLAN structure (Mermaid, Graphviz, HTML/SVG)
- **Documentation Generation**: Generates easy-to-review documentation (Markdown, HTML, PDF)
- **CVE Correlation**: Correlates high-ranking CVEs (CVSS 7.0+) to detected software versions
- **Network Topology Visualization**: Visualizes network topology (Mermaid, Graphviz, interactive HTML, Cytoscape.js)
- **MITRE ATT&CK Mapping**: Maps detected activities to MITRE ATT&CK techniques
- **Attack Chain Generation**: Suggests attack chains and patterns drawing from:
  - W-SLAM
  - ROGUEPILOT
  - ROCKHAMMER
  - CORTISOL
  - ACTIVEGAME
  - SLEEPYMONEY
  - WINCLOAK
  - SWORD
- **ML-Guided Suggestions**: Optional integration with `ai/` directory for ML-guided attack chain ideas
- **Rich Browsing Interface**: TUI and Web interface for interactive exploration

### Parser Usage

```bash
cd parser
pip install -r requirements.txt
python parser.py <pastebin_url>
```

See `parser/README.md` for detailed parser documentation.

## Error Handling

- Graceful degradation if token acquisition fails
- Continues enumeration even if some modules fail
- Detailed error logging in output
- Fallback services if Pastebin fails
- MDM neutralization continues even if some techniques fail
- EDR evasion continues even if some techniques fail

## Security Considerations

- No hardcoded credentials (except Pastebin password)
- Minimal footprint
- Clean error handling
- No persistence mechanisms
- Self-contained executable
- Self-deletes after completion
- MDM neutralization requires SYSTEM privileges
- EDR evasion uses kernel-level techniques (requires SYSTEM privileges)
- All evasion techniques are logged in output

## Limitations

- Some features require SYSTEM privileges (MDM neutralization, deep analysis)
- Full VLAN enumeration requires SNMP/WMI access
- Network discovery performs subnet scanning (limited to 50 hosts per adapter for performance)
- Pastebin API key must be configured
- EDR evasion effectiveness depends on EDR product and configuration
- MDM neutralization effectiveness depends on MDM product and kernel access availability
- Recursive enumeration may be slow on large networks
- Some evasion techniques may be detected by advanced EDR

## Troubleshooting

### Build Errors

**Missing libraries:**
- Ensure all required libraries are available
- Check compiler installation
- Verify library paths in Makefile

**Linker errors:**
- Verify library paths
- Check library names match your compiler
- Ensure all source files are included in build

### Runtime Errors

**Token acquisition fails:**
- Normal if not running as administrator
- Enumeration continues without SYSTEM privileges
- MDM neutralization will be skipped
- Check error details in output

**MDM neutralization fails:**
- Requires SYSTEM token
- May fail if kernel access unavailable
- Check error details in output
- Enumeration continues anyway

**EDR evasion fails:**
- May fail if kernel access unavailable
- Some EDR products may detect evasion attempts
- Check error details in output
- Enumeration continues anyway

**Pastebin upload fails:**
- Check internet connection
- Verify API key is correct
- Program will try fallback services (Hastebin, 0x0.st, File.io)

**Recursive enumeration slow:**
- Normal on large networks
- Reduce maximum depth if needed
- Some discovery methods may timeout

## File Structure

```
ENUMERATOR/
├── enumerator.c          # Main enumeration logic
├── enumerator.h          # Main header file
├── token_acquisition.c   # SYSTEM token acquisition
├── token_acquisition.h
├── progress.c            # Progress bar display
├── progress.h
├── pastebin.c            # Pastebin upload
├── pastebin.h
├── network_recursive.c   # Recursive network discovery
├── network_recursive.h
├── mdm_detection.c       # MDM detection
├── mdm_detection.h
├── mdm_neutralization.c  # MDM neutralization
├── mdm_neutralization.h
├── edr_detection.c       # EDR detection
├── edr_detection.h
├── edr_evasion.c         # EDR evasion
├── edr_evasion.h
├── Makefile              # Build configuration
├── build.bat             # Windows build script
├── README.md             # This file
└── parser/               # Python parser toolkit
    ├── parser.py
    ├── vlan_diagram.py
    ├── doc_generator.py
    ├── cve_correlator.py
    ├── network_cve_correlator.py
    ├── topology_builder.py
    ├── mitre_mapper.py
    ├── technique_pattern_matcher.py
    ├── cve_chain_generator.py
    ├── multi_stage_chain_builder.py
    ├── ml_chain_suggester.py
    ├── chain_explorer.py
    ├── chain_browser_tui.py
    ├── web_interface/
    └── README.md
```

## License

See project license file.

## References

- GETMovin enumeration patterns
- W-SLAM enumeration techniques and EDR evasion
- PE5 kernel exploitation framework
- ROGUEPILOT, ROCKHAMMER, CORTISOL, ACTIVEGAME, SLEEPYMONEY, WINCLOAK, SWORD attack patterns
- Windows API documentation
- Pastebin API documentation
- MITRE ATT&CK framework

## Acknowledgments- W-SLAM framework for EDR evasion techniques
- PE5 framework for kernel-level token manipulation
- Various offensive security tools for enumeration patterns
