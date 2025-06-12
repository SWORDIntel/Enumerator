#!/usr/bin/env bash
###############################################################################
# hw-inventory-extended.sh — Comprehensive hardware and driver analyzer
#
# Creates detailed hardware inventory focused on driver requirements and firmware
# status. Identifies hardware with missing/incompatible drivers and firmware needs.
#
# Output:
#   • /tmp/hw-$(hostname)-YYYYMMDD_HHMM.md   (comprehensive markdown report)
#   • /tmp/hw-$(hostname)-YYYYMMDD_HHMM.csv  (tabular summary for automation)
#   • /tmp/hw-$(hostname)-YYYYMMDD_HHMM-driver-todo.txt (action items list)
#
# Features:
#   • ✅ Full hardware identification (CPU/memory/disks/PCI/USB/Thunderbolt)
#   • ✅ Current kernel modules vs available modules analysis
#   • ✅ Firmware requirement detection with version checking
#   • ✅ Driver compatibility analysis with kernel version
#   • ✅ Missing driver detection and alternative suggestions
#   • ✅ Boot firmware/ACPI tables analysis
#   • ✅ GPU configuration and driver compatibility check
#   • ✅ Wireless hardware detailed analysis
#   • ✅ Action items list for driver/firmware installation
###############################################################################

set -Eeuo pipefail
shopt -s lastpipe nullglob

# ── Environment & Globals ──────────────────────────────────────────────────
SCRIPT_VERSION="2.1.0"
KERNEL_VER=$(uname -r)
UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo "Unknown")
DATE_STAMP=$(date +%Y%m%d_%H%M)
HOSTNAME=$(hostname)
ARCH=$(uname -m)

# Output file paths
OUT_DIR="/tmp"
OUT_BASE="${OUT_DIR}/hw-${HOSTNAME}-${DATE_STAMP}"
OUT_MD="${OUT_BASE}.md"
OUT_CSV="${OUT_BASE}.csv"
OUT_TODO="${OUT_BASE}-driver-todo.txt"
OUT_DEB_PACKAGES="${OUT_BASE}-packages.txt"
OUT_MODULE_NEEDS="${OUT_BASE}-modules.txt"

# Stats counters
MISSING_DRIVERS=0
MISSING_FIRMWARE=0
NON_OPTIMAL_DRIVERS=0
TOTAL_DEVICES=0

# ── Helper Functions ────────────────────────────────────────────────────────
ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { printf '\e[1;34m[%s] %s\e[0m\n' "$(ts)" "$*"; }
warn() { printf '\e[1;33m[WARN] %s\e[0m\n' "$*"; }
error() { printf '\e[1;31m[ERROR] %s\e[0m\n' "$*"; }
success() { printf '\e[1;32m[OK] %s\e[0m\n' "$*"; }

# Initialize output files
init_outputs() {
    # Create directory if it doesn't exist
    [[ -d "$OUT_DIR" ]] || mkdir -p "$OUT_DIR"
    
    # Initialize main report with header
    cat > "$OUT_MD" <<EOF
# Hardware Inventory and Driver Analysis Report
**System**: $(hostname)  
**Date**: $(date '+%Y-%m-%d %H:%M:%S')  
**Kernel**: $(uname -r)  
**Distro**: $(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | head -n1 || echo "Unknown")  
**Architecture**: $(uname -m)  

---
EOF

    # Initialize CSV with header
    cat > "$OUT_CSV" <<EOF
TYPE,SLOT_ID,VENDOR_ID,DEVICE_ID,DESCRIPTION,KERNEL_DRIVER,AVAILABLE_DRIVERS,FIRMWARE_STATUS,ACTION_NEEDED
EOF

    # Initialize TODO list
    cat > "$OUT_TODO" <<EOF
# Driver and Firmware Action Items for $(hostname)
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Kernel: $(uname -r)

EOF

    # Initialize package list
    echo "# Recommended packages for installation" > "$OUT_DEB_PACKAGES"
    
    # Initialize module needs
    echo "# Modules that need to be built/loaded" > "$OUT_MODULE_NEEDS"
    
    # Create temp directory for detailed component analysis
    TMP_DETAIL_DIR=$(mktemp -d /tmp/hw-analysis.XXXXXX)
    trap 'rm -rf "$TMP_DETAIL_DIR"' EXIT
}

# Add section divider to markdown
divider() { 
    printf '\n---\n\n' >> "$OUT_MD"
}

# Add a device action item to TODO list
add_action_item() {
    local type=$1
    local device=$2
    local description=$3
    local action=$4
    
    printf "## %s: %s\n%s\n\n%s\n\n" "$type" "$device" "$description" "$action" >> "$OUT_TODO"
    
    case "$action" in
        *apt-get*install*)
            echo "${action#*install }" | tr ' ' '\n' | grep -v '^$' >> "$OUT_DEB_PACKAGES"
            ;;
        *modprobe*)
            echo "${action#*modprobe }" | tr ' ' '\n' | grep -v '^$' >> "$OUT_MODULE_NEEDS"
            ;;
    esac
}

# Check if a command exists
cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ── Section: System Summary ───────────────────────────────────────────────────
system_summary() {
    log "Generating system overview"

    {
        echo "# System Overview"
        divider
        
        echo "## System Information"
        echo "| Component | Details |"
        echo "|-----------|---------|"
        echo "| Hostname | $(hostname) |"
        echo "| Kernel | $(uname -r) |"
        echo "| Architecture | $(uname -m) |"
        echo "| Distribution | $(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | head -n1 || echo "Unknown") |"
        echo "| Boot Mode | $([ -d /sys/firmware/efi ] && echo "UEFI" || echo "BIOS/Legacy") |"
        echo "| Machine Type | $(dmidecode -s system-product-name 2>/dev/null || echo "Unknown") |"
        echo "| Manufacturer | $(dmidecode -s system-manufacturer 2>/dev/null || echo "Unknown") |"
        echo
    } >> "$OUT_MD"
}

# ── Section: CPU & Memory ─────────────────────────────────────────────────
cpu_memory() {
    log "Analyzing CPU and memory"

    local cpu_manufacturer=$(lscpu | grep "Vendor ID" | awk -F': *' '{print $2}' | xargs)
    local cpu_model=$(lscpu | grep "Model name" | awk -F': *' '{print $2}' | xargs)
    local cpu_cores=$(lscpu | grep "^CPU(s)" | awk -F': *' '{print $2}' | xargs)
    local cpu_threads=$(lscpu | grep "Thread(s) per core" | awk -F': *' '{print $2}' | xargs)
    local cpu_freq=$(lscpu | grep "CPU max MHz" | awk -F': *' '{print $2}' | xargs)
    local cpu_driver="native_kernel"
    
    # Check for CPU microcode updates
    local microcode_status="Unknown"
    if grep -q "microcode" /proc/cpuinfo; then
        microcode_status="Loaded"
    else
        microcode_status="Missing"
        case "$cpu_manufacturer" in
            *Intel*)
                add_action_item "CPU" "$cpu_model" "Missing Intel CPU microcode" \
                "Install Intel microcode updates:\n\`\`\`\napt-get install intel-microcode\n\`\`\`"
                MISSING_FIRMWARE=$((MISSING_FIRMWARE + 1))
                ;;
            *AMD*)
                add_action_item "CPU" "$cpu_model" "Missing AMD CPU microcode" \
                "Install AMD microcode updates:\n\`\`\`\napt-get install amd64-microcode\n\`\`\`"
                MISSING_FIRMWARE=$((MISSING_FIRMWARE + 1))
                ;;
        esac
    fi

    # Gather memory info
    local mem_total=$(free -h | grep "Mem:" | awk '{print $2}')
    local mem_speed=$(dmidecode -t memory 2>/dev/null | grep -m1 "Speed" | awk '{print $2 " " $3}')
    local mem_type=$(dmidecode -t memory 2>/dev/null | grep -m1 "Type:" | awk '{print $2}')
    
    # Check for CPU throttling or thermal issues
    local throttling_status="Normal"
    if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq ]; then
        local current_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)
        local max_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)
        
        if [ "$current_freq" -lt "$max_freq" ]; then
            local freq_diff=$((max_freq - current_freq))
            local throttle_percent=$((freq_diff * 100 / max_freq))
            
            if [ "$throttle_percent" -gt 20 ]; then
                throttling_status="Throttled ($throttle_percent% below max)"
                warn "CPU appears to be throttling ($throttle_percent% below maximum frequency)"
                add_action_item "CPU" "$cpu_model" "CPU is throttling ($throttle_percent% below maximum)" \
                "Check cooling system and power management settings. Consider:\n\
                1. Cleaning fans and heatsinks\n\
                2. Replacing thermal paste\n\
                3. Checking for BIOS/firmware updates\n\
                4. Installing thermald:\n\`\`\`\napt-get install thermald\n\`\`\`"
            fi
        fi
    fi

    {
        echo "# CPU & Memory"
        divider
        
        echo "## CPU Information"
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Manufacturer | $cpu_manufacturer |"
        echo "| Model | $cpu_model |"
        echo "| Physical Cores | $cpu_cores |"
        echo "| Threads per Core | $cpu_threads |"
        echo "| Maximum Frequency | $cpu_freq MHz |"
        echo "| Microcode | $microcode_status |"
        echo "| Throttling Status | $throttling_status |"
        echo "| Virtualization | $(lscpu | grep -i "Virtualization" | awk -F': *' '{print $2}' || echo "Not supported") |"
        echo
        
        echo "## CPU Governors and Scaling"
        echo "\`\`\`"
        for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            if [ -f "$governor" ]; then
                echo "$(basename $(dirname $(dirname "$governor"))): $(cat "$governor")"
            fi
        done
        echo "\`\`\`"
        echo
        
        echo "## Memory Information"
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Total Memory | $mem_total |"
        echo "| Memory Type | $mem_type |"
        echo "| Memory Speed | $mem_speed |"
        echo
        
        echo "### Memory Modules"
        echo "\`\`\`"
        dmidecode -t memory 2>/dev/null | grep -A12 "Memory Device" | grep -E "Size|Type|Speed|Locator|Manufacturer" || echo "Memory information unavailable"
        echo "\`\`\`"
        echo
        
        echo "## Memory Usage"
        echo "\`\`\`"
        free -h
        echo "\`\`\`"
        echo
    } >> "$OUT_MD"

    # Add to CSV
    echo "CPU,0,$cpu_manufacturer,$(echo $cpu_model | tr ',' ' '),$cpu_model,$cpu_driver,native,${microcode_status},$([ "$microcode_status" == "Missing" ] && echo "YES" || echo "NO")" >> "$OUT_CSV"
    TOTAL_DEVICES=$((TOTAL_DEVICES + 1))
}

# ── Section: BIOS/UEFI/ACPI ────────────────────────────────────────────────
firmware_analysis() {
    log "Analyzing system firmware and ACPI tables"

    local boot_mode="Unknown"
    [ -d /sys/firmware/efi ] && boot_mode="UEFI" || boot_mode="BIOS/Legacy"
    
    local bios_vendor=$(dmidecode -s bios-vendor 2>/dev/null || echo "Unknown")
    local bios_version=$(dmidecode -s bios-version 2>/dev/null || echo "Unknown")
    local bios_date=$(dmidecode -s bios-release-date 2>/dev/null || echo "Unknown")
    local sys_manufacturer=$(dmidecode -s system-manufacturer 2>/dev/null || echo "Unknown")
    local sys_product=$(dmidecode -s system-product-name 2>/dev/null || echo "Unknown")
    
    # Check for ACPI errors in dmesg
    local acpi_warnings=$(dmesg | grep -i "acpi.*warn" | wc -l)
    local acpi_errors=$(dmesg | grep -i "acpi.*error" | wc -l)
    
    # ACPI action needed check
    local acpi_action_needed="NO"
    if [ "$acpi_errors" -gt 0 ]; then
        acpi_action_needed="YES"
        add_action_item "FIRMWARE" "ACPI Tables" "$acpi_errors ACPI errors detected" \
        "Check for BIOS/UEFI updates from $sys_manufacturer for $sys_product.\n\
        Consider booting with kernel parameters:\n\`\`\`\nacpi=force acpi_osi=Linux\n\`\`\`"
        MISSING_FIRMWARE=$((MISSING_FIRMWARE + 1))
    fi
    
    # Check for outdated firmware based on release date
    local fw_status="Current"
    if [[ "$bios_date" != "Unknown" && "$bios_date" < "$(date -d '1 year ago' '+%Y-%m')" ]]; then
        fw_status="Potentially outdated (older than 1 year)"
        add_action_item "FIRMWARE" "$sys_product BIOS/UEFI" "Firmware may be outdated ($bios_version from $bios_date)" \
        "Check for BIOS/UEFI updates from $sys_manufacturer for $sys_product"
        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
    fi

    {
        echo "# System Firmware"
        divider
        
        echo "## BIOS/UEFI Information"
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Boot Mode | $boot_mode |"
        echo "| BIOS Vendor | $bios_vendor |"
        echo "| BIOS Version | $bios_version |"
        echo "| BIOS Date | $bios_date |"
        echo "| System Manufacturer | $sys_manufacturer |"
        echo "| System Model | $sys_product |"
        echo "| Firmware Status | $fw_status |"
        echo
        
        echo "## ACPI Tables"
        echo "| Table | Status |"
        echo "|-------|--------|"
        
        # List ACPI tables
        if cmd_exists acpidump; then
            acpidump 2>/dev/null | grep -E 'ACPI Table' | while read -r line; do
                local table_name=$(echo "$line" | awk '{print $3}')
                local table_status="Valid"
                if dmesg | grep -i "acpi.*error.*$table_name" &>/dev/null; then
                    table_status="⚠️ Error detected"
                fi
                echo "| $table_name | $table_status |"
            done
        else
            if [ -d /sys/firmware/acpi/tables ]; then
                for table in /sys/firmware/acpi/tables/*; do
                    local table_name=$(basename "$table")
                    local table_status="Valid"
                    if dmesg | grep -i "acpi.*error.*$table_name" &>/dev/null; then
                        table_status="⚠️ Error detected"
                    fi
                    echo "| $table_name | $table_status |"
                done
            else
                echo "| ACPI tables list | Not available |"
            fi
        fi
        
        echo
        
        echo "## ACPI Diagnostics"
        echo "| Metric | Count |"
        echo "|--------|-------|"
        echo "| ACPI Warnings | $acpi_warnings |"
        echo "| ACPI Errors | $acpi_errors |"
        
        if [ "$acpi_errors" -gt 0 ]; then
            echo
            echo "### ACPI Error Details"
            echo "\`\`\`"
            dmesg | grep -i "acpi.*error" | head -10
            echo "\`\`\`"
        fi
        
        echo
        
        # IOMMU/Virtualization status
        echo "## IOMMU Status"
        if dmesg | grep -i -e "DMAR" -e "IOMMU" | grep -i enabled &>/dev/null; then
            echo "IOMMU is **enabled**"
        else
            echo "IOMMU appears to be **disabled** or not supported"
            add_action_item "VIRTUALIZATION" "IOMMU" "IOMMU appears to be disabled" \
            "Enable IOMMU in BIOS/UEFI settings (may be labeled as VT-d for Intel or AMD-Vi for AMD).\n\
            For kernel parameters, add: \`intel_iommu=on\` or \`amd_iommu=on\` in GRUB configuration."
        fi
        
        echo
    } >> "$OUT_MD"
    
    # Add to CSV
    echo "FIRMWARE,0,$bios_vendor,$bios_version,$sys_product BIOS/UEFI,N/A,N/A,$fw_status,$acpi_action_needed" >> "$OUT_CSV"
    TOTAL_DEVICES=$((TOTAL_DEVICES + 1))
}

# ── Section: Block Devices ────────────────────────────────────────────────
analyze_storage() {
    log "Analyzing storage devices and controllers"

    {
        echo "# Storage Devices"
        divider
        
        echo "## Block Devices Overview"
        echo "\`\`\`"
        lsblk -o NAME,MODEL,SIZE,TYPE,TRAN,SERIAL,FSTYPE | column -t
        echo "\`\`\`"
        echo
        
        # Get storage controllers
        echo "## Storage Controllers"
        echo "| Controller | Driver | Status |"
        echo "|------------|--------|--------|"
        
        lspci -nnk | grep -A3 "storage\|RAID\|SATA\|SCSI\|NVM" | grep -v "^--" | while read -r controller; do
            if [[ $controller =~ ^([0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9])\ (.+)\ \[(.+)\]:\ (.+)$ ]]; then
                local slot="${BASH_REMATCH[1]}"
                local class="${BASH_REMATCH[2]}"
                local vendor_device="${BASH_REMATCH[3]}"
                local description="${BASH_REMATCH[4]}"
                
                # Get driver
                local driver=$(lspci -s "$slot" -nvk | grep -A2 "Kernel driver in use" | awk -F': ' '/Kernel driver in use/ {print $2}')
                local driver_modules=$(lspci -s "$slot" -nvk | grep -A2 "Kernel modules" | awk -F': ' '/Kernel modules/ {print $2}')
                
                # Check driver status
                local driver_status="✅ Optimal"
                if [ -z "$driver" ]; then
                    driver_status="❌ No driver"
                    driver="—"
                    MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
                    add_action_item "STORAGE" "$description" "Missing driver for storage controller" \
                    "Available modules: $driver_modules\n\nTry loading with:\n\`\`\`\nmodprobe ${driver_modules/,/ }\n\`\`\`\n\nOr install:\n\`\`\`\napt-get install linux-modules-extra-$(uname -r)\n\`\`\`"
                elif [[ "$description" == *NVM* && "$driver" != "nvme" ]]; then
                    driver_status="⚠️ NVMe controller not using nvme driver"
                    NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                    add_action_item "STORAGE" "$description" "NVMe controller not using optimal driver" \
                    "Try loading the nvme driver:\n\`\`\`\nmodprobe nvme\n\`\`\`"
                fi
                
                echo "| $description | $driver | $driver_status |"
                
                # Add to CSV
                local need_action=$([ "$driver_status" != "✅ Optimal" ] && echo "YES" || echo "NO")
                echo "STORAGE,$slot,$(echo $vendor_device | cut -d: -f1),$(echo $vendor_device | cut -d: -f2),$description,$driver,$driver_modules,${driver_status#* },$need_action" >> "$OUT_CSV"
                TOTAL_DEVICES=$((TOTAL_DEVICES + 1))
            fi
        done
        
        echo
        
        # SMART status if available
        if cmd_exists smartctl; then
            echo "## SMART Status"
            echo "| Device | Model | Health | Temperature | Power On Hours |"
            echo "|--------|-------|--------|-------------|----------------|"
            
            lsblk -d -o NAME,TYPE | grep disk | awk '{print $1}' | while read -r disk; do
                local model=$(smartctl -i /dev/$disk 2>/dev/null | grep "Device Model" | awk -F': *' '{print $2}' || echo "Unknown")
                local health=$(smartctl -H /dev/$disk 2>/dev/null | grep "overall-health" | awk -F': *' '{print $2}' || echo "Unknown")
                local temp=$(smartctl -A /dev/$disk 2>/dev/null | grep "Temperature_Celsius" | awk '{print $10}' || echo "—")
                local hours=$(smartctl -A /dev/$disk 2>/dev/null | grep "Power_On_Hours" | awk '{print $10}' || echo "—")
                
                echo "| /dev/$disk | $model | $health | ${temp}°C | $hours |"
            done
            
            echo
        fi
        
        # NVMe specific information
        if cmd_exists nvme; then
            echo "## NVMe Devices"
            echo "\`\`\`"
            nvme list 2>/dev/null || echo "No NVMe devices found or nvme tool not available"
            echo "\`\`\`"
            echo
        fi
        
        # RAID status if available
        if cmd_exists mdadm; then
            echo "## Software RAID Status"
            echo "\`\`\`"
            mdadm --detail --scan 2>/dev/null || echo "No software RAID configurations found"
            echo "\`\`\`"
            echo
        fi
        
        # Check for optimal I/O schedulers
        echo "## I/O Schedulers"
        echo "| Device | Current Scheduler | Recommended |"
        echo "|--------|-------------------|-------------|"
        
        for disk in /sys/block/*/queue/scheduler; do
            if [ -f "$disk" ]; then
                local dev=$(echo "$disk" | cut -d'/' -f4)
                local current=$(cat "$disk" | grep -o '\[.*\]' | tr -d '[]')
                local recommended="mq-deadline"
                
                if [[ "$dev" == nvme* ]]; then
                    recommended="none"
                elif [[ "$dev" == sd* ]]; then
                    if grep -q "ssd" /sys/block/$dev/queue/rotational; then
                        recommended="mq-deadline"
                    else
                        recommended="bfq"
                    fi
                fi
                
                local status_icon="✅"
                if [ "$current" != "$recommended" ]; then
                    status_icon="⚠️"
                    add_action_item "STORAGE" "/dev/$dev" "Suboptimal I/O scheduler: $current" \
                    "Change to recommended scheduler ($recommended):\n\`\`\`\necho $recommended > /sys/block/$dev/queue/scheduler\n\`\`\`\n\nFor permanent change, add to /etc/udev/rules.d/60-scheduler.rules:\n\`\`\`\nACTION==\"add|change\", KERNEL==\"$dev\", ATTR{queue/scheduler}=\"$recommended\"\n\`\`\`"
                fi
                
                echo "| /dev/$dev | $current | $status_icon $recommended |"
            fi
        done
        
        echo
    } >> "$OUT_MD"
}

# ── Section: PCI Devices ────────────────────────────────────────────────────
analyze_pci_devices() {
    log "Analyzing PCI devices and drivers"

    # First, extract vendor names from IDs database
    local pci_ids=$(mktemp)
    if [ -f /usr/share/misc/pci.ids ]; then
        cp /usr/share/misc/pci.ids "$pci_ids"
    elif [ -f /usr/share/hwdata/pci.ids ]; then
        cp /usr/share/hwdata/pci.ids "$pci_ids"
    else
        # If no PCI IDs database found, try to download it
        if cmd_exists curl; then
            curl -s https://pci-ids.ucw.cz/v2.2/pci.ids > "$pci_ids" || echo "# PCI ID database not available" > "$pci_ids"
        elif cmd_exists wget; then
            wget -q -O "$pci_ids" https://pci-ids.ucw.cz/v2.2/pci.ids || echo "# PCI ID database not available" > "$pci_ids"
        else
            echo "# PCI ID database not available" > "$pci_ids"
        fi
    fi

    {
        echo "# PCI Devices"
        divider
        
        echo "## PCI Devices Overview"
        echo "| Slot | Class | Vendor | Device | Driver | Status |"
        echo "|------|-------|--------|--------|--------|--------|"
        
        lspci -nnk | while read -r line; do
            if [[ $line =~ ^([0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9])\ (.+)\ \[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\](:\ (.+))?$ ]]; then
                local slot="${BASH_REMATCH[1]}"
                local class="${BASH_REMATCH[2]}"
                local vendor_id="${BASH_REMATCH[3]}"
                local device_id="${BASH_REMATCH[4]}"
                local description="${BASH_REMATCH[6]}"
                
                # Get vendor name from PCI ID database
                local vendor_name=$(grep -A 1 "^$vendor_id" "$pci_ids" | head -1 | cut -c 6- || echo "Unknown")
                
                # Get current driver and available modules
                local driver=$(lspci -s "$slot" -k | grep -A 1 "Kernel driver in use" | awk -F': ' '/Kernel driver in use/ {print $2}')
                local available_drivers=$(lspci -s "$slot" -k | grep -A 1 "Kernel modules" | awk -F': ' '/Kernel modules/ {print $2}')
                
                # Check for firmware issues
                local firmware_status="✅"
                if dmesg | grep -i "$slot.*firmware" | grep -iE "missing|failed|error" &>/dev/null; then
                    firmware_status="❌ Missing firmware"
                    MISSING_FIRMWARE=$((MISSING_FIRMWARE + 1))
                    
                    # Identify common firmware packages based on the device
                    local fw_package=""
                    case "$vendor_id:$device_id" in
                        # Intel Wi-Fi
                        8086:*)
                            if [[ "$class" == *"Network controller"* ]]; then
                                fw_package="firmware-iwlwifi"
                            fi
                            ;;
                        # AMD GPUs
                        1002:*)
                            fw_package="firmware-amd-graphics"
                            ;;
                        # Broadcom Wi-Fi
                        14e4:*)
                            if [[ "$class" == *"Network controller"* ]]; then
                                fw_package="firmware-b43-installer firmware-brcm80211"
                            fi
                            ;;
                        # Realtek Wi-Fi/Ethernet
                        10ec:*)
                            fw_package="firmware-realtek"
                            ;;
                        # Atheros Wi-Fi
                        168c:*)
                            fw_package="firmware-atheros"
                            ;;
                    esac
                    
                    if [ -n "$fw_package" ]; then
                        add_action_item "FIRMWARE" "$vendor_name $description" "Missing firmware for PCI device" \
                        "Install firmware package:\n\`\`\`\napt-get install $fw_package\n\`\`\`"
                    else
                        add_action_item "FIRMWARE" "$vendor_name $description" "Missing firmware for PCI device" \
                        "Install firmware-misc-nonfree package:\n\`\`\`\napt-get install firmware-misc-nonfree\n\`\`\`"
                    fi
                fi
                
                # Check driver status
                local driver_status="✅ Using optimal driver"
                if [ -z "$driver" ]; then
                    driver="—"
                    if [ -n "$available_drivers" ]; then
                        driver_status="❌ Driver available but not loaded"
                        add_action_item "DRIVER" "$vendor_name $description" "Driver not loaded for PCI device" \
                        "Available modules: $available_drivers\n\nLoad with:\n\`\`\`\nmodprobe ${available_drivers/,/ }\n\`\`\`"
                        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                    else
                        driver_status="❌ No driver available"
                        MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
                        
                        # Special handling for common devices
                        local recommendation=""
                        case "$vendor_id:$device_id" in
                            # NVIDIA GPUs
                            10de:*)
                                recommendation="Install NVIDIA drivers:\n\`\`\`\napt-get install nvidia-driver\n\`\`\`"
                                ;;
                            # AMD GPUs
                            1002:*)
                                recommendation="Install AMD drivers:\n\`\`\`\napt-get install firmware-amd-graphics mesa-vulkan-drivers\n\`\`\`"
                                ;;
                            *)
                                recommendation="Check if this device needs a proprietary driver or if support is available in a newer kernel."
                                ;;
                        esac
                        
                        add_action_item "DRIVER" "$vendor_name $description" "No driver available for PCI device" "$recommendation"
                    fi
                elif dmesg | grep -i "$driver.*failed\|$driver.*error" &>/dev/null; then
                    driver_status="⚠️ Driver loaded but has errors"
                    NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                    add_action_item "DRIVER" "$vendor_name $description" "Driver loaded but has errors" \
                    "Check dmesg for specific errors related to $driver driver.\nConsider trying alternative driver(s) if available: $available_drivers"
                fi
                
                echo "| $slot | $class | $vendor_name | $description | $driver | $driver_status $firmware_status |"
                
                # Add to CSV
                local need_action="NO"
                if [[ "$driver_status" != "✅ Using optimal driver" || "$firmware_status" != "✅" ]]; then
                    need_action="YES"
                fi
                
                echo "PCI,$slot,$vendor_id,$device_id,$description,$driver,$available_drivers,${firmware_status#* },${need_action}" >> "$OUT_CSV"
                TOTAL_DEVICES=$((TOTAL_DEVICES + 1))
                
                # Detailed analysis of important device classes
                case "$class" in
                    *"VGA compatible controller"*|*"Display controller"*)
                        analyze_graphics_card "$slot" "$vendor_id" "$device_id" "$description" "$driver" "$available_drivers"
                        ;;
                    *"Network controller"*)
                        analyze_wireless_device "$slot" "$vendor_id" "$device_id" "$description" "$driver" "$available_drivers"
                        ;;
                    *"Ethernet controller"*)
                        analyze_ethernet_device "$slot" "$vendor_id" "$device_id" "$description" "$driver" "$available_drivers"
                        ;;
                esac
            fi
        done
        
        echo
    } >> "$OUT_MD"
    
    rm -f "$pci_ids"
}

# ── GPU Specific Analysis ────────────────────────────────────────────────────
analyze_graphics_card() {
    local slot="$1"
    local vendor_id="$2"
    local device_id="$3"
    local description="$4"
    local driver="$5"
    local available_drivers="$6"
    
    local vendor_name="Unknown"
    case "$vendor_id" in
        10de) vendor_name="NVIDIA" ;;
        1002) vendor_name="AMD" ;;
        8086) vendor_name="Intel" ;;
        *) vendor_name="Unknown" ;;
    esac
    
    log "Analyzing GPU: $vendor_name $description"
    
    # Gather GPU specific information
    local gpu_info_file="$TMP_DETAIL_DIR/gpu_${slot//:/}_info.txt"
    
    # Basic GPU info
    lspci -v -s "$slot" > "$gpu_info_file"
    
    # Check for optimal driver
    local optimal_driver="false"
    local recommended_driver=""
    local driver_package=""
    
    case "$vendor_name" in
        "NVIDIA")
            # Check if using NVIDIA or nouveau
            if [ "$driver" == "nvidia" ]; then
                optimal_driver="true"
                # Check NVIDIA driver version
                if cmd_exists nvidia-smi; then
                    local nvidia_version=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null)
                    echo "NVIDIA Driver Version: $nvidia_version" >> "$gpu_info_file"
                fi
            else
                recommended_driver="nvidia"
                driver_package="nvidia-driver"
            fi
            ;;
            
        "AMD")
            # Check if using amdgpu
            if [ "$driver" == "amdgpu" ]; then
                optimal_driver="true"
            else
                recommended_driver="amdgpu"
                driver_package="firmware-amd-graphics mesa-vulkan-drivers"
            fi
            ;;
            
        "Intel")
            # Check if using i915
            if [ "$driver" == "i915" ]; then
                optimal_driver="true"
            else
                recommended_driver="i915"
                driver_package="xserver-xorg-video-intel"
            fi
            ;;
    esac
    
    # Check for firmware issues
    local firmware_status=$(dmesg | grep -i "$slot\|$driver" | grep -i "firmware" | grep -iE "missing|failed|error" || echo "")
    
    # Check for Vulkan support
    local vulkan_support="Unknown"
    if cmd_exists vulkaninfo; then
        vulkaninfo &> "$TMP_DETAIL_DIR/vulkan_info.txt"
        if grep -q "$vendor_name" "$TMP_DETAIL_DIR/vulkan_info.txt"; then
            vulkan_support="Available"
        else
            vulkan_support="Not available"
        fi
    fi
    
    # Check current rendering in X11 if available
    local glx_info="Not available"
    if cmd_exists glxinfo; then
        glxinfo | grep "OpenGL renderer" > "$TMP_DETAIL_DIR/glx_info.txt"
        glx_info=$(cat "$TMP_DETAIL_DIR/glx_info.txt" 2>/dev/null || echo "Not available")
    fi
    
    {
        echo "## GPU Details: $vendor_name $description"
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Slot | $slot |"
        echo "| Vendor | $vendor_name |"
        echo "| Model | $description |"
        echo "| Driver in use | $driver |"
        echo "| Available drivers | $available_drivers |"
        echo "| Vulkan support | $vulkan_support |"
        echo "| Current renderer | $glx_info |"
        echo "| Using optimal driver | $([ "$optimal_driver" == "true" ] && echo "Yes ✅" || echo "No ❌") |"
        echo
        
        if [ "$optimal_driver" != "true" ] && [ -n "$recommended_driver" ]; then
            echo "### Driver Recommendation"
            echo "This GPU should be using the $recommended_driver driver for optimal performance."
            echo
            add_action_item "GPU" "$vendor_name $description" "Not using optimal driver" \
            "Install recommended driver package:\n\`\`\`\napt-get install $driver_package\n\`\`\`"
            NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
        fi
        
        if [ -n "$firmware_status" ]; then
            echo "### Firmware Issues Detected"
            echo "\`\`\`"
            echo "$firmware_status"
            echo "\`\`\`"
            echo
            add_action_item "GPU FIRMWARE" "$vendor_name $description" "GPU firmware issue detected" \
            "Install firmware packages:\n\`\`\`\napt-get install firmware-misc-nonfree $([ "$vendor_name" == "AMD" ] && echo "firmware-amd-graphics")\n\`\`\`"
            MISSING_FIRMWARE=$((MISSING_FIRMWARE + 1))
        fi
    } >> "$OUT_MD"
}

# ── Wireless Device Analysis ────────────────────────────────────────────────
analyze_wireless_device() {
    local slot="$1"
    local vendor_id="$2"
    local device_id="$3"
    local description="$4"
    local driver="$5"
    local available_drivers="$6"
    
    log "Analyzing wireless device: $description"
    
    # Get current wireless status
    local wifi_interface=""
    local wifi_status="Not configured"
    local regulatory_domain="Unknown"
    
    if cmd_exists iw; then
        # Find which interface corresponds to this PCI device
        for iface in /sys/class/net/*; do
            if [ -L "$iface/device" ]; then
                local dev_path=$(readlink -f "$iface/device")
                local pci_slot=$(basename "$(dirname "$dev_path")")
                if [ "${pci_slot//0000:}" = "$slot" ]; then
                    wifi_interface=$(basename "$iface")
                    break
                fi
            fi
        done
        
        if [ -n "$wifi_interface" ]; then
            # Get interface status
            iw dev "$wifi_interface" info > "$TMP_DETAIL_DIR/wifi_${wifi_interface}_info.txt" 2>/dev/null || true
            iw dev "$wifi_interface" scan > "$TMP_DETAIL_DIR/wifi_${wifi_interface}_scan.txt" 2>/dev/null || true
            
            # Check regulatory domain
            if cmd_exists iw; then
                regulatory_domain=$(iw reg get | grep -i "country" | head -1 | awk '{print $2}' || echo "Unset")
            fi
            
            # Check link status
            if [ -f "/sys/class/net/$wifi_interface/operstate" ]; then
                wifi_status=$(cat "/sys/class/net/$wifi_interface/operstate")
            fi
        fi
    fi
    
    # Check for firmware issues
    local firmware_status="✅ No issues detected"
    if dmesg | grep -iE "$slot|$driver|$wifi_interface" | grep -iE "firmware|fw" | grep -iE "missing|failed|error" &>/dev/null; then
        firmware_status="❌ Firmware issues detected"
        MISSING_FIRMWARE=$((MISSING_FIRMWARE + 1))
        
        # Determine appropriate firmware package
        local fw_package=""
        case "$vendor_id" in
            # Intel
            8086)
                fw_package="firmware-iwlwifi"
                ;;
            # Broadcom
            14e4)
                fw_package="firmware-b43-installer firmware-brcm80211"
                ;;
            # Realtek
            10ec)
                fw_package="firmware-realtek"
                ;;
            # Atheros
            168c)
                fw_package="firmware-atheros"
                ;;
            # Others
            *)
                fw_package="firmware-misc-nonfree"
                ;;
        esac
        
        add_action_item "WIRELESS" "$description" "Missing firmware for wireless device" \
        "Install firmware package:\n\`\`\`\napt-get install $fw_package\n\`\`\`"
    fi
    
    # Check for optimal driver
    local driver_recommendation=""
    if [ -z "$driver" ]; then
        driver_recommendation="No driver loaded. Available modules: $available_drivers"
        MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
        
        add_action_item "WIRELESS" "$description" "No driver loaded for wireless device" \
        "Available modules: $available_drivers\n\nLoad with:\n\`\`\`\nmodprobe ${available_drivers/,/ }\n\`\`\`"
    elif dmesg | grep -i "$driver" | grep -iE "failed|error" &>/dev/null; then
        driver_recommendation="Driver loaded but has errors. Check dmesg for details."
        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
        
        add_action_item "WIRELESS" "$description" "Driver errors for wireless device" \
        "Check for error messages:\n\`\`\`\ndmesg | grep -i '$driver'\n\`\`\`\n\nConsider alternative drivers if available: $available_drivers"
    fi
    
    # Regulatory domain check
    local reg_recommendation=""
    if [ "$regulatory_domain" == "Unset" ] || [ "$regulatory_domain" == "00" ]; then
        reg_recommendation="Regulatory domain not set. This may limit available channels and transmit power."
        add_action_item "WIRELESS" "Regulatory Domain" "Wireless regulatory domain not set" \
        "Set your country code:\n\`\`\`\niw reg set US  # Replace with your country code\n\`\`\`\n\nFor permanent setting, add to /etc/default/crda:\n\`\`\`\nCRDA_DOMAIN=US  # Replace with your country code\n\`\`\`"
    fi
    
    {
        echo "## Wireless Device: $description"
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Slot | $slot |"
        echo "| Device | $description |"
        echo "| Driver | $driver |"
        echo "| Available drivers | $available_drivers |"
        echo "| Interface | $wifi_interface |"
        echo "| Status | $wifi_status |"
        echo "| Regulatory domain | $regulatory_domain |"
        echo "| Firmware status | $firmware_status |"
        echo
        
        if [ -n "$driver_recommendation" ]; then
            echo "### Driver Status"
            echo "$driver_recommendation"
            echo
        fi
        
        if [ -n "$reg_recommendation" ]; then
            echo "### Regulatory Domain"
            echo "$reg_recommendation"
            echo
        fi
        
        # Show supported capabilities if interface is available
        if [ -n "$wifi_interface" ] && [ -f "$TMP_DETAIL_DIR/wifi_${wifi_interface}_info.txt" ]; then
            echo "### Wireless Capabilities"
            echo "\`\`\`"
            cat "$TMP_DETAIL_DIR/wifi_${wifi_interface}_info.txt"
            echo "\`\`\`"
            echo
        fi
    } >> "$OUT_MD"
}

# ── Ethernet Device Analysis ────────────────────────────────────────────────
analyze_ethernet_device() {
    local slot="$1"
    local vendor_id="$2"
    local device_id="$3"
    local description="$4"
    local driver="$5"
    local available_drivers="$6"
    
    log "Analyzing ethernet device: $description"
    
    # Find corresponding network interface
    local eth_interface=""
    for iface in /sys/class/net/*; do
        if [ -L "$iface/device" ]; then
            local dev_path=$(readlink -f "$iface/device")
            local pci_slot=$(basename "$(dirname "$dev_path")")
            if [ "${pci_slot//0000:}" = "$slot" ]; then
                eth_interface=$(basename "$iface")
                break
            fi
        fi
    done
    
    # Get interface details
    local link_status="Unknown"
    local speed="Unknown"
    local duplex="Unknown"
    
    if [ -n "$eth_interface" ]; then
        if [ -f "/sys/class/net/$eth_interface/operstate" ]; then
            link_status=$(cat "/sys/class/net/$eth_interface/operstate")
        fi
        
        if cmd_exists ethtool; then
            ethtool "$eth_interface" > "$TMP_DETAIL_DIR/eth_${eth_interface}_info.txt" 2>/dev/null || true
            speed=$(grep -i "Speed:" "$TMP_DETAIL_DIR/eth_${eth_interface}_info.txt" | awk '{print $2}' || echo "Unknown")
            duplex=$(grep -i "Duplex:" "$TMP_DETAIL_DIR/eth_${eth_interface}_info.txt" | awk '{print $2}' || echo "Unknown")
        fi
    fi
    
    # Check for driver issues
    local driver_status="✅ Driver loaded and functioning"
    if [ -z "$driver" ]; then
        driver_status="❌ No driver loaded"
        MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
        
        add_action_item "ETHERNET" "$description" "No driver loaded for ethernet device" \
        "Available modules: $available_drivers\n\nLoad with:\n\`\`\`\nmodprobe ${available_drivers/,/ }\n\`\`\`"
    elif dmesg | grep -i "$driver\|$eth_interface" | grep -iE "failed|error" &>/dev/null; then
        driver_status="⚠️ Driver loaded but has errors"
        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
        
        add_action_item "ETHERNET" "$description" "Driver errors for ethernet device" \
        "Check for error messages:\n\`\`\`\ndmesg | grep -i '$driver\\|$eth_interface'\n\`\`\`"
    fi
    
    # Check for firmware issues
    local firmware_status="✅ No issues detected"
    if dmesg | grep -iE "$slot|$driver|$eth_interface" | grep -i "firmware" | grep -iE "missing|failed|error" &>/dev/null; then
        firmware_status="❌ Firmware issues detected"
        MISSING_FIRMWARE=$((MISSING_FIRMWARE + 1))
        
        # Common firmware packages per vendor
        local fw_package="firmware-misc-nonfree"
        case "$vendor_id" in
            # Realtek
            10ec)
                fw_package="firmware-realtek"
                ;;
            # Intel
            8086)
                fw_package="firmware-linux-nonfree"
                ;;
            # Broadcom
            14e4)
                fw_package="firmware-bnx2 firmware-bnx2x"
                ;;
            # Atheros
            1969)
                fw_package="firmware-atheros"
                ;;
        esac
        
        add_action_item "ETHERNET" "$description" "Missing firmware for ethernet device" \
        "Install firmware package:\n\`\`\`\napt-get install $fw_package\n\`\`\`"
    fi
    
    {
        echo "## Ethernet Device: $description"
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Slot | $slot |"
        echo "| Device | $description |"
        echo "| Driver | $driver |"
        echo "| Available drivers | $available_drivers |"
        echo "| Interface | $eth_interface |"
        echo "| Link status | $link_status |"
        echo "| Speed | $speed |"
        echo "| Duplex | $duplex |"
        echo "| Driver status | $driver_status |"
        echo "| Firmware status | $firmware_status |"
        echo
        
        # Show detailed capabilities if available
        if [ -n "$eth_interface" ] && [ -f "$TMP_DETAIL_DIR/eth_${eth_interface}_info.txt" ]; then
            echo "### Interface Capabilities"
            echo "\`\`\`"
            cat "$TMP_DETAIL_DIR/eth_${eth_interface}_info.txt"
            echo "\`\`\`"
            echo
        fi
    } >> "$OUT_MD"
}

# ── Section: USB Devices ────────────────────────────────────────────────────
analyze_usb_devices() {
    log "Analyzing USB devices"

    {
        echo "# USB Devices"
        divider
        
        echo "## USB Controllers"
        echo "| Controller | Driver | Status |"
        echo "|------------|--------|--------|"
        
        lspci -nnk | grep -i "USB controller" | while read -r controller; do
            if [[ $controller =~ ^([0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9])\ (.+)\ \[(.+)\]:\ (.+)$ ]]; then
                local slot="${BASH_REMATCH[1]}"
                local class="${BASH_REMATCH[2]}"
                local vendor_device="${BASH_REMATCH[3]}"
                local description="${BASH_REMATCH[4]}"
                
                # Get driver
                local driver=$(lspci -s "$slot" -nnk | grep -A2 "Kernel driver in use" | awk -F': ' '/Kernel driver in use/ {print $2}')
                local driver_modules=$(lspci -s "$slot" -nnk | grep -A2 "Kernel modules" | awk -F': ' '/Kernel modules/ {print $2}')
                
                # Check driver status
                local driver_status="✅ OK"
                if [ -z "$driver" ]; then
                    driver_status="❌ No driver"
                    driver="—"
                    MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
                    
                    add_action_item "USB" "$description" "Missing driver for USB controller" \
                    "Available modules: $driver_modules\n\nLoad with:\n\`\`\`\nmodprobe ${driver_modules/,/ }\n\`\`\`"
                elif [[ "$description" == *"USB3"* ]] || [[ "$description" == *"xHCI"* ]]; then
                    if [ "$driver" != "xhci_hcd" ]; then
                        driver_status="⚠️ Not using xhci_hcd"
                        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                        
                        add_action_item "USB" "$description" "Not using optimal driver for USB 3.x controller" \
                        "Try loading xhci_hcd module:\n\`\`\`\nmodprobe xhci_hcd\n\`\`\`"
                    fi
                elif [[ "$description" == *"EHCI"* ]]; then
                    if [ "$driver" != "ehci-pci" ] && [ "$driver" != "ehci_hcd" ]; then
                        driver_status="⚠️ Not using ehci driver"
                        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                        
                        add_action_item "USB" "$description" "Not using optimal driver for USB 2.0 controller" \
                        "Try loading ehci-pci module:\n\`\`\`\nmodprobe ehci-pci\n\`\`\`"
                    fi
                fi
                
                echo "| $description | $driver | $driver_status |"
                
                # Add to CSV
                local need_action=$([ "$driver_status" != "✅ OK" ] && echo "YES" || echo "NO")
                local vendor_id=${vendor_device%:*}
                local device_id=${vendor_device#*:}
                echo "USB-CONTROLLER,$slot,$vendor_id,$device_id,$description,$driver,$driver_modules,${driver_status#* },$need_action" >> "$OUT_CSV"
                TOTAL_DEVICES=$((TOTAL_DEVICES + 1))
            fi
        done
        
        echo
        
        # Check for USB devices without drivers
        echo "## USB Devices"
        echo "| Bus:Device | Manufacturer | Product | Driver | Status |"
        echo "|------------|--------------|---------|--------|--------|"
        
        if cmd_exists lsusb; then
            lsusb | while read -r line; do
                if [[ $line =~ Bus\ ([0-9]+)\ Device\ ([0-9]+):\ ID\ ([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\ (.*)$ ]]; then
                    local bus="${BASH_REMATCH[1]}"
                    local device="${BASH_REMATCH[2]}"
                    local vendor_id="${BASH_REMATCH[3]}"
                    local device_id="${BASH_REMATCH[4]}"
                    local description="${BASH_REMATCH[5]}"
                    
                    # Try to find the driver
                    local driver="—"
                    local driver_status="❌ No driver"
                    local sysfs_path="/sys/bus/usb/devices/${bus}-${device}"
                    
                    # Alternative paths to check
                    if [ ! -d "$sysfs_path" ]; then
                        for path in /sys/bus/usb/devices/*; do
                            if [ -f "$path/idVendor" ] && [ -f "$path/idProduct" ]; then
                                if [ "$(cat $path/idVendor)" == "$vendor_id" ] && [ "$(cat $path/idProduct)" == "$device_id" ]; then
                                    sysfs_path="$path"
                                    break
                                fi
                            fi
                        done
                    fi
                    
                    if [ -d "$sysfs_path" ]; then
                        # Check if driver is bound
                        if [ -d "$sysfs_path/driver" ]; then
                            driver=$(basename $(readlink -f "$sysfs_path/driver"))
                            driver_status="✅ Driver loaded"
                        else
                            # Special cases for common device types
                            case "$description" in
                                *"Hub"*|*"hub"*)
                                    # USB hubs often don't need separate drivers
                                    driver="hub"
                                    driver_status="✅ Hub driver"
                                    ;;
                                *"Keyboard"*|*"Mouse"*|*"HID"*)
                                    # HID devices should use hid driver
                                    if lsmod | grep -q "hid"; then
                                        driver_status="⚠️ HID driver loaded but not bound"
                                        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                                        
                                        add_action_item "USB" "$description" "HID device not properly bound to driver" \
                                        "Try reconnecting the device or check for conflicts:\n\`\`\`\nmodprobe -r hid && modprobe hid\n\`\`\`"
                                    else
                                        driver_status="❌ Missing HID driver"
                                        MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
                                        
                                        add_action_item "USB" "$description" "Missing HID driver for input device" \
                                        "Load HID drivers:\n\`\`\`\nmodprobe hid hid-generic usbhid\n\`\`\`"
                                    fi
                                    ;;
                                *"Bluetooth"*)
                                    # Bluetooth devices should use btusb
                                    if lsmod | grep -q "btusb"; then
                                        driver_status="⚠️ btusb loaded but not bound"
                                        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                                        
                                        add_action_item "USB" "$description" "Bluetooth adapter not properly bound to driver" \
                                        "Try reloading bluetooth drivers:\n\`\`\`\nmodprobe -r btusb && modprobe btusb\n\`\`\`"
                                    else
                                        driver_status="❌ Missing Bluetooth driver"
                                        MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
                                        
                                        add_action_item "USB" "$description" "Missing driver for Bluetooth adapter" \
                                        "Load Bluetooth drivers:\n\`\`\`\napt-get install bluetooth && modprobe btusb\n\`\`\`"
                                    fi
                                    ;;
                                *"Webcam"*|*"Camera"*)
                                    # Webcams should use uvcvideo
                                    if lsmod | grep -q "uvcvideo"; then
                                        driver_status="⚠️ uvcvideo loaded but not bound"
                                        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                                        
                                        add_action_item "USB" "$description" "Webcam not properly bound to driver" \
                                        "Try reloading webcam driver:\n\`\`\`\nmodprobe -r uvcvideo && modprobe uvcvideo\n\`\`\`"
                                    else
                                        driver_status="❌ Missing webcam driver"
                                        MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
                                        
                                        add_action_item "USB" "$description" "Missing driver for webcam" \
                                        "Load webcam drivers:\n\`\`\`\nmodprobe uvcvideo\n\`\`\`"
                                    fi
                                    ;;
                                *"Mass Storage"*|*"Storage"*)
                                    # Storage devices should use usb-storage
                                    if lsmod | grep -q "usb_storage"; then
                                        driver_status="⚠️ usb-storage loaded but not bound"
                                        NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                                        
                                        add_action_item "USB" "$description" "Storage device not properly bound to driver" \
                                        "Try reloading storage driver:\n\`\`\`\nmodprobe -r usb_storage && modprobe usb_storage\n\`\`\`"
                                    else
                                        driver_status="❌ Missing storage driver"
                                        MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
                                        
                                        add_action_item "USB" "$description" "Missing driver for USB storage device" \
                                        "Load storage drivers:\n\`\`\`\nmodprobe usb_storage\n\`\`\`"
                                    fi
                                    ;;
                            esac
                        fi
                    fi
                    
                    echo "| $bus:$device | $vendor_id | $description | $driver | $driver_status |"
                    
                    # Add to CSV
                    local need_action=$([ "$driver_status" != "✅ Driver loaded" ] && [ "$driver_status" != "✅ Hub driver" ] && echo "YES" || echo "NO")
                    echo "USB-DEVICE,$bus:$device,$vendor_id,$device_id,\"$description\",$driver,${driver_status#* },${driver_status#* },$need_action" >> "$OUT_CSV"
                    TOTAL_DEVICES=$((TOTAL_DEVICES + 1))
                fi
            done
        else
            echo "| — | — | — | — | lsusb tool not available |"
        fi
        
        echo
        
        # USB detailed tree view
        echo "## USB Device Tree"
        echo "\`\`\`"
        if cmd_exists lsusb; then
            lsusb -tv 2>/dev/null || echo "USB tree view not available"
        else
            echo "lsusb tool not available"
        fi
        echo "\`\`\`"
        echo
    } >> "$OUT_MD"
}

# ── Section: Thunderbolt Devices ──────────────────────────────────────────
analyze_thunderbolt() {
    log "Checking for Thunderbolt devices"

    if [ -d "/sys/bus/thunderbolt" ]; then
        {
            echo "# Thunderbolt Devices"
            divider
            
            echo "Thunderbolt subsystem is present in the kernel."
            echo
            
            if ls /sys/bus/thunderbolt/devices/ &>/dev/null; then
                echo "## Thunderbolt Controllers and Devices"
                echo "| Device | Type | Name | Driver | Status |"
                echo "|--------|------|------|--------|--------|"
                
                for dev in /sys/bus/thunderbolt/devices/*; do
                    if [ -d "$dev" ]; then
                        local tb_name=$(basename "$dev")
                        local tb_type="Unknown"
                        local tb_desc="Unknown"
                        local driver="—"
                        local status="Unknown"
                        
                        if [ -f "$dev/device_type" ]; then
                            tb_type=$(cat "$dev/device_type")
                        fi
                        
                        if [ -f "$dev/device_name" ]; then
                            tb_desc=$(cat "$dev/device_name")
                        elif [ -f "$dev/vendor_name" ] && [ -f "$dev/device_name" ]; then
                            tb_desc="$(cat $dev/vendor_name) $(cat $dev/device_name)"
                        fi
                        
                        if [ -d "$dev/driver" ]; then
                            driver=$(basename $(readlink -f "$dev/driver"))
                            status="✅ Connected"
                        else
                            status="⚠️ No driver bound"
                            NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                            
                            add_action_item "THUNDERBOLT" "$tb_desc ($tb_name)" "No driver bound to Thunderbolt device" \
                            "Ensure Thunderbolt support is enabled in the BIOS/UEFI.\nInstall Thunderbolt utilities:\n\`\`\`\napt-get install bolt\n\`\`\`"
                        fi
                        
                        echo "| $tb_name | $tb_type | $tb_desc | $driver | $status |"
                        
                        # Add to CSV
                        local need_action=$([ "$status" != "✅ Connected" ] && echo "YES" || echo "NO")
                        echo "THUNDERBOLT,$tb_name,0000,0000,$tb_desc,$driver,N/A,$status,$need_action" >> "$OUT_CSV"
                        TOTAL_DEVICES=$((TOTAL_DEVICES + 1))
                    fi
                done
                
                echo
            else
                echo "No Thunderbolt devices currently connected."
                echo
            fi
            
            # Thunderbolt security settings
            echo "## Thunderbolt Security"
            if [ -f "/sys/bus/thunderbolt/security" ]; then
                local security=$(cat "/sys/bus/thunderbolt/security")
                echo "Security level: $security"
                
                if [ "$security" == "none" ]; then
                    echo
                    echo "> ⚠️ **Warning**: Thunderbolt security is disabled. This may expose your system to DMA attacks."
                    
                    add_action_item "SECURITY" "Thunderbolt" "Thunderbolt security is disabled" \
                    "Enable Thunderbolt security in BIOS/UEFI settings (recommended: 'user' or 'secure' level).\n\nFor software management, install:\n\`\`\`\napt-get install bolt\n\`\`\`"
                fi
            else
                echo "Security information not available in sysfs."
            fi
            
            echo
            
            # Thunderbolt driver status
            echo "## Thunderbolt Kernel Modules"
            echo "\`\`\`"
            lsmod | grep -i "thunderbolt" || echo "No Thunderbolt modules currently loaded."
            echo "\`\`\`"
            
            echo
        } >> "$OUT_MD"
    fi
}

# ── Section: Network Interfaces ───────────────────────────────────────────
analyze_network_interfaces() {
    log "Analyzing network interfaces and drivers"

    {
        echo "# Network Interfaces"
        divider
        
        echo "## Interface Overview"
        echo "| Interface | Type | MAC Address | Driver | Status | Speed |"
        echo "|-----------|------|------------|--------|--------|-------|"
        
        for iface in /sys/class/net/*; do
            if [ -d "$iface" ]; then
                local if_name=$(basename "$iface")
                local if_type="Unknown"
                local mac="Unknown"
                local driver="—"
                local status="Unknown"
                local speed="—"
                
                # Skip loopback
                if [ "$if_name" == "lo" ]; then
                    continue
                fi
                
                # Get interface type
                if [ -d "$iface/wireless" ]; then
                    if_type="Wireless"
                elif [ -d "$iface/bridge" ]; then
                    if_type="Bridge"
                elif [ -d "$iface/bonding" ]; then
                    if_type="Bond"
                else
                    if_type="Ethernet"
                fi
                
                # Get MAC address
                if [ -f "$iface/address" ]; then
                    mac=$(cat "$iface/address")
                fi
                
                # Get driver
                if [ -L "$iface/device/driver" ] && [ -e "$iface/device/driver" ]; then
                    driver=$(basename $(readlink -f "$iface/device/driver"))
                elif cmd_exists ethtool; then
                    driver=$(ethtool -i "$if_name" 2>/dev/null | grep "driver:" | awk '{print $2}' || echo "—")
                fi
                
                # Get status
                if [ -f "$iface/operstate" ]; then
                    status=$(cat "$iface/operstate")
                fi
                
                # Get link speed
                if [ "$status" == "up" ] && cmd_exists ethtool; then
                    speed=$(ethtool "$if_name" 2>/dev/null | grep -i "Speed:" | awk '{print $2}' || echo "—")
                fi
                
                # Check for driver issues
                local driver_status="✅"
                if [ "$driver" == "—" ]; then
                    driver_status="❌ No driver"
                    MISSING_DRIVERS=$((MISSING_DRIVERS + 1))
                    
                    add_action_item "NETWORK" "$if_name" "Missing driver for network interface" \
                    "Check for compatible drivers and load manually. For common network drivers:\n\`\`\`\nmodprobe e1000e e1000 igb ixgbe r8169 tg3 bnx2\n\`\`\`"
                elif dmesg | grep -i "$if_name\|$driver" | grep -iE "failed|error" &>/dev/null; then
                    driver_status="⚠️ Driver issues"
                    NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
                    
                    add_action_item "NETWORK" "$if_name" "Driver issues for network interface" \
                    "Check error messages:\n\`\`\`\ndmesg | grep -i '$if_name\\|$driver'\n\`\`\`"
                fi
                
                echo "| $if_name | $if_type | $mac | $driver $driver_status | $status | $speed |"
                
                # Add to CSV
                local vendor="Unknown"
                local device="Unknown"
                if [ -f "$iface/device/vendor" ] && [ -f "$iface/device/device" ]; then
                    vendor=$(cat "$iface/device/vendor" | sed 's/0x//')
                    device=$(cat "$iface/device/device" | sed 's/0x//')
                fi
                
                local need_action=$([ "$driver_status" != "✅" ] && echo "YES" || echo "NO")
                echo "NETWORK,$if_name,$vendor,$device,$if_type interface,$driver,N/A,${driver_status#* },$need_action" >> "$OUT_CSV"
                TOTAL_DEVICES=$((TOTAL_DEVICES + 1))
            fi
        done
        
        echo
        
        # More detailed network information
        echo "## Network Configuration"
        if cmd_exists ip; then
            echo "### IP Address Configuration"
            echo "\`\`\`"
            ip -o addr show | grep -v "^lo" || echo "No IP addresses configured"
            echo "\`\`\`"
            echo
            
            echo "### Routing Table"
            echo "\`\`\`"
            ip route || echo "No routes configured"
            echo "\`\`\`"
            echo
        else
            echo "IP configuration tool not available."
            echo
        fi
        
        # DNS configuration
        echo "### DNS Configuration"
        echo "\`\`\`"
        if [ -f "/etc/resolv.conf" ]; then
            grep -v "^#" /etc/resolv.conf || echo "No DNS servers configured"
        else
            echo "resolv.conf not found"
        fi
        echo "\`\`\`"
        echo
        
        # Network manager status
        echo "### Network Management"
        echo "| Service | Status |"
        echo "|---------|--------|"
        
        local nm_status="Not installed"
        if cmd_exists systemctl; then
            if systemctl is-active NetworkManager &>/dev/null; then
                nm_status="Active (running)"
            elif systemctl is-enabled NetworkManager &>/dev/null; then
                nm_status="Enabled but not running"
            elif systemctl list-unit-files | grep -q NetworkManager; then
                nm_status="Installed but disabled"
            fi
        fi
        
        echo "| NetworkManager | $nm_status |"
        
        local systemd_networkd="Not active"
        if cmd_exists systemctl; then
            if systemctl is-active systemd-networkd &>/dev/null; then
                systemd_networkd="Active (running)"
            elif systemctl is-enabled systemd-networkd &>/dev/null; then
                systemd_networkd="Enabled but not running"
            fi
        fi
        
        echo "| systemd-networkd | $systemd_networkd |"
        echo
    } >> "$OUT_MD"
}

# ── Section: Kernel Module Analysis ─────────────────────────────────────────
analyze_kernel_modules() {
    log "Analyzing kernel modules and driver status"

    {
        echo "# Kernel Module Analysis"
        divider
        
        # Count loaded modules
        local loaded_modules=$(lsmod | wc -l)
        
        echo "## Kernel Module Stats"
        echo "| Metric | Count |"
        echo "|--------|-------|"
        echo "| Kernel version | $(uname -r) |"
        echo "| Loaded modules | $loaded_modules |"
        echo "| Available modules | $(find /lib/modules/$(uname -r) -name "*.ko*" 2>/dev/null | wc -l) |"
        echo
        
        # Check for missing essential modules
        echo "## Essential Driver Status"
        echo "| Subsystem | Status | Modules |"
        echo "|-----------|--------|---------|"
        
        # USB
        local usb_status="✅ Loaded"
        local usb_modules=$(lsmod | grep -E "usb_|xhci|ehci|ohci|uhci" | awk '{print $1}' | tr '\n' ' ')
        if [ -z "$usb_modules" ]; then
            usb_status="❌ Not loaded"
            NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
            
            add_action_item "KERNEL" "USB Subsystem" "USB modules not loaded" \
            "Load essential USB modules:\n\`\`\`\nmodprobe xhci_hcd ehci_hcd ohci_hcd uhci_hcd usb_storage usbhid\n\`\`\`"
        fi
        echo "| USB | $usb_status | $usb_modules |"
        
        # Graphics
        local gpu_status="✅ Loaded"
        local gpu_modules=$(lsmod | grep -E "nvidia|radeon|amdgpu|nouveau|i915|intel_agp|drm" | awk '{print $1}' | tr '\n' ' ')
        if [ -z "$gpu_modules" ]; then
            gpu_status="❌ Not loaded"
            NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
            
            add_action_item "KERNEL" "Graphics Subsystem" "Graphics modules not loaded" \
            "Load appropriate GPU modules (choose based on your hardware):\n\`\`\`\n# For Intel: modprobe i915\n# For AMD: modprobe amdgpu\n# For NVIDIA: modprobe nvidia\n\`\`\`"
        fi
        echo "| Graphics | $gpu_status | $gpu_modules |"
        
        # Sound
        local sound_status="✅ Loaded"
        local sound_modules=$(lsmod | grep -E "snd|sound|audio" | awk '{print $1}' | tr '\n' ' ')
        if [ -z "$sound_modules" ]; then
            sound_status="❌ Not loaded"
            NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
            
            add_action_item "KERNEL" "Audio Subsystem" "Audio modules not loaded" \
            "Load essential audio modules:\n\`\`\`\nmodprobe snd-hda-intel snd-hda-codec\n\`\`\`"
        fi
        echo "| Sound | $sound_status | $sound_modules |"
        
        # Network
        local net_status="✅ Loaded"
        local net_modules=$(lsmod | grep -E "e1000|igb|r8169|ath|iwl|rtl|wl|mwifiex" | awk '{print $1}' | tr '\n' ' ')
        if [ -z "$net_modules" ]; then
            net_status="⚠️ Limited"
            NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
        fi
        echo "| Network | $net_status | $net_modules |"
        
        # Input devices
        local input_status="✅ Loaded"
        local input_modules=$(lsmod | grep -E "hid|input|touchpad|mouse|kbd" | awk '{print $1}' | tr '\n' ' ')
        if [ -z "$input_modules" ]; then
            input_status="❌ Not loaded"
            NON_OPTIMAL_DRIVERS=$((NON_OPTIMAL_DRIVERS + 1))
            
            add_action_item "KERNEL" "Input Subsystem" "Input modules not loaded" \
            "Load essential input modules:\n\`\`\`\nmodprobe hid usbhid hid-generic\n\`\`\`"
        fi
        echo "| Input | $input_status | $input_modules |"
        
        echo
        
        # Check for modules with loading errors
        echo "## Module Loading Issues"
        echo "\`\`\`"
        dmesg | grep -i "module" | grep -iE "fail|error|taint" | head -10 || echo "No module loading issues detected"
        echo "\`\`\`"
        echo
        
        # DKMS status if available
        if cmd_exists dkms; then
            echo "## DKMS Status"
            echo "\`\`\`"
            dkms status || echo "No DKMS modules found"
            echo "\`\`\`"
            echo
        fi
    } >> "$OUT_MD"
}

# ── Section: Driver Configuration Analysis ──────────────────────────────────
analyze_driver_config() {
    log "Analyzing driver configurations and parameters"

    {
        echo "# Driver Configuration Analysis"
        divider
        
        # Check for blacklisted modules
        echo "## Blacklisted Modules"
        echo "\`\`\`"
        if [ -d "/etc/modprobe.d" ]; then
            grep -r "blacklist" /etc/modprobe.d/ | sort || echo "No blacklisted modules found"
        else
            echo "modprobe.d directory not found"
        fi
        echo "\`\`\`"
        echo
        
        # Check for custom module parameters
        echo "## Custom Module Parameters"
        echo "\`\`\`"
        if [ -d "/etc/modprobe.d" ]; then
            grep -r "options" /etc/modprobe.d/ | sort || echo "No custom module parameters found"
        else
            echo "modprobe.d directory not found"
        fi
        echo "\`\`\`"
        echo
        
        # Kernel command line parameters related to drivers
        echo "## Kernel Driver Parameters"
        echo "\`\`\`"
        if [ -f "/proc/cmdline" ]; then
            cat /proc/cmdline
        else
            echo "Kernel cmdline not available"
        fi
        echo "\`\`\`"
        echo
        
        # Module load order
        echo "## Module Load Configuration"
        echo "\`\`\`"
        if [ -f "/etc/modules" ]; then
            cat /etc/modules || echo "No modules configured for early loading"
        elif [ -d "/etc/modules-load.d" ]; then
            find /etc/modules-load.d -type f -exec cat {} \; || echo "No modules configured for early loading"
        else
            echo "Module load configuration not found"
        fi
        echo "\`\`\`"
        echo
    } >> "$OUT_MD"
}

# ── Section: Summary Statistics ────────────────────────────────────────────
generate_summary() {
    log "Generating summary statistics"

    {
        echo "# Hardware Analysis Summary"
        divider
        
        echo "## Statistics"
        echo "| Metric | Count | Status |"
        echo "|--------|-------|--------|"
        echo "| Total devices analyzed | $TOTAL_DEVICES | |"
        echo "| Devices with missing drivers | $MISSING_DRIVERS | $([ $MISSING_DRIVERS -eq 0 ] && echo "✅ Good" || echo "❌ Action needed") |"
        echo "| Devices with non-optimal drivers | $NON_OPTIMAL_DRIVERS | $([ $NON_OPTIMAL_DRIVERS -eq 0 ] && echo "✅ Good" || echo "⚠️ Could be improved") |"
        echo "| Devices with missing firmware | $MISSING_FIRMWARE | $([ $MISSING_FIRMWARE -eq 0 ] && echo "✅ Good" || echo "❌ Action needed") |"
        echo
        
        echo "## Action Items Summary"
        
        if [ $((MISSING_DRIVERS + MISSING_FIRMWARE)) -eq 0 ] && [ $NON_OPTIMAL_DRIVERS -eq 0 ]; then
            echo "✅ **No critical issues detected!** All devices appear to have appropriate drivers and firmware."
        else
            echo "The following issues were detected:"
            echo
            
            if [ $MISSING_DRIVERS -gt 0 ]; then
                echo "### Missing Drivers"
                echo "* $MISSING_DRIVERS device(s) have no drivers loaded"
                echo "* See detailed recommendations in \`$OUT_TODO\`"
                echo
            fi
            
            if [ $MISSING_FIRMWARE -gt 0 ]; then
                echo "### Missing Firmware"
                echo "* $MISSING_FIRMWARE device(s) have missing firmware"
                echo "* See firmware recommendations in \`$OUT_TODO\`"
                echo
            fi
            
            if [ $NON_OPTIMAL_DRIVERS -gt 0 ]; then
                echo "### Suboptimal Configurations"
                echo "* $NON_OPTIMAL_DRIVERS device(s) could have better driver configurations"
                echo "* See optimization suggestions in \`$OUT_TODO\`"
                echo
            fi
            
            # Summarize recommended actions
            echo "### Recommended Actions"
            echo "1. Check the detailed action items list: \`$OUT_TODO\`"
            echo "2. Install recommended packages: \`$OUT_DEB_PACKAGES\`"
            echo "3. Load missing modules: \`$OUT_MODULE_NEEDS\`"
            echo
            
            # One-liner summary
            echo "Quick fix attempt (may not address all issues):"
            echo "\`\`\`bash"
            echo "# Install commonly missing firmware and driver packages"
            echo "apt-get update && apt-get install linux-firmware firmware-linux-nonfree firmware-misc-nonfree"
            echo "\`\`\`"
        fi
        
        echo
        
        # System recommendations based on hardware
        echo "## System Recommendations"
        
        local kernel_ver=$(uname -r)
        if [[ "$kernel_ver" =~ -([0-9]+)- ]]; then
            local kernel_ver_num=${BASH_REMATCH[1]}
            if [ "$kernel_ver_num" -lt 5 ]; then
                echo "* **Kernel Upgrade Recommended**: Your kernel ($kernel_ver) is quite old. Consider upgrading to a newer kernel for better hardware support."
                echo
                add_action_item "SYSTEM" "Kernel" "Kernel version is outdated" \
                "Consider upgrading to a newer kernel for better hardware support:\n\`\`\`\napt-get update && apt-get install linux-image-generic\n\`\`\`"
            fi
        fi
        
        # CPU-specific recommendations
        local cpu_vendor=$(lscpu | grep "Vendor ID" | awk -F': *' '{print $2}' | xargs)
        if [ "$cpu_vendor" == "AuthenticAMD" ]; then
            echo "* **CPU Scheduler**: For AMD processors, consider using the 'schedutil' CPU governor for better performance/power balance."
            echo
        elif [ "$cpu_vendor" == "GenuineIntel" ]; then
            echo "* **Power Management**: For Intel processors, ensure intel_pstate driver is being used for optimal power management."
            echo
        fi
        
        # Add recommendations for GPU
        if lspci | grep -i "VGA\|3D\|Display" | grep -i "NVIDIA" &>/dev/null; then
            echo "* **NVIDIA GPU Detected**: For optimal performance with NVIDIA GPUs, consider installing the proprietary drivers."
            echo
        elif lspci | grep -i "VGA\|3D\|Display" | grep -i "AMD\|ATI" &>/dev/null; then
            echo "* **AMD GPU Detected**: For optimal performance with AMD GPUs, ensure firmware-amd-graphics is installed."
            echo
        fi
        
        # Add recommendations for Wi-Fi
        if lspci | grep -i "Network controller" | grep -iE "WiFi|Wireless|WLAN" &>/dev/null; then
            echo "* **Wireless Hardware Detected**: Ensure that the appropriate firmware packages are installed for your wireless adapter."
            echo
        fi
        
        echo "## Report Files"
        echo "* **Full Report**: \`$OUT_MD\`"
        echo "* **CSV Summary**: \`$OUT_CSV\`"
        echo "* **Action Items**: \`$OUT_TODO\`"
        echo "* **Packages to Install**: \`$OUT_DEB_PACKAGES\`"
        echo "* **Modules to Load**: \`$OUT_MODULE_NEEDS\`"
        echo
        
        echo "Report generated by hw-inventory-extended.sh v$SCRIPT_VERSION on $(date)"
    } >> "$OUT_MD"
}

# ── Main Program ────────────────────────────────────────────────────────────
main() {
    log "Hardware inventory script v$SCRIPT_VERSION starting"
    log "Kernel: $(uname -r), Distribution: $(lsb_release -ds 2>/dev/null || echo "Unknown")"
    
    # Check if running as root (some commands need root)
    if [ "$(id -u)" -ne 0 ]; then
        warn "Not running as root. Some hardware information may be unavailable."
    fi
    
    # Initialize output files
    init_outputs
    
    # Run analysis sections
    system_summary
    cpu_memory
    firmware_analysis
    analyze_storage
    analyze_pci_devices
    analyze_usb_devices
    analyze_thunderbolt  # This may not output anything if no Thunderbolt hardware
    analyze_network_interfaces
    analyze_kernel_modules
    analyze_driver_config
    
    # Generate summary
    generate_summary
    
    log "Hardware inventory complete!"
    log "Report saved to: $OUT_MD"
    log "CSV data saved to: $OUT_CSV"
    log "Action items saved to: $OUT_TODO"
    
    # Print summary to console
    echo
    echo "=============== HARDWARE INVENTORY SUMMARY ==============="
    echo "Total devices analyzed:        $TOTAL_DEVICES"
    echo "Devices with missing drivers:  $MISSING_DRIVERS"
    echo "Devices with missing firmware: $MISSING_FIRMWARE"
    echo "Devices needing optimization:  $NON_OPTIMAL_DRIVERS"
    echo
    echo "Report saved to: $OUT_MD"
    echo "Action items:    $OUT_TODO"
    echo "==========================================================="
    echo
    
    exit 0
}

main "$@"
