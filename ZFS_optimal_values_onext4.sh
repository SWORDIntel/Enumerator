#!/bin/bash
# bench.sh - Filesystem compression benchmark for ext4 systems
# Simulates different ZFS compression algorithms using standard tools

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

# Colors for better output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}ZFS Compression Simulator for ext4 Systems${NC}"
echo -e "${YELLOW}Testing on: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)${NC}"

# Create test directory
TEST_DIR="/tmp/compression_test"
mkdir -p "$TEST_DIR"

# Cleanup function
cleanup() {
  echo "Cleaning up..."
  rm -rf "$TEST_DIR"
  echo "Cleanup completed"
}

trap cleanup EXIT INT TERM

# Create different types of test data
echo -e "${BLUE}Generating test data files...${NC}"

# 1. Text data (highly compressible)
if [ -f "/usr/share/dict/words" ]; then
  cat /usr/share/dict/words /usr/share/dict/words /usr/share/dict/words > "$TEST_DIR/text.dat"
else
  for i in $(seq 1 10000); do
    echo "This is a test line $i with random words banana apple orange computer network system" >> "$TEST_DIR/text.dat"
  done
fi

# 2. Binary-like data (less compressible)
dd if=/dev/urandom of="$TEST_DIR/binary.dat" bs=1M count=10 2>/dev/null

# 3. Mixed data (moderately compressible)
cat "$TEST_DIR/text.dat" "$TEST_DIR/binary.dat" > "$TEST_DIR/mixed.dat"

# 4. Zero data (extremely compressible)
dd if=/dev/zero of="$TEST_DIR/zero.dat" bs=1M count=20 2>/dev/null

# Test function
test_compression() {
  local file=$1
  local name=$2
  local filesize=$(stat -c %s "$file")
  local filemb=$(echo "scale=2; $filesize / 1048576" | bc)
  
  echo -e "\n${YELLOW}Testing compression on $name data ($filemb MB)${NC}"
  echo -e "Algorithm\tRatio\t\tComp MB/s\tDecomp MB/s"
  echo -e "-------------------------------------------------"
  
  # LZ4 simulation
  start=$(date +%s.%N)
  lz4 -q -1 "$file" "$TEST_DIR/test.lz4"
  end=$(date +%s.%N)
  comp_time=$(echo "$end - $start" | bc)
  comp_speed=$(echo "scale=2; $filemb / $comp_time" | bc)
  comp_size=$(stat -c %s "$TEST_DIR/test.lz4")
  ratio=$(echo "scale=2; $filesize / $comp_size" | bc)
  
  start=$(date +%s.%N)
  lz4 -q -d "$TEST_DIR/test.lz4" "$TEST_DIR/test.out"
  end=$(date +%s.%N)
  decomp_time=$(echo "$end - $start" | bc)
  decomp_speed=$(echo "scale=2; $filemb / $decomp_time" | bc)
  
  printf "%-10s\t%s:1\t\t%-10s\t%-10s\n" "lz4" "$ratio" "$comp_speed" "$decomp_speed"
  rm -f "$TEST_DIR/test.lz4" "$TEST_DIR/test.out"
  
  # ZSTD level 1 simulation
  start=$(date +%s.%N)
  zstd -q -1 -o "$TEST_DIR/test.zst1" "$file"
  end=$(date +%s.%N)
  comp_time=$(echo "$end - $start" | bc)
  comp_speed=$(echo "scale=2; $filemb / $comp_time" | bc)
  comp_size=$(stat -c %s "$TEST_DIR/test.zst1")
  ratio=$(echo "scale=2; $filesize / $comp_size" | bc)
  
  start=$(date +%s.%N)
  zstd -q -d -o "$TEST_DIR/test.out" "$TEST_DIR/test.zst1"
  end=$(date +%s.%N)
  decomp_time=$(echo "$end - $start" | bc)
  decomp_speed=$(echo "scale=2; $filemb / $decomp_time" | bc)
  
  printf "%-10s\t%s:1\t\t%-10s\t%-10s\n" "zstd-1" "$ratio" "$comp_speed" "$decomp_speed"
  rm -f "$TEST_DIR/test.zst1" "$TEST_DIR/test.out"
  
  # ZSTD level 3 simulation
  start=$(date +%s.%N)
  zstd -q -3 -o "$TEST_DIR/test.zst3" "$file"
  end=$(date +%s.%N)
  comp_time=$(echo "$end - $start" | bc)
  comp_speed=$(echo "scale=2; $filemb / $comp_time" | bc)
  comp_size=$(stat -c %s "$TEST_DIR/test.zst3")
  ratio=$(echo "scale=2; $filesize / $comp_size" | bc)
  
  start=$(date +%s.%N)
  zstd -q -d -o "$TEST_DIR/test.out" "$TEST_DIR/test.zst3"
  end=$(date +%s.%N)
  decomp_time=$(echo "$end - $start" | bc)
  decomp_speed=$(echo "scale=2; $filemb / $decomp_time" | bc)
  
  printf "%-10s\t%s:1\t\t%-10s\t%-10s\n" "zstd-3" "$ratio" "$comp_speed" "$decomp_speed"
  rm -f "$TEST_DIR/test.zst3" "$TEST_DIR/test.out"
  
  # ZSTD level 7 simulation
  start=$(date +%s.%N)
  zstd -q -7 -o "$TEST_DIR/test.zst7" "$file"
  end=$(date +%s.%N)
  comp_time=$(echo "$end - $start" | bc)
  comp_speed=$(echo "scale=2; $filemb / $comp_time" | bc)
  comp_size=$(stat -c %s "$TEST_DIR/test.zst7")
  ratio=$(echo "scale=2; $filesize / $comp_size" | bc)
  
  start=$(date +%s.%N)
  zstd -q -d -o "$TEST_DIR/test.out" "$TEST_DIR/test.zst7"
  end=$(date +%s.%N)
  decomp_time=$(echo "$end - $start" | bc)
  decomp_speed=$(echo "scale=2; $filemb / $decomp_time" | bc)
  
  printf "%-10s\t%s:1\t\t%-10s\t%-10s\n" "zstd-7" "$ratio" "$comp_speed" "$decomp_speed"
  rm -f "$TEST_DIR/test.zst7" "$TEST_DIR/test.out"
  
  # GZIP simulation (for comparison)
  start=$(date +%s.%N)
  gzip -c -1 "$file" > "$TEST_DIR/test.gz"
  end=$(date +%s.%N)
  comp_time=$(echo "$end - $start" | bc)
  comp_speed=$(echo "scale=2; $filemb / $comp_time" | bc)
  comp_size=$(stat -c %s "$TEST_DIR/test.gz")
  ratio=$(echo "scale=2; $filesize / $comp_size" | bc)
  
  start=$(date +%s.%N)
  gunzip -c "$TEST_DIR/test.gz" > "$TEST_DIR/test.out"
  end=$(date +%s.%N)
  decomp_time=$(echo "$end - $start" | bc)
  decomp_speed=$(echo "scale=2; $filemb / $decomp_time" | bc)
  
  printf "%-10s\t%s:1\t\t%-10s\t%-10s\n" "gzip" "$ratio" "$comp_speed" "$decomp_speed"
  rm -f "$TEST_DIR/test.gz" "$TEST_DIR/test.out"
}

# Install dependencies if needed
install_deps() {
  echo -e "${BLUE}Installing required packages...${NC}"
  apt-get update
  apt-get install -y lz4 zstd bc
}

# CPU, RAM and Thermal info
check_system() {
  echo -e "\n${BLUE}System Information:${NC}"
  echo -e "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
  echo -e "Cores: $(grep -c processor /proc/cpuinfo)"
  echo -e "RAM: $(free -h | awk '/Mem:/ {print $2}')"
  
  # Check CPU temperature if possible
  if [ -f "/sys/class/thermal/thermal_zone0/temp" ]; then
    temp=$(( $(cat /sys/class/thermal/thermal_zone0/temp) / 1000 ))
    echo -e "CPU Temperature: ${temp}°C"
  elif command -v sensors >/dev/null 2>&1; then
    echo -e "CPU Temperature: $(sensors | grep -m 1 -i "core" | awk '{print $3}')"
  fi
  
  # Check CPU frequency
  if [ -f "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq" ]; then
    freq=$(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq) / 1000 ))
    max_freq=$(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq) / 1000 ))
    echo -e "CPU Frequency: ${freq}MHz / ${max_freq}MHz ($(( freq * 100 / max_freq ))%)"
  fi
}

# Main function
main() {
  # Check for dependencies
  if ! command -v lz4 >/dev/null 2>&1 || ! command -v zstd >/dev/null 2>&1; then
    install_deps
  fi
  
  check_system
  
  # Run tests
  test_compression "$TEST_DIR/text.dat" "text"
  test_compression "$TEST_DIR/binary.dat" "binary"
  test_compression "$TEST_DIR/mixed.dat" "mixed"
  test_compression "$TEST_DIR/zero.dat" "zero"
  
  # Show summary and recommendations
  echo -e "\n${GREEN}Test Results Summary${NC}"
  echo -e "${BLUE}Based on these results, here are the recommended ZFS compression settings:${NC}"
  
  echo -e "\n1. ${YELLOW}Boot Pool (bpool)${NC}"
  echo -e "   Recommendation: ${GREEN}lz4${NC}"
  echo -e "   Command: sudo zfs set compression=lz4 bpool/BOOT/siduction"
  echo -e "   Reason: Fastest decompression speed, critical for boot performance"
  
  echo -e "\n2. ${YELLOW}Root Dataset (rpool/ROOT)${NC}"
  echo -e "   Recommendation: ${GREEN}zstd-3${NC}"
  echo -e "   Command: sudo zfs set compression=zstd-3 rpool/ROOT/siduction"
  echo -e "   Reason: Good balance between compression ratio and performance"
  
  echo -e "\n3. ${YELLOW}Home Dataset (for user data)${NC}"
  echo -e "   Recommendation: ${GREEN}zstd-7${NC}"
  echo -e "   Command: sudo zfs set compression=zstd-7 rpool/ROOT/siduction/home"
  echo -e "   Reason: Better compression ratio for user data, where access is less frequent"
  
  echo -e "\n${BLUE}ZFS Compression Simulation Complete!${NC}"
  
  # CPU info after tests
  if [ -f "/sys/class/thermal/thermal_zone0/temp" ]; then
    temp=$(( $(cat /sys/class/thermal/thermal_zone0/temp) / 1000 ))
    echo -e "Final CPU Temperature: ${temp}°C"
  fi
}

# Run the main function
main
