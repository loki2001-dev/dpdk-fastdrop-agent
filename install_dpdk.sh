#!/bin/bash

echo "=====> Installing required packages..."
sudo apt update
sudo apt install -y libpcap-dev
sudo apt install -y python3-pyelftools
sudo apt install -y build-essential linux-headers-$(uname -r) git meson ninja-build libnuma-dev

########################################################################################################################
# Step 1. Please run the following command in the terminal. (lspci -nn | grep Ethernet)
# Step 2. Enter the value obtained in Step 1 into the 'PCI_ADDRESS' field below, then run the script. (example: PCI_ADDRESS="0000:01:00.0")
########################################################################################################################
PCI_ADDRESS=""

echo "=====> Building DPDK..."
DPDK_DIR="$(pwd)/3rdparty/dpdk"
if [ ! -d "$DPDK_DIR" ]; then
  echo "Error: DPDK source directory not found at $DPDK_DIR"
  exit 1
fi

cd "$DPDK_DIR"

meson setup build --reconfigure || meson setup build
ninja -C build
sudo ninja -C build install
sudo ldconfig

echo "=====> Setting hugepages..."
sudo mkdir -p /mnt/huge
if ! mountpoint -q /mnt/huge; then
  sudo mount -t hugetlbfs nodev /mnt/huge
else
  echo "/mnt/huge is already mounted."
fi

echo "=====> Current hugepages status:"
grep Huge /proc/meminfo

echo "=====> Allocating 1024 hugepages..."
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages

echo "=====> Loading vfio-pci kernel module..."
sudo modprobe vfio-pci

echo "=====> Binding network card PCI address: $PCI_ADDRESS"
sudo ./usertools/dpdk-devbind.py --bind=vfio-pci $PCI_ADDRESS

echo "=====> Starting DPDK testpmd for basic verification..."
sudo dpdk-testpmd -l 0-3 -n 4 -- --portmask=0x1 --auto-start -- -i

echo "=====> DPDK installation and test successfully!"