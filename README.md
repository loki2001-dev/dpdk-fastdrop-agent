# dpdk-firewall-agent (Modern C++ & DPDK)
- A Blocklist-Based Packet Filtering Firewall Project
- Lightweight and efficient DPDK-based firewall that filters network packets by IP and port rules.
- Parses and applies filter rules loaded from JSON configuration files, then passes or drops packets accordingly.

---

## Features
- Loads filtering rules from JSON config files (e.g. `block_list.json`)
- Parses TCP/UDP packets for IP and port matching
- Burst-based packet receive, parse, filter, and transmit pipeline
- Releases memory of dropped or failed-to-send packets to prevent leaks
- Avoids excessive CPU usage by sleeping or pausing briefly when no packets are received
- Logs transmit counts and firewall status for easy monitoring
- DPDK for high-performance packet processing
- JSON parsing with [nlohmann/json](https://github.com/nlohmann/json)
- Modern C++17 standard libraries for filesystem and optional handling

---

## Getting Started
### Prerequisites
- Linux (Ubuntu 20.04 or later recommended)
- Requires DPDK 21.11 or later installed (included as a sh script)
- Requires CMake 3.14 or later
- Requires C++17 compatible compiler
- [nlohmann/json](https://github.com/nlohmann/json) (included as a submodule or dependency)
- [spdlog](https://github.com/gabime/spdlog) (optional, included as a submodule)

---

## Build Instructions
### Setup and Installation
```bash
# Update package lists
sudo apt update

# Clone the repository
git clone https://github.com/loki2001-dev/dpdk-firewall-agent.git
cd dpdk-firewall-agent

# Initialize submodules
git submodule update --init --recursive

# Install dependencies
. install_dpdk.sh

# Build the project
. build_project.sh