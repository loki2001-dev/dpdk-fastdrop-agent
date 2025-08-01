#include <unistd.h>
#include <iomanip>
#include "dpdk_init.h"

dpdk_init::dpdk_init()
    : _mem_buf_pool(nullptr)
    , _mem_buf_pool_name("MBUF_POOL")
    , _mem_buf_pool_size(8192)
    , _mem_buf_pool_cache_size(250)
    , _mem_buf_pool_data_size(RTE_MBUF_DEFAULT_BUF_SIZE)
    , _port_id(RTE_MAX_ETHPORTS)
    , _initialized(false) {
    spdlog::info("Starting DPDK initialization...");

    // Check environment: root, hugepages configured and mounted
    if (!ensure_dpdk_environment()) {
        spdlog::error("DPDK environment check failed.");
        return;
    }
    spdlog::info("DPDK environment ready.");

    // Initialize Environment Abstraction Layer (EAL)
    if (!initialize_eal()) {
        spdlog::error("Failed to initialize EAL.");
        return;
    }
    spdlog::info("EAL initialized successfully.");

    // Find and validate a usable Ethernet port
    if (!find_and_validate_port()) {
        spdlog::error("DPDK initialization aborted due to port errors.");
        return;
    }
    spdlog::info("Ethernet port found and validated: port_id={}", _port_id);

    // Create packet buffer pool (mbuf pool)
    if (!create_mbuf_pool()) {
        spdlog::error("DPDK initialization aborted due to mbuf pool creation failure.");
        return;
    }
    spdlog::info("Mbuf pool created successfully.");

    // Configure and start Ethernet port
    if (!configure_and_start_port()) {
        spdlog::error("DPDK initialization aborted due to port configuration/start failure.");
        return;
    }
    spdlog::info("Ethernet port configured and started.");

    // Load Filter Rules
    const std::string filter_rule_path = "../config/block_list.json";
    if (!_packet_filter.load_rules(filter_rule_path)) {
        spdlog::error("Failed to load packet filtering rules from {}", filter_rule_path);
        return;
    }
    _packet_filter.print_rules_comments();

    spdlog::info("DPDK initialization complete. Port {} started in promiscuous mode.", _port_id);
    _initialized = true;
    rte_atomic32_set(&_running, 1);
}

dpdk_init::~dpdk_init() {
    if (is_initialized()) {
        rte_eth_dev_stop(_port_id);
        rte_eth_dev_close(_port_id);
        spdlog::info("DPDK port {} stopped and closed.", _port_id);
    }
}

bool dpdk_init::find_and_validate_port() {
    uint16_t port_count = rte_eth_dev_count_avail();
    if (port_count == 0) {
        spdlog::error("No Ethernet devices found.");
        return false;
    }

    for (uint16_t port = 0; port < port_count; ++port) {
        if (rte_eth_dev_is_valid_port(port)) {
            _port_id = port;
            spdlog::info("Using Ethernet port: {}", _port_id);
            return true;
        }
    }

    spdlog::error("No available Ethernet port found.");
    return false;
}

bool dpdk_init::create_mbuf_pool() {
    _mem_buf_pool = rte_pktmbuf_pool_create(
        _mem_buf_pool_name.c_str(),
        _mem_buf_pool_size,
        _mem_buf_pool_cache_size,
        0,
        _mem_buf_pool_data_size,
        rte_socket_id()  // Allocate memory on current socket
    );

    if (!_mem_buf_pool) {
        spdlog::error("Failed to create mbuf pool: {}", rte_strerror(rte_errno));
        return false;
    }
    return true;
}

bool dpdk_init::configure_and_start_port() const {
    rte_eth_conf port_conf = {};
    port_conf.rxmode.max_lro_pkt_size = RTE_ETHER_MAX_LEN;  // Max LRO packet size
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;   // Multi Queue

    int result = 0;

    constexpr uint16_t rx_queue_count = 2;
    constexpr uint16_t tx_queue_count = 2;

    rte_eth_dev_configure(_port_id, rx_queue_count, tx_queue_count, &port_conf);

    // Setup RX queue 0-n with 128 descriptors
    for (uint16_t q = 0; q < rx_queue_count; ++q) {
        int ret = rte_eth_rx_queue_setup(_port_id, q, 128, rte_eth_dev_socket_id(_port_id), nullptr, _mem_buf_pool);
        if (ret < 0) {
            spdlog::error("RX queue {} setup failed: {}", q, ret);
            return false;
        }
    }

    // Setup TX queue 0 with 128 descriptors
    result = rte_eth_tx_queue_setup(_port_id, 0, 128, rte_eth_dev_socket_id(_port_id), nullptr);
    if (result < 0) {
        spdlog::error("Failed to setup TX queue: {}", rte_strerror(-result));
        return false;
    }

    // OPTIONAL (RX interrupt mode)
    for (uint16_t q = 0; q < rx_queue_count; ++q) {
        int ret = rte_eth_dev_rx_intr_enable(_port_id, q);
        if (ret != 0) {
            spdlog::warn("RX interrupt enable failed for queue {}: {}", q, ret);
        } else {
            spdlog::info("RX interrupt enabled for queue {}", q);
        }
    }

    // Verification
    if (!is_ready_for_dpdk()) {
        spdlog::error("Failed to Ready for DPDK: {}", rte_strerror(-result));
        return false;
    }

    // Start the Ethernet device
    result = rte_eth_dev_start(_port_id);
    if (result < 0) {
        spdlog::error("Failed to start Ethernet device: {}", rte_strerror(-result));
        return false;
    }

    // Enable promiscuous mode to receive all packets
    rte_eth_promiscuous_enable(_port_id);
    return true;
}

bool dpdk_init::initialize_eal() {
    const char* eal_args[] = {
        "dpdk-app",
        "-l", "0-3",            // Logical core 0-n
        "-n", "4",              // Memory channels
        "--proc-type=auto",         // Auto-detect primary/secondary
        "--log-level=8",            // Debug log level
        "--vdev=net_tap0"           // Virtual NIC for testing
    };
    constexpr int eal_argc = std::size(eal_args);
    int result = rte_eal_init(eal_argc, const_cast<char**>(eal_args));
    if (result < 0) {
        spdlog::error("rte_eal_init failed with code: {}", result);
        return false;
    }
    return true;
}

bool dpdk_init::is_root() {
    bool root = geteuid() == 0;
    spdlog::info("Check root privilege: {}", root ? "yes" : "no");
    return root;
}

bool dpdk_init::has_hugepages() {
    std::ifstream f("/proc/meminfo");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("HugePages_Total") != std::string::npos) {
            try {
                auto count = std::stoi(line.substr(line.find(':') + 1));
                spdlog::info("HugePages_Total: {}", count);
                return count > 0;
            } catch (...) {
                spdlog::error("Failed to parse HugePages_Total");
                return false;
            }
        }
    }
    spdlog::warn("HugePages_Total not found in /proc/meminfo");
    return false;
}

bool dpdk_init::is_hugepages_mounted() {
    std::ifstream mounts("/proc/mounts");
    if (!mounts.is_open()) {
        spdlog::error("Failed to open /proc/mounts");
        return false;
    }

    std::string line;
    while (std::getline(mounts, line)) {
        bool is_hugetlbfs = line.find("hugetlbfs") != std::string::npos;
        if (!is_hugetlbfs) {
            continue;
        }

        bool has_mnt_huge = line.find("/mnt/huge") != std::string::npos;
        bool has_dev_hugepages = line.find("/dev/hugepages") != std::string::npos;

        if (has_mnt_huge || has_dev_hugepages) {
            spdlog::info("Hugepages filesystem is mounted: {}", line);
            return true;
        }
    }

    spdlog::warn("Hugepages filesystem is not mounted.");
    return false;
}

bool dpdk_init::is_ready_for_dpdk() {
    if (!is_root()) {
        spdlog::error("Must run as root (tip, sudo ./dpdk-fastdrop-agent)");
        return false;
    }

    if (!has_hugepages()) {
        spdlog::error("Hugepages not configured. Try: sudo sysctl -w vm.nr_hugepages=1024");
        return false;
    }

    if (!is_hugepages_mounted()) {
        spdlog::error("Hugepages not mounted. Try: sudo mount -t hugetlbfs none /mnt/huge");
        return false;
    }

    spdlog::info("Running as root user.");
    return true;
}

bool dpdk_init::configure_hugepages() {
    spdlog::info("Configuring hugepages...");

    const std::string cmd = "sysctl -w vm.nr_hugepages=1024";
    int result = std::system(cmd.c_str());
    if(result != 0) {
        spdlog::error("Failed to configure hugepages.");
        return false;
    }

    spdlog::info("Hugepages configured.");
    return result;
}

bool dpdk_init::mount_hugepages() {
    spdlog::info("Mounting hugetlbfs at /mnt/huge...");

    const std::string cmd = "mkdir -p /mnt/huge && mount -t hugetlbfs none /mnt/huge";
    int result = std::system(cmd.c_str());
    if(result != 0) {
        spdlog::error("Failed to mount hugetlbfs.");
        return false;
    }

    spdlog::info("hugetlbfs mounted successfully.");
    return result;
}

bool dpdk_init::ensure_dpdk_environment() {
    if (!is_root()) {
        spdlog::error("Must run as root (tip, sudo ./dpdk-fastdrop-agent)");
        return false;
    }

    bool result = true;

    if (!has_hugepages()) {
        if (!configure_hugepages()) {
            spdlog::error("Failed to configure hugepages");
            result = false;
        }
    } else {
        spdlog::info("Hugepages are configured.");
    }

    if (!is_hugepages_mounted()) {
        if (!mount_hugepages()) {
            spdlog::error("Failed to mount hugepages");
            result = false;
        }
    } else {
        spdlog::info("Hugepages are mounted.");
    }

    return result;
}

bool dpdk_init::is_initialized() const {
    return _initialized;
}

void dpdk_init::stop_workers() {
    rte_atomic32_set(&_running, 0);

    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_wait_lcore(lcore_id);
    }
}

int dpdk_init::run_loop_worker(void* arg) {
    auto* self = static_cast<dpdk_init*>(arg);
    const unsigned lcore_id = rte_lcore_id();
    const uint16_t burst_size = 32;
    rte_mbuf* bufs[burst_size];

    const uint16_t rx_queue_count = 2;
    const uint16_t queue_id = lcore_id % rx_queue_count;

    spdlog::info("Starting worker loop on lcore {} with RX queue {}", lcore_id, queue_id);

    int empty_poll_counter = 0;
    constexpr int sleep_threshold = 100;
    while (rte_atomic32_read(&self->_running)) {
        const uint16_t nb_rx = rte_eth_rx_burst(self->_port_id, queue_id, bufs, burst_size);
        if (nb_rx == 0) {
            if (++empty_poll_counter >= sleep_threshold) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                empty_poll_counter = 0;
            } else {
                rte_pause();
            }
            continue;
        }

        empty_poll_counter = 0;

        for (uint16_t i = 0; i < nb_rx; i++) {
            rte_mbuf* pkt = bufs[i];
            const uint8_t* pkt_data = rte_pktmbuf_mtod(pkt, const uint8_t*);
            uint16_t pkt_len = rte_pktmbuf_pkt_len(pkt);

            if (self->_packet_parser.parse(pkt_data, pkt_len)) {
                // ip, port, ...
                uint32_t src_ip = self->_packet_parser.get_src_ip();
                uint16_t src_port = self->_packet_parser.get_src_port();
                bool is_tcp = self->_packet_parser.is_tcp();

                // compare
                if (self->_packet_filter.match(src_ip, src_port, is_tcp)) {
                    self->_packet_parser.print_packet_hex_ascii(pkt_data, pkt_len);
                    self->_packet_parser.print_summary();
                } else {
                    spdlog::info("Packet blocked by filter: IP={} Port={}", self->_packet_parser.ipv4_to_string(src_ip), src_port);
                }
            } else {
                spdlog::warn("Failed to parse packet on lcore {}", lcore_id);
            }

            rte_pktmbuf_free(pkt);
        }
    }

    spdlog::info("Worker loop on lcore {} exiting", lcore_id);
    return 0;
}

void dpdk_init::launch_workers() {
    unsigned lcore_id;

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(dpdk_init::run_loop_worker, this, lcore_id);
    }
}