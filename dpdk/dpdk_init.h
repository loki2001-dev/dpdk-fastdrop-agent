#pragma once

#include <fstream>
#include <memory>
#include <rte_atomic.h>
#include <rte_ethdev.h>
#include <spdlog/spdlog.h>

#include "dpdk_packet_parser.h"
#include "dpdk_packet_filter.h"

class dpdk_init : public std::enable_shared_from_this<dpdk_init> {
public:
    explicit dpdk_init();
    virtual ~dpdk_init();

    bool is_initialized() const;
    void launch_workers();
    void stop_workers();

private:
    bool find_and_validate_port();
    bool create_mbuf_pool();
    bool configure_and_start_port() const;
    static bool initialize_eal();
    static bool is_root();
    static bool is_hugepages_mounted();
    static bool is_ready_for_dpdk();
    static bool has_hugepages();
    static bool configure_hugepages();
    static bool ensure_dpdk_environment();
    static bool mount_hugepages();

    static int run_loop_worker(void* arg);

private:
    dpdk_packet_parser _packet_parser;
    dpdk_packet_filter _packet_filter;

    rte_atomic32_t _running;
    rte_mempool* _mem_buf_pool;

    std::string _mem_buf_pool_name;
    uint16_t _mem_buf_pool_size;
    uint16_t _mem_buf_pool_cache_size;
    uint16_t _mem_buf_pool_data_size;

    uint16_t _port_id;
    bool _initialized;
};