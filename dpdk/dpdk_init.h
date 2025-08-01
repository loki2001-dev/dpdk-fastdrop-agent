#pragma once

#include <unistd.h>
#include <fstream>
#include <rte_ethdev.h>
#include <spdlog/spdlog.h>
#include <memory>

class dpdk_init : public std::enable_shared_from_this<dpdk_init> {
public:
    explicit dpdk_init();
    virtual ~dpdk_init();

    bool is_initialized();

private:
    bool find_and_validate_port();
    bool create_mbuf_pool();
    bool configure_and_start_port();
    bool initialize_eal();
    bool is_root();
    bool is_hugepages_mounted();
    bool is_ready_for_dpdk();
    bool has_hugepages();
    bool configure_hugepages();
    bool ensure_dpdk_environment();
    bool mount_hugepages();

private:
    rte_mempool* _mem_buf_pool;

    std::string _mem_buf_pool_name;
    uint16_t _mem_buf_pool_size;
    uint16_t _mem_buf_pool_cache_size;
    uint16_t _mem_buf_pool_data_size;

    uint16_t _port_id;
    bool _initialized;
};