#ifndef DPDK_FASTDROP_AGENT_DPDK_PACKET_FILTER_H
#define DPDK_FASTDROP_AGENT_DPDK_PACKET_FILTER_H

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

class dpdk_packet_filter : public std::enable_shared_from_this<dpdk_packet_filter> {
public:
    explicit dpdk_packet_filter();
    virtual ~dpdk_packet_filter();

    bool load_rules(const std::string& path);
    bool match(uint32_t ip, uint16_t port, bool is_tcp);
    void print_rules_comments() const;

private:
    typedef struct Rule {
        std::optional<uint32_t> ip;
        std::optional<uint16_t> port;
        bool block;
        std::string comment;
    } Rule_t;

    std::vector<Rule_t> _rules;
};

#endif // DPDK_FASTDROP_AGENT_DPDK_PACKET_FILTER_H
