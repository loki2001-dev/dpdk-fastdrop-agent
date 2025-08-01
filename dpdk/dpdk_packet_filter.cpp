#include "dpdk_packet_filter.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

dpdk_packet_filter::dpdk_packet_filter() {

}

dpdk_packet_filter::~dpdk_packet_filter() {

}

bool dpdk_packet_filter::load_rules(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        spdlog::error("Failed to open rule file: {}", path);
        return false;
    }

    nlohmann::json json;
    try {
        f >> json;
    } catch (const std::exception& e) {
        spdlog::error("JSON parse error: {}", e.what());
        return false;
    }

    _rules.clear();
    for (const auto& item : json) {
        Rule rule;

        if (item.contains("ip")) {
            std::string ip_str = item["ip"].get<std::string>();
            in_addr addr{};
            if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
                rule.ip = addr.s_addr;
            } else {
                spdlog::warn("Invalid IP in rule: {}", ip_str);
                continue;
            }
        }

        if (item.contains("port")) {
            rule.port = static_cast<uint16_t>(item["port"].get<int>());
        }

        rule.block = item.value("block", true);

        if (item.contains("comment")) {
            rule.comment = item["comment"].get<std::string>();
        }

        _rules.push_back(rule);
    }

    spdlog::info("Loaded {} filtering rules", _rules.size());
    return true;
}

bool dpdk_packet_filter::match(uint32_t ip, uint16_t port, bool is_tcp) {
    for (const auto& rule : _rules) {
        if (rule.ip && *rule.ip != ip) {
            continue;
        }

        if (rule.port && *rule.port != port) {
            continue;
        }

        // block: false
        return !rule.block;
    }
    return true;
}

void dpdk_packet_filter::print_rules_comments() const {
    spdlog::info("==== Packet Filter Rules Comments (Total: {}) ====", _rules.size());
    int idx = 0;
    for (const auto& rule : _rules) {
        if (!rule.comment.empty()) {
            spdlog::info("- Rule {}: {}", idx++, rule.comment);
        } else {
            spdlog::info("- Rule {}: (No comment)", idx++);
        }
    }
    spdlog::info("===============================================================");
}