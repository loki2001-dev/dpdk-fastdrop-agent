#include "dpdk_packet_parser.h"
#include <sstream>
#include <iomanip>
#include <cctype>
#include <arpa/inet.h>

dpdk_packet_parser::dpdk_packet_parser()
    : _network_proto(NetworkProtocol::NONE)
    , _l4_proto(L4Protocol::NONE)
    , _data(nullptr)
    , _len(0) {

}

dpdk_packet_parser::~dpdk_packet_parser() {

}

std::string dpdk_packet_parser::mac_to_string(const uint8_t* mac) const {
    std::stringstream ss;
    ss << std::uppercase;
    for (int i = 0; i < 6; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
        if (i != 5) ss << ":";
    }
    return ss.str();
}

const uint8_t* dpdk_packet_parser::skip_ipv6_extension_headers(const uint8_t* data, uint16_t total_len, uint8_t& next_header, uint16_t& header_len) const {
    const uint8_t* ptr = data;
    uint16_t offset = sizeof(ipv6_hdr);
    next_header = reinterpret_cast<const ipv6_hdr*>(data)->next_header;

    int max_extensions = 8;

    while (max_extensions-- > 0) {
        switch (next_header) {
            case 0:   // Hop-by-Hop Options
            case 43:  // Routing Header
            case 60:  // Destination Options
            case 51:  // Authentication Header
            case 50:  // Encapsulating Security Payload
            {
                if (offset + 2 > total_len) {
                    return nullptr;
                }
                const ipv6_ext_hdr* ext_hdr = reinterpret_cast<const ipv6_ext_hdr*>(ptr + offset);
                next_header = ext_hdr->next_header;
                uint16_t ext_len = (ext_hdr->hdr_ext_len + 1) * 8;
                offset += ext_len;
                if (offset > total_len) {
                    return nullptr;
                }
                break;
            }
            case 44: // Fragment Header
            {
                if (offset + 8 > total_len) {
                    return nullptr;
                }
                const ipv6_ext_hdr* frag_hdr = reinterpret_cast<const ipv6_ext_hdr*>(ptr + offset);
                next_header = frag_hdr->next_header;
                offset += 8;
                if (offset > total_len) {
                    return nullptr;
                }
                break;
            }
            default:
                header_len = offset;
                return ptr + offset;
        }
    }
    return nullptr;
}

bool dpdk_packet_parser::parse(const uint8_t* data, uint16_t len) {
    if (!data || len < sizeof(ether_hdr)) {
        return false;
    }

    _data = data;
    _len = len;
    _eth = reinterpret_cast<const ether_hdr*>(data);

    uint16_t eth_type = ntohs(_eth->ether_type);

    _ip4 = nullptr;
    _ip6 = nullptr;
    _tcp = nullptr;
    _udp = nullptr;
    _network_proto = NetworkProtocol::NONE;
    _l4_proto = L4Protocol::NONE;

    if (eth_type == 0x86DD) { // IPv6
        if (len < sizeof(ether_hdr) + sizeof(ipv6_hdr)) return false;
        _ip6 = reinterpret_cast<const ipv6_hdr*>(data + sizeof(ether_hdr));
        _network_proto = NetworkProtocol::IPv6;

        uint8_t next_header;
        uint16_t l4_offset = 0;
        const uint8_t* l4_ptr = skip_ipv6_extension_headers(data + sizeof(ether_hdr), len - sizeof(ether_hdr), next_header, l4_offset);
        if (!l4_ptr) return false;

        uint16_t l4_len = len - (sizeof(ether_hdr) + l4_offset);

        switch (next_header) {
            case 6: // TCP
                if (l4_len >= sizeof(tcp_hdr)) {
                    _tcp = reinterpret_cast<const tcp_hdr*>(l4_ptr);
                    _l4_proto = L4Protocol::TCP;
                }
                break;
            case 17: // UDP
                if (l4_len >= sizeof(udp_hdr)) {
                    _udp = reinterpret_cast<const udp_hdr*>(l4_ptr);
                    _l4_proto = L4Protocol::UDP;
                }
                break;
            default:
                _l4_proto = L4Protocol::OTHER;
                break;
        }
    } else if (eth_type == 0x0800) { // IPv4
        if (len < sizeof(ether_hdr) + sizeof(ipv4_hdr)) return false;
        _ip4 = reinterpret_cast<const ipv4_hdr*>(data + sizeof(ether_hdr));
        _network_proto = NetworkProtocol::IPv4;

        uint8_t ihl = _ip4->version_ihl & 0x0F;
        uint16_t ip_header_len = ihl * 4;
        if (len < sizeof(ether_hdr) + ip_header_len) return false;

        uint8_t next_proto = _ip4->next_proto_id;
        const uint8_t* l4_ptr = data + sizeof(ether_hdr) + ip_header_len;
        uint16_t l4_len = len - (sizeof(ether_hdr) + ip_header_len);

        if (next_proto == 6 && l4_len >= sizeof(tcp_hdr)) {  // TCP
            _tcp = reinterpret_cast<const tcp_hdr*>(l4_ptr);
            _l4_proto = L4Protocol::TCP;
        } else if (next_proto == 17 && l4_len >= sizeof(udp_hdr)) { // UDP
            _udp = reinterpret_cast<const udp_hdr*>(l4_ptr);
            _l4_proto = L4Protocol::UDP;
        } else {
            _l4_proto = L4Protocol::OTHER;
        }
    } else {
        _network_proto = NetworkProtocol::NONE;
        _l4_proto = L4Protocol::NONE;
    }

    return true;
}

void dpdk_packet_parser::print_packet_hex_ascii(const uint8_t* data, uint16_t len) const {
    constexpr size_t line_width = 16;
    size_t max_len = len < 64 ? len : 64;

    spdlog::info("===============================================================");
    spdlog::info("Data (first {} bytes):", max_len);

    for (size_t offset = 0; offset < max_len; offset += line_width) {
        std::stringstream ss;
        ss << std::setw(4) << std::setfill('0') << std::hex << offset << "  ";

        // HEX
        for (size_t i = 0; i < line_width; ++i) {
            if (offset + i < max_len) {
                ss << std::setw(2) << std::setfill('0') << std::hex << (int)data[offset + i] << " ";
            } else {
                ss << "   ";
            }
        }
        ss << " ";

        // ASCII
        for (size_t i = 0; i < line_width; ++i) {
            if (offset + i < max_len) {
                unsigned char c = data[offset + i];
                ss << (std::isprint(c) ? static_cast<char>(c) : '.');
            }
        }

        spdlog::info("{}", ss.str());
    }
}

void dpdk_packet_parser::print_summary() const {
    if (!_eth) return;

    std::stringstream ss;
    ss << "Ethernet: DST=" << mac_to_string(_eth->dst_addr)
       << " SRC=" << mac_to_string(_eth->src_addr)
       << " Ethertype=0x" << std::hex << ntohs(_eth->ether_type);
    spdlog::info("{}", ss.str());

    if (_network_proto == NetworkProtocol::IPv6 && _ip6) {
        uint8_t version = (ntohl(_ip6->ver_tc_fl) >> 28) & 0xF;
        uint16_t payload_len = ntohs(_ip6->payload_len);

        char src_ip[INET6_ADDRSTRLEN] = {0x00, };
        char dst_ip[INET6_ADDRSTRLEN] = {0x00, };
        inet_ntop(AF_INET6, _ip6->src_addr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, _ip6->dst_addr, dst_ip, sizeof(dst_ip));

        spdlog::info("IPv6: Version={} PayloadLen={} NextHeader={} HopLimit={}",
                     version,
                     payload_len,
                     _ip6->next_header,
                     _ip6->hop_limit);
        spdlog::info("IPv6 SRC: {}", src_ip);
        spdlog::info("IPv6 DST: {}", dst_ip);
    }
    else if (_network_proto == NetworkProtocol::IPv4 && _ip4) {
        char src_ip[INET_ADDRSTRLEN] = {0x00, };
        char dst_ip[INET_ADDRSTRLEN] = {0x00, };
        inet_ntop(AF_INET, &_ip4->src_addr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &_ip4->dst_addr, dst_ip, sizeof(dst_ip));

        spdlog::info("IPv4: Version={} IHL={} TotalLen={} TTL={} Protocol={}",
                     (_ip4->version_ihl >> 4),
                     (_ip4->version_ihl & 0x0F),
                     ntohs(_ip4->total_length),
                     _ip4->time_to_live, _ip4->next_proto_id);
        spdlog::info("IPv4 SRC: {}", src_ip);
        spdlog::info("IPv4 DST: {}", dst_ip);
    }

    switch (_l4_proto) {
        case L4Protocol::TCP:
            if (_tcp) {
                spdlog::info("TCP: SRC_PORT={} DST_PORT={}", ntohs(_tcp->src_port), ntohs(_tcp->dst_port));
            }
            break;
        case L4Protocol::UDP:
            if (_udp) {
                spdlog::info("UDP: SRC_PORT={} DST_PORT={}", ntohs(_udp->src_port), ntohs(_udp->dst_port));
            }
            break;
        case L4Protocol::OTHER:
            if (_network_proto == NetworkProtocol::IPv6 && _ip6) {
                spdlog::info("L4 Protocol: {}", (int)_ip6->next_header);
            } else if (_network_proto == NetworkProtocol::IPv4 && _ip4) {
                spdlog::info("L4 Protocol: {}", (int)_ip4->next_proto_id);
            }
            break;
        default:
            break;
    }
}