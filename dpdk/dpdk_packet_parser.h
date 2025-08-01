#ifndef DPDK_FASTDROP_AGENT_DPDK_PACKET_PARSER_H
#define DPDK_FASTDROP_AGENT_DPDK_PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <netinet/in.h>  // ntohs, ntohl
#include <arpa/inet.h>   // inet_ntop
#include <spdlog/spdlog.h>

// Ethernet header
struct ether_hdr {
    uint8_t  dst_addr[6];
    uint8_t  src_addr[6];
    uint16_t ether_type;
} __attribute__((packed));

// IPv4 header
struct ipv4_hdr {
    uint8_t  version_ihl;       // version (4 bits) + IHL (4 bits)
    uint8_t  type_of_service;
    uint16_t total_length;
    uint16_t packet_id;
    uint16_t fragment_offset;
    uint8_t  time_to_live;
    uint8_t  next_proto_id;
    uint16_t hdr_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((packed));

// IPv6 header
struct ipv6_hdr {
    uint32_t ver_tc_fl;     // version(4), traffic class(8), flow label(20)
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
} __attribute__((packed));

// IPv6 Ext header
struct ipv6_ext_hdr {
    uint8_t next_header;
    uint8_t hdr_ext_len;    // length in 8-octet units, not including first 8 octets
} __attribute__((packed));

// TCP header
struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

// UDP header
struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} __attribute__((packed));

enum class NetworkProtocol {
    NONE,
    IPv4,
    IPv6
};

enum class L4Protocol {
    NONE,
    TCP,
    UDP,
    OTHER
};

class dpdk_packet_parser : public std::enable_shared_from_this<dpdk_packet_parser> {
public:
    explicit dpdk_packet_parser();
    virtual ~dpdk_packet_parser();

    bool parse(const uint8_t* data, uint16_t len);
    void print_packet_hex_ascii(const uint8_t* data, uint16_t len) const;
    void print_summary() const;

private:
    const uint8_t* skip_ipv6_extension_headers(const uint8_t* data, uint16_t total_len, uint8_t& next_header, uint16_t& header_len) const;
    std::string mac_to_string(const uint8_t* mac) const;

    const uint8_t* _data;
    uint16_t _len;

    const ether_hdr* _eth = nullptr;
    const ipv4_hdr* _ip4 = nullptr;
    const ipv6_hdr* _ip6 = nullptr;
    const tcp_hdr* _tcp = nullptr;
    const udp_hdr* _udp = nullptr;

    NetworkProtocol _network_proto;
    L4Protocol _l4_proto;
};

#endif // DPDK_FASTDROP_AGENT_DPDK_PACKET_PARSER_H
