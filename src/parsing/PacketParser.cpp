#include "netwire/parsing/PacketParser.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <ctime>
#include <iomanip>
#include <sstream>

namespace netwire::parsing {

namespace {

struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct IPv4Header {
    uint8_t versionIhl;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsFragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint32_t srcAddr;
    uint32_t dstAddr;
};

struct TcpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t dataOffsetRes;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPtr;
};

std::string IpToString(uint32_t networkOrder) {
    in_addr addr{};
    addr.S_un.S_addr = networkOrder;
    char buffer[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN) == nullptr) {
        return "0.0.0.0";
    }
    return buffer;
}

}

bool IsValidIPv4(const std::string& ip) {
    in_addr addr{};
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

bool IsPrivateOrLoopback(uint32_t ipNetworkOrder) {
    const uint32_t ip = ntohl(ipNetworkOrder);
    const auto b1 = static_cast<uint8_t>((ip >> 24) & 0xFF);
    const auto b2 = static_cast<uint8_t>((ip >> 16) & 0xFF);
    if (b1 == 10) {
        return true;
    }
    if (b1 == 172 && b2 >= 16 && b2 <= 31) {
        return true;
    }
    if (b1 == 192 && b2 == 168) {
        return true;
    }
    return b1 == 127;
}

std::string FormatTimestamp(const timeval& timestamp) {
    std::tm tmLocal{};
    time_t t = timestamp.tv_sec;
    localtime_s(&tmLocal, &t);
    std::ostringstream out;
    out << std::setfill('0')
        << "[" << std::setw(2) << tmLocal.tm_hour << ":"
        << std::setw(2) << tmLocal.tm_min << ":"
        << std::setw(2) << tmLocal.tm_sec << "."
        << std::setw(6) << timestamp.tv_usec << "]";
    return out.str();
}

bool TryParsePacket(const pcap_pkthdr* header, const u_char* packet, core::PacketModel& outPacket) {
    if (!header || !packet || header->caplen < sizeof(EthernetHeader)) {
        return false;
    }

    const auto* ethernet = reinterpret_cast<const EthernetHeader*>(packet);
    if (ntohs(ethernet->type) != 0x0800) {
        return false;
    }

    const auto* ipStart = packet + sizeof(EthernetHeader);
    if (header->caplen < sizeof(EthernetHeader) + sizeof(IPv4Header)) {
        return false;
    }
    const auto* ip = reinterpret_cast<const IPv4Header*>(ipStart);
    const uint8_t ihl = static_cast<uint8_t>((ip->versionIhl & 0x0F) * 4);
    if (ihl < 20 || ip->protocol != IPPROTO_TCP) {
        return false;
    }

    const auto* tcpStart = ipStart + ihl;
    if (header->caplen < static_cast<uint32_t>(sizeof(EthernetHeader) + ihl + sizeof(TcpHeader))) {
        return false;
    }
    const auto* tcp = reinterpret_cast<const TcpHeader*>(tcpStart);
    const uint8_t tcpHeaderLength = static_cast<uint8_t>(((tcp->dataOffsetRes >> 4) & 0x0F) * 4);
    if (tcpHeaderLength < 20) {
        return false;
    }

    const auto* payloadStart = tcpStart + tcpHeaderLength;
    const auto* packetEnd = packet + header->caplen;
    if (payloadStart > packetEnd) {
        return false;
    }

    outPacket.timestamp = header->ts;
    outPacket.srcIpRaw = ip->srcAddr;
    outPacket.dstIpRaw = ip->dstAddr;
    outPacket.srcIp = IpToString(ip->srcAddr);
    outPacket.dstIp = IpToString(ip->dstAddr);
    outPacket.srcPort = ntohs(tcp->srcPort);
    outPacket.dstPort = ntohs(tcp->dstPort);
    outPacket.ipTotalLength = ntohs(ip->totalLength);
    outPacket.ttl = ip->ttl;
    outPacket.protocol = ip->protocol;
    outPacket.seq = ntohl(tcp->seqNum);
    outPacket.ack = ntohl(tcp->ackNum);
    outPacket.window = ntohs(tcp->window);
    outPacket.payloadLength = static_cast<std::size_t>(packetEnd - payloadStart);
    outPacket.payload.assign(reinterpret_cast<const char*>(payloadStart), outPacket.payloadLength);
    return true;
}

}
