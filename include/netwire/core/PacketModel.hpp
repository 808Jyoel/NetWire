#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <winsock2.h>

namespace netwire::core {

struct PacketModel {
    timeval timestamp{};
    std::string srcIp;
    std::string dstIp;
    uint32_t srcIpRaw = 0;
    uint32_t dstIpRaw = 0;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint16_t ipTotalLength = 0;
    uint8_t ttl = 0;
    uint8_t protocol = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint16_t window = 0;
    std::size_t payloadLength = 0;
    std::string payload;
};

struct HttpModel {
    std::string requestLine;
    std::optional<std::string> host;
    std::optional<std::string> userAgent;
    bool hasAuthorization = false;
    std::optional<std::string> basicCredentials;
    std::optional<std::string> passwordLikeField;
};

}
