#include "netwire/parsing/TlsParser.hpp"

#include "netwire/core/Text.hpp"

#include <cstdint>

namespace netwire::parsing {

namespace {

bool CanRead(std::size_t offset, std::size_t need, std::size_t size) {
    return offset + need <= size;
}

uint16_t ReadU16(const std::string& data, std::size_t offset) {
    return static_cast<uint16_t>((static_cast<uint8_t>(data[offset]) << 8) |
                                 static_cast<uint8_t>(data[offset + 1]));
}

uint32_t ReadU24(const std::string& data, std::size_t offset) {
    return (static_cast<uint32_t>(static_cast<uint8_t>(data[offset])) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(data[offset + 1])) << 8) |
           static_cast<uint32_t>(static_cast<uint8_t>(data[offset + 2]));
}

}

std::optional<std::string> ExtractTlsServerName(const core::PacketModel& packet) {
    const std::string& data = packet.payload;
    if (!CanRead(0, 9, data.size())) {
        return std::nullopt;
    }

    if (static_cast<uint8_t>(data[0]) != 0x16) {
        return std::nullopt;
    }
    if (static_cast<uint8_t>(data[1]) != 0x03) {
        return std::nullopt;
    }

    const uint16_t recordLength = ReadU16(data, 3);
    if (!CanRead(5, recordLength, data.size())) {
        return std::nullopt;
    }

    if (static_cast<uint8_t>(data[5]) != 0x01) {
        return std::nullopt;
    }

    const uint32_t helloLength = ReadU24(data, 6);
    if (!CanRead(9, helloLength, data.size())) {
        return std::nullopt;
    }

    std::size_t pos = 9;
    if (!CanRead(pos, 2 + 32, data.size())) {
        return std::nullopt;
    }
    pos += 2 + 32;

    if (!CanRead(pos, 1, data.size())) {
        return std::nullopt;
    }
    const uint8_t sessionIdLength = static_cast<uint8_t>(data[pos]);
    pos += 1;
    if (!CanRead(pos, sessionIdLength, data.size())) {
        return std::nullopt;
    }
    pos += sessionIdLength;

    if (!CanRead(pos, 2, data.size())) {
        return std::nullopt;
    }
    const uint16_t cipherSuitesLength = ReadU16(data, pos);
    pos += 2;
    if (!CanRead(pos, cipherSuitesLength, data.size())) {
        return std::nullopt;
    }
    pos += cipherSuitesLength;

    if (!CanRead(pos, 1, data.size())) {
        return std::nullopt;
    }
    const uint8_t compressionLength = static_cast<uint8_t>(data[pos]);
    pos += 1;
    if (!CanRead(pos, compressionLength, data.size())) {
        return std::nullopt;
    }
    pos += compressionLength;

    if (!CanRead(pos, 2, data.size())) {
        return std::nullopt;
    }
    const uint16_t extensionsLength = ReadU16(data, pos);
    pos += 2;
    if (!CanRead(pos, extensionsLength, data.size())) {
        return std::nullopt;
    }
    const std::size_t extEnd = pos + extensionsLength;

    while (CanRead(pos, 4, extEnd)) {
        const uint16_t extType = ReadU16(data, pos);
        const uint16_t extLen = ReadU16(data, pos + 2);
        pos += 4;
        if (!CanRead(pos, extLen, extEnd)) {
            return std::nullopt;
        }

        if (extType == 0x0000) {
            if (extLen < 5) {
                return std::nullopt;
            }
            std::size_t namePos = pos;
            const uint16_t nameListLen = ReadU16(data, namePos);
            namePos += 2;
            const std::size_t nameEnd = pos + 2 + nameListLen;
            if (nameEnd > pos + extLen) {
                return std::nullopt;
            }

            while (CanRead(namePos, 3, nameEnd)) {
                const uint8_t nameType = static_cast<uint8_t>(data[namePos]);
                const uint16_t nameLen = ReadU16(data, namePos + 1);
                namePos += 3;
                if (!CanRead(namePos, nameLen, nameEnd)) {
                    return std::nullopt;
                }
                if (nameType == 0x00 && nameLen > 0) {
                    return core::ToLower(data.substr(namePos, nameLen));
                }
                namePos += nameLen;
            }
        }

        pos += extLen;
    }

    return std::nullopt;
}

}
