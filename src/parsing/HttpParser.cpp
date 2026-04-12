#include "netwire/parsing/HttpParser.hpp"

#include "netwire/core/Text.hpp"
#include "netwire/parsing/PacketParser.hpp"

#include <sstream>
#include <unordered_map>
#include <vector>

namespace netwire::parsing {

namespace {

bool StartsWithMethod(const std::string& payload) {
    static const std::vector<std::string> methods = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "
    };
    for (const auto& method : methods) {
        if (payload.rfind(method, 0) == 0) {
            return true;
        }
    }
    return false;
}

std::string DecodeBase64(const std::string& value) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::unordered_map<char, int> map;
    for (std::size_t i = 0; i < alphabet.size(); ++i) {
        map[alphabet[i]] = static_cast<int>(i);
    }

    std::string out;
    int block = 0;
    int bits = -8;
    for (unsigned char c : value) {
        if (std::isspace(c)) {
            continue;
        }
        if (c == '=') {
            break;
        }
        const auto it = map.find(static_cast<char>(c));
        if (it == map.end()) {
            return {};
        }
        block = (block << 6) + it->second;
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<char>((block >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

std::optional<std::string> FindPasswordLikeField(const std::string& payload) {
    const std::string lower = core::ToLower(payload);
    static const std::vector<std::string> keys = {"password=", "passwd=", "pwd=", "pass="};
    for (const auto& key : keys) {
        const auto pos = lower.find(key);
        if (pos == std::string::npos) {
            continue;
        }
        const auto start = pos + key.size();
        const auto end = lower.find_first_of("& \r\n", start);
        return payload.substr(start, end == std::string::npos ? std::string::npos : end - start);
    }
    return std::nullopt;
}

std::unordered_map<std::string, std::string> ParseHeaders(const std::string& payload, std::string& requestLine) {
    std::unordered_map<std::string, std::string> headers;
    std::istringstream stream(payload);
    std::string line;

    if (!std::getline(stream, requestLine)) {
        return headers;
    }
    if (!requestLine.empty() && requestLine.back() == '\r') {
        requestLine.pop_back();
    }

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            break;
        }
        const auto split = line.find(':');
        if (split == std::string::npos) {
            continue;
        }
        const std::string key = core::ToLower(core::Trim(line.substr(0, split)));
        const std::string value = core::Trim(line.substr(split + 1));
        headers[key] = value;
    }

    return headers;
}

}

std::optional<core::HttpModel> ParseHttpRequest(const core::PacketModel& packet, bool demoCleartext) {
    if (packet.payload.empty() || !StartsWithMethod(packet.payload)) {
        return std::nullopt;
    }

    core::HttpModel model;
    auto headers = ParseHeaders(packet.payload, model.requestLine);

    const auto hostIt = headers.find("host");
    if (hostIt != headers.end()) {
        model.host = hostIt->second;
    }

    const auto userAgentIt = headers.find("user-agent");
    if (userAgentIt != headers.end()) {
        model.userAgent = userAgentIt->second;
    }

    const auto authorizationIt = headers.find("authorization");
    if (authorizationIt != headers.end()) {
        model.hasAuthorization = true;
        const std::string value = authorizationIt->second;
        const std::string lower = core::ToLower(value);
        if (lower.rfind("basic ", 0) == 0) {
            const std::string encoded = core::Trim(value.substr(6));
            const std::string decoded = DecodeBase64(encoded);
            if (!decoded.empty()) {
                const bool localOnly = IsPrivateOrLoopback(packet.srcIpRaw) && IsPrivateOrLoopback(packet.dstIpRaw);
                if (demoCleartext && localOnly) {
                    model.basicCredentials = decoded;
                } else {
                    const auto split = decoded.find(':');
                    if (split != std::string::npos) {
                        const std::string user = decoded.substr(0, split);
                        const std::string pass = decoded.substr(split + 1);
                        model.basicCredentials = user + ":" + core::SafeMask(pass);
                    } else {
                        model.basicCredentials = core::SafeMask(decoded);
                    }
                }
            }
        }
    }

    const auto passwordField = FindPasswordLikeField(packet.payload);
    if (passwordField.has_value()) {
        const bool localOnly = IsPrivateOrLoopback(packet.srcIpRaw) && IsPrivateOrLoopback(packet.dstIpRaw);
        if (demoCleartext && localOnly) {
            model.passwordLikeField = *passwordField;
        } else {
            model.passwordLikeField = core::SafeMask(*passwordField);
        }
    }

    return model;
}

}
