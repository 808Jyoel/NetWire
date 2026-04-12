#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace netwire::core {

class HostnameResolver {
public:
    std::string Resolve(uint32_t ipNetworkOrder, const std::string& fallbackIp);

private:
    std::unordered_map<uint32_t, std::string> cache_;
};

}
