#include "netwire/core/HostnameResolver.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

namespace netwire::core {

std::string HostnameResolver::Resolve(uint32_t ipNetworkOrder, const std::string& fallbackIp) {
    const auto found = cache_.find(ipNetworkOrder);
    if (found != cache_.end()) {
        return found->second;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ipNetworkOrder;

    char host[NI_MAXHOST]{};
    const int result = getnameinfo(reinterpret_cast<sockaddr*>(&addr),
                                   sizeof(addr),
                                   host,
                                   static_cast<DWORD>(sizeof(host)),
                                   nullptr,
                                   0,
                                   NI_NAMEREQD);

    std::string resolved = fallbackIp;
    if (result == 0 && host[0] != '\0') {
        resolved = host;
    }

    cache_[ipNetworkOrder] = resolved;
    return resolved;
}

}
