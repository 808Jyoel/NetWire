#pragma once

#include "netwire/core/Options.hpp"

#include <pcap.h>

#include <functional>
#include <optional>
#include <ostream>
#include <string>

namespace netwire::capture {

class PcapSession {
public:
    using Handler = std::function<void(const pcap_pkthdr*, const u_char*)>;

    static void ListInterfaces(std::ostream& out, std::ostream& err);
    static std::optional<std::string> ResolveInterface(const std::string& ifaceArg);

    int Run(const std::string& ifaceName,
            const core::Options& options,
            const std::string& bpfFilter,
            const Handler& handler,
            std::ostream& err) const;
};

}
