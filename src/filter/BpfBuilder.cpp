#include "netwire/filter/BpfBuilder.hpp"

#include <sstream>

namespace netwire::filter {

std::string BuildTcpFilter(const core::Options& options) {
    std::ostringstream bpf;
    bpf << "tcp";
    if (options.ipFilter.has_value()) {
        bpf << " and host " << *options.ipFilter;
    }
    if (options.portFilter.has_value()) {
        bpf << " and port " << *options.portFilter;
    }
    return bpf.str();
}

}
