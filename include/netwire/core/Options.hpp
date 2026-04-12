#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace netwire::core {

struct Options {
    std::string iface;
    std::optional<std::string> ipFilter;
    std::optional<uint16_t> portFilter;
    int count = 0;
    bool demoCleartext = false;
    bool resolveHostnames = true;
    bool defensiveMode = false;
    bool alertConsole = false;
};

}
