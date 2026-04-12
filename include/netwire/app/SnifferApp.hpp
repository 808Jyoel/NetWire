#pragma once

#include "netwire/core/Options.hpp"

#include <ostream>

namespace netwire::app {

class SnifferApp {
public:
    int Run(const core::Options& options, std::ostream& out, std::ostream& err) const;
};

}
