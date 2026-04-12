#pragma once

#include "netwire/core/Options.hpp"

#include <string>

namespace netwire::filter {

std::string BuildTcpFilter(const core::Options& options);

}
