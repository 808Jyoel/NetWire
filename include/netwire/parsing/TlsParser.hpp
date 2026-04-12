#pragma once

#include "netwire/core/PacketModel.hpp"

#include <optional>
#include <string>

namespace netwire::parsing {

std::optional<std::string> ExtractTlsServerName(const core::PacketModel& packet);

}
