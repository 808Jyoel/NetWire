#pragma once

#include "netwire/core/PacketModel.hpp"

#include <optional>
#include <string>

namespace netwire::parsing {

std::optional<core::HttpModel> ParseHttpRequest(const core::PacketModel& packet, bool demoCleartext);

}
