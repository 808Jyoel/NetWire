#pragma once

#include "netwire/core/Options.hpp"

#include <optional>
#include <ostream>

namespace netwire::cli {

struct ParseResult {
    bool valid = false;
    bool showHelp = false;
    bool interactive = false;
    std::optional<core::Options> options;
};

ParseResult ParseArguments(int argc, char* argv[], std::ostream& err);
void PrintUsage(std::ostream& out);
std::optional<core::Options> PromptInteractiveOptions(std::ostream& out, std::ostream& err);

}
