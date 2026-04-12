#include <iostream>
#include "netwire/app/SnifferApp.hpp"
#include "netwire/capture/PcapSession.hpp"
#include "netwire/cli/Arguments.hpp"

namespace {

void printInteractiveLogo() {
    std::cout
        << "========================================\n"
        << "      _   _      _ __        ___        \n"
        << "     | \\ | | ___| |\\ \\      / (_)_ __   \n"
        << "     |  \\| |/ _ \\ __\\ \\ /\\ / /| | '__|  \n"
        << "     | |\\  |  __/ |_ \\ V  V / | | |     \n"
        << "     |_| \\_|\\___|\\__| \\_/\\_/  |_|_|     \n"
        << "            NetWire Console             \n"
        << "========================================\n\n";
}

}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        printInteractiveLogo();
        auto interactive = netwire::cli::PromptInteractiveOptions(std::cout, std::cerr);
        if (!interactive.has_value()) {
            return 1;
        }
        netwire::app::SnifferApp app;
        return app.Run(*interactive, std::cout, std::cerr);
    }

    auto parsed = netwire::cli::ParseArguments(argc, argv, std::cerr);
    if (parsed.showHelp) {
        netwire::cli::PrintUsage(std::cout);
        netwire::capture::PcapSession::ListInterfaces(std::cout, std::cerr);
        return 0;
    }
    if (!parsed.valid || !parsed.options.has_value()) {
        if (parsed.interactive) {
            printInteractiveLogo();
            auto interactive = netwire::cli::PromptInteractiveOptions(std::cout, std::cerr);
            if (!interactive.has_value()) {
                return 1;
            }
            netwire::app::SnifferApp app;
            return app.Run(*interactive, std::cout, std::cerr);
        }
        netwire::capture::PcapSession::ListInterfaces(std::cout, std::cerr);
        netwire::cli::PrintUsage(std::cout);
        return 1;
    }

    netwire::app::SnifferApp app;
    return app.Run(*parsed.options, std::cout, std::cerr);
}
