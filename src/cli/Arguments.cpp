#include "netwire/cli/Arguments.hpp"

#include "netwire/capture/PcapSession.hpp"
#include "netwire/core/Text.hpp"
#include "netwire/parsing/PacketParser.hpp"

#include <iostream>
#include <string>

namespace netwire::cli {

namespace {

bool ParsePort(const std::string& value, uint16_t& outPort) {
    if (!core::IsNumeric(value)) {
        return false;
    }
    const int parsed = std::stoi(value);
    if (parsed < 1 || parsed > 65535) {
        return false;
    }
    outPort = static_cast<uint16_t>(parsed);
    return true;
}

bool AskYesNo(const std::string& question, bool defaultValue, std::ostream& out) {
    std::string input;
    while (true) {
        out << question << (defaultValue ? " [Y/n]: " : " [y/N]: ");
        std::getline(std::cin, input);
        input = core::ToLower(core::Trim(input));
        if (input.empty()) {
            return defaultValue;
        }
        if (input == "y" || input == "yes" || input == "s" || input == "si") {
            return true;
        }
        if (input == "n" || input == "no") {
            return false;
        }
        out << "Respuesta invalida. Usa y/n.\n";
    }
}

}

ParseResult ParseArguments(int argc, char* argv[], std::ostream& err) {
    ParseResult result{};
    core::Options options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--iface" && i + 1 < argc) {
            options.iface = argv[++i];
            continue;
        }

        if (arg == "--ip" && i + 1 < argc) {
            const std::string ip = argv[++i];
            if (!parsing::IsValidIPv4(ip)) {
                err << "IPv4 invalida: " << ip << "\n";
                return result;
            }
            options.ipFilter = ip;
            continue;
        }

        if (arg == "--port" && i + 1 < argc) {
            uint16_t port = 0;
            if (!ParsePort(argv[++i], port)) {
                err << "Puerto invalido\n";
                return result;
            }
            options.portFilter = port;
            continue;
        }

        if (arg == "--count" && i + 1 < argc) {
            const std::string countStr = argv[++i];
            if (!core::IsNumeric(countStr)) {
                err << "Count invalido\n";
                return result;
            }
            options.count = std::stoi(countStr);
            if (options.count < 0) {
                err << "Count debe ser >= 0\n";
                return result;
            }
            continue;
        }

        if (arg == "--demo-cleartext") {
            options.demoCleartext = true;
            continue;
        }

        if (arg == "--no-hostname") {
            options.resolveHostnames = false;
            continue;
        }

        if (arg == "--defensive") {
            options.defensiveMode = true;
            continue;
        }

        if (arg == "--interactive" || arg == "-i") {
            result.valid = true;
            result.interactive = true;
            return result;
        }

        if (arg == "--help" || arg == "-h") {
            result.valid = true;
            result.showHelp = true;
            return result;
        }

        err << "Argumento no reconocido: " << arg << "\n";
        return result;
    }

    if (options.iface.empty()) {
        err << "Falta --iface\n";
        return result;
    }

    result.valid = true;
    result.options = options;
    return result;
}

void PrintUsage(std::ostream& out) {
    out << "Uso:\n";
    out << "  sniffer_lite --iface <indice|nombre> [--ip <IPv4>] [--port <1-65535>] [--count <N>] [--demo-cleartext] [--no-hostname] [--defensive]\n";
    out << "  sniffer_lite --interactive\n\n";
    out << "Ejemplos:\n";
    out << "  sniffer_lite --iface 1 --port 80\n";
    out << "  sniffer_lite --iface \\Device\\NPF_{...} --ip 192.168.1.10 --count 50\n";
    out << "  sniffer_lite --interactive\n";
}

std::optional<core::Options> PromptInteractiveOptions(std::ostream& out, std::ostream& err) {
    core::Options options;
    capture::PcapSession::ListInterfaces(out, err);

    std::string input;
    out << "Selecciona interfaz (indice o nombre): ";
    std::getline(std::cin, input);
    options.iface = core::Trim(input);
    if (options.iface.empty()) {
        err << "Interfaz requerida.\n";
        return std::nullopt;
    }

    out << "Filtro IP (opcional, Enter para omitir): ";
    std::getline(std::cin, input);
    input = core::Trim(input);
    if (!input.empty()) {
        if (!parsing::IsValidIPv4(input)) {
            err << "IPv4 invalida.\n";
            return std::nullopt;
        }
        options.ipFilter = input;
    }

    out << "Filtro puerto (opcional, Enter para omitir): ";
    std::getline(std::cin, input);
    input = core::Trim(input);
    if (!input.empty()) {
        uint16_t port = 0;
        if (!ParsePort(input, port)) {
            err << "Puerto invalido.\n";
            return std::nullopt;
        }
        options.portFilter = port;
    }

    out << "Cantidad de paquetes (0 = infinito): ";
    std::getline(std::cin, input);
    input = core::Trim(input);
    if (!input.empty()) {
        if (!core::IsNumeric(input)) {
            err << "Count invalido.\n";
            return std::nullopt;
        }
        options.count = std::stoi(input);
    }

    options.demoCleartext = AskYesNo("Activar demo cleartext local", false, out);
    options.resolveHostnames = AskYesNo("Resolver hostnames (reverse DNS)", true, out);
    options.defensiveMode = AskYesNo("Activar modo defensivo de alertas", true, out);
    options.alertConsole = options.defensiveMode;
    return options;
}

}
