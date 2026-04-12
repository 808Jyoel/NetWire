#include "netwire/capture/PcapSession.hpp"

#include "netwire/core/Text.hpp"

#include <string>

namespace netwire::capture {

namespace {

struct CallbackContext {
    PcapSession::Handler handler;
};

void CaptureCallback(u_char* userData, const pcap_pkthdr* header, const u_char* packet) {
    auto* context = reinterpret_cast<CallbackContext*>(userData);
    if (context && context->handler) {
        context->handler(header, packet);
    }
}

}

void PcapSession::ListInterfaces(std::ostream& out, std::ostream& err) {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* allDevices = nullptr;
    if (pcap_findalldevs(&allDevices, errbuf) == -1) {
        err << "Error al listar interfaces: " << errbuf << "\n";
        return;
    }

    out << "Interfaces disponibles:\n";
    int index = 1;
    for (pcap_if_t* device = allDevices; device != nullptr; device = device->next, ++index) {
        out << "  [" << index << "] " << (device->name ? device->name : "(sin nombre)");
        if (device->description) {
            out << " - " << device->description;
        }
        out << "\n";
    }
    pcap_freealldevs(allDevices);
}

std::optional<std::string> PcapSession::ResolveInterface(const std::string& ifaceArg) {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* allDevices = nullptr;
    if (pcap_findalldevs(&allDevices, errbuf) == -1) {
        return std::nullopt;
    }

    std::optional<std::string> result;
    if (core::IsNumeric(ifaceArg)) {
        const int target = std::stoi(ifaceArg);
        int index = 1;
        for (pcap_if_t* device = allDevices; device != nullptr; device = device->next, ++index) {
            if (index == target && device->name) {
                result = std::string(device->name);
                break;
            }
        }
    } else {
        for (pcap_if_t* device = allDevices; device != nullptr; device = device->next) {
            if (device->name && ifaceArg == device->name) {
                result = std::string(device->name);
                break;
            }
        }
    }

    pcap_freealldevs(allDevices);
    return result;
}

int PcapSession::Run(const std::string& ifaceName,
                     const core::Options& options,
                     const std::string& bpfFilter,
                     const Handler& handler,
                     std::ostream& err) const {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* capture = pcap_open_live(ifaceName.c_str(), 65536, 1, 1000, errbuf);
    if (!capture) {
        err << "Error abriendo interfaz: " << errbuf << "\n";
        return 1;
    }

    bpf_program fp{};
    if (pcap_compile(capture, &fp, bpfFilter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        err << "Error compilando filtro BPF: " << pcap_geterr(capture) << "\n";
        pcap_close(capture);
        return 1;
    }
    if (pcap_setfilter(capture, &fp) == -1) {
        err << "Error aplicando filtro BPF: " << pcap_geterr(capture) << "\n";
        pcap_freecode(&fp);
        pcap_close(capture);
        return 1;
    }
    pcap_freecode(&fp);

    CallbackContext context{handler};
    const int packetCount = options.count > 0 ? options.count : -1;
    const int result = pcap_loop(capture, packetCount, CaptureCallback, reinterpret_cast<u_char*>(&context));
    if (result == -1) {
        err << "Error en captura: " << pcap_geterr(capture) << "\n";
        pcap_close(capture);
        return 1;
    }

    pcap_close(capture);
    return 0;
}

}
