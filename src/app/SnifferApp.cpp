#include "netwire/app/SnifferApp.hpp"

#include "netwire/core/HostnameResolver.hpp"
#include "netwire/core/Text.hpp"
#include "netwire/capture/PcapSession.hpp"
#include "netwire/filter/BpfBuilder.hpp"
#include "netwire/parsing/HttpParser.hpp"
#include "netwire/parsing/PacketParser.hpp"
#include "netwire/parsing/TlsParser.hpp"

#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <unordered_set>
#include <unordered_map>

namespace netwire::app {

namespace {

std::string EndpointId(const std::string& ip, uint16_t port) {
    return ip + ":" + std::to_string(port);
}

std::string FlowKey(const std::string& srcIp, uint16_t srcPort, const std::string& dstIp, uint16_t dstPort) {
    return EndpointId(srcIp, srcPort) + "->" + EndpointId(dstIp, dstPort);
}

std::string NormalizeHost(const std::string& value) {
    std::string host = core::ToLower(core::Trim(value));
    const auto colon = host.find(':');
    if (colon != std::string::npos) {
        host = host.substr(0, colon);
    }
    return host;
}

bool EndsWith(const std::string& value, const std::string& suffix) {
    if (suffix.size() > value.size()) {
        return false;
    }
    return value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string DetectCdn(const std::string& host) {
    if (host.empty()) {
        return "";
    }
    static const std::vector<std::pair<std::string, std::string>> signatures = {
        {"akamaitechnologies.com", "akamai"},
        {"edgesuite.net", "akamai"},
        {"edgekey.net", "akamai"},
        {"cloudflare.com", "cloudflare"},
        {"cloudfront.net", "cloudfront"},
        {"fastly.net", "fastly"},
        {"fastlylb.net", "fastly"},
        {"cdn77.org", "cdn77"}
    };
    for (const auto& signature : signatures) {
        if (EndsWith(host, signature.first)) {
            return signature.second;
        }
    }
    return "";
}

bool StartsWith(const std::string& value, const std::string& prefix) {
    if (prefix.size() > value.size()) {
        return false;
    }
    return value.compare(0, prefix.size(), prefix) == 0;
}

std::string DetectProviderFromIp(const std::string& ip) {
    if (StartsWith(ip, "162.159.")) {
        return "cloudflare";
    }
    if (StartsWith(ip, "2.22.") || StartsWith(ip, "23.")) {
        return "akamai";
    }
    if (StartsWith(ip, "140.82.")) {
        return "github";
    }
    if (StartsWith(ip, "35.186.")) {
        return "google-cloud";
    }
    if (StartsWith(ip, "52.89.")) {
        return "aws";
    }
    return "";
}

std::string DetectProvider(const std::string& host, const std::string& ip) {
    const std::string byHost = DetectCdn(host);
    if (!byHost.empty()) {
        return byHost;
    }
    return DetectProviderFromIp(ip);
}

std::string FormatEndpoint(const std::string& ip, const std::string& host, uint16_t port) {
    if (host.empty() || host == ip) {
        const std::string provider = DetectProvider("", ip);
        if (provider.empty()) {
            return ip + ":" + std::to_string(port);
        }
        return ip + "{net:" + provider + "}:" + std::to_string(port);
    }
    const std::string provider = DetectProvider(host, ip);
    if (provider.empty()) {
        return host + "[" + ip + "]:" + std::to_string(port);
    }
    return host + "{net:" + provider + "}[" + ip + "]:" + std::to_string(port);
}

const std::unordered_set<uint16_t> kCommonOutboundPorts = {
    53, 80, 123, 443, 465, 587, 853, 993, 995
};

const std::unordered_set<uint16_t> kHighRiskShellPorts = {
    4444, 5555, 1337, 9001, 31337
};

struct FlowTelemetry {
    int packetCount = 0;
    int smallOutboundCount = 0;
    bool alertedUncommonPort = false;
    bool alertedHighRiskPort = false;
    bool alertedBeaconing = false;
    bool alertedUnknownPersistent = false;
};

void EmitAlert(std::ostream& out,
               std::ofstream* alertStream,
               const std::string& level,
               const std::string& message) {
    const std::string line = "[ALERTA][" + level + "] " + message;
    out << line << "\n";
    if (alertStream && alertStream->is_open()) {
        (*alertStream) << line << "\n";
        alertStream->flush();
    }
}

void AssignFlowHost(const core::PacketModel& packet,
                    const std::string& host,
                    std::unordered_map<std::string, std::string>& flowHostByKey,
                    std::unordered_map<std::string, std::string>& flowServerByKey) {
    if (host.empty()) {
        return;
    }
    const std::string fwd = FlowKey(packet.srcIp, packet.srcPort, packet.dstIp, packet.dstPort);
    const std::string rev = FlowKey(packet.dstIp, packet.dstPort, packet.srcIp, packet.srcPort);
    const std::string serverEndpoint = EndpointId(packet.dstIp, packet.dstPort);
    flowHostByKey[fwd] = host;
    flowHostByKey[rev] = host;
    flowServerByKey[fwd] = serverEndpoint;
    flowServerByKey[rev] = serverEndpoint;
}

}

int SnifferApp::Run(const core::Options& options, std::ostream& out, std::ostream& err) const {
    const auto ifaceName = capture::PcapSession::ResolveInterface(options.iface);
    if (!ifaceName.has_value()) {
        err << "No se pudo resolver la interfaz: " << options.iface << "\n";
        capture::PcapSession::ListInterfaces(out, err);
        return 1;
    }

    const std::string bpf = filter::BuildTcpFilter(options);
    out << "Capturando en: " << *ifaceName << "\n";
    out << "Filtro BPF: " << bpf << "\n";
    if (options.demoCleartext) {
        out << "Modo demo cleartext activo solo para trafico local/privado\n";
    }
    out << "Resolucion de hostname: " << (options.resolveHostnames ? "activa" : "desactivada") << "\n";
    out << "Modo defensivo: " << (options.defensiveMode ? "activo" : "desactivado") << "\n";
    out << "Vista: compacta\n";

    std::ofstream alertStream;
    if (options.defensiveMode && options.alertConsole) {
        const std::filesystem::path alertsPath = std::filesystem::absolute("netwire-alerts.log");
        alertStream.open(alertsPath, std::ios::out | std::ios::trunc);
        if (!alertStream.is_open()) {
            err << "No se pudo abrir archivo de alertas: " << alertsPath.string() << "\n";
        } else {
            const std::string command =
                "start \"NetWire Alerts\" powershell -NoExit -Command \"Get-Content -Path '" + alertsPath.string() + "' -Wait\"";
            std::system(command.c_str());
            out << "Consola de alertas: " << alertsPath.string() << "\n";
        }
    }

    out << "Presiona Ctrl+C para detener\n\n";

    core::HostnameResolver resolver;
    std::unordered_map<std::string, std::string> flowHostByKey;
    std::unordered_map<std::string, std::string> flowServerByKey;
    std::unordered_map<std::string, FlowTelemetry> flowTelemetryByKey;
    capture::PcapSession session;
    return session.Run(*ifaceName, options, bpf,
                       [&](const pcap_pkthdr* header, const u_char* raw) {
                           core::PacketModel packet;
                           if (!parsing::TryParsePacket(header, raw, packet)) {
                               return;
                           }

                           const auto tlsHost = parsing::ExtractTlsServerName(packet);
                           if (tlsHost.has_value()) {
                               AssignFlowHost(packet, NormalizeHost(*tlsHost), flowHostByKey, flowServerByKey);
                           }

                           const auto http = parsing::ParseHttpRequest(packet, options.demoCleartext);
                           if (http.has_value() && http->host.has_value()) {
                               AssignFlowHost(packet, NormalizeHost(*http->host), flowHostByKey, flowServerByKey);
                           }

                           std::string srcHost = options.resolveHostnames ? resolver.Resolve(packet.srcIpRaw, packet.srcIp) : packet.srcIp;
                           std::string dstHost = options.resolveHostnames ? resolver.Resolve(packet.dstIpRaw, packet.dstIp) : packet.dstIp;
                           const std::string key = FlowKey(packet.srcIp, packet.srcPort, packet.dstIp, packet.dstPort);
                           const auto flowHost = flowHostByKey.find(key);
                           const auto flowServer = flowServerByKey.find(key);
                           if (flowHost != flowHostByKey.end() && flowServer != flowServerByKey.end()) {
                               const std::string srcEndpoint = EndpointId(packet.srcIp, packet.srcPort);
                               const std::string dstEndpoint = EndpointId(packet.dstIp, packet.dstPort);
                               if (srcEndpoint == flowServer->second) {
                                   srcHost = flowHost->second;
                               }
                               if (dstEndpoint == flowServer->second) {
                                   dstHost = flowHost->second;
                               }
                           }

                           out << parsing::FormatTimestamp(packet.timestamp) << " "
                               << FormatEndpoint(packet.srcIp, srcHost, packet.srcPort) << " -> "
                               << FormatEndpoint(packet.dstIp, dstHost, packet.dstPort)
                               << " | payload=" << packet.payloadLength << "\n";

                           if (options.defensiveMode) {
                               auto& telemetry = flowTelemetryByKey[key];
                               telemetry.packetCount += 1;

                               const bool srcPrivate = parsing::IsPrivateOrLoopback(packet.srcIpRaw);
                               const bool dstPrivate = parsing::IsPrivateOrLoopback(packet.dstIpRaw);
                               const bool outbound = srcPrivate && !dstPrivate;
                               const bool unknownProvider = DetectProvider(dstHost, packet.dstIp).empty();

                               if (outbound && packet.payloadLength <= 8) {
                                   telemetry.smallOutboundCount += 1;
                               }

                               if (outbound && !kCommonOutboundPorts.count(packet.dstPort) && packet.payloadLength > 0 && !telemetry.alertedUncommonPort) {
                                   EmitAlert(out, &alertStream, "MEDIA", "Puerto de salida no comun detectado en flujo " + key + " (dstPort=" + std::to_string(packet.dstPort) + ")");
                                   telemetry.alertedUncommonPort = true;
                               }

                               if (outbound && kHighRiskShellPorts.count(packet.dstPort) && unknownProvider && !telemetry.alertedHighRiskPort) {
                                   EmitAlert(out, &alertStream, "ALTA", "Patron similar a reverse shell: puerto de alto riesgo y destino no clasificado en flujo " + key);
                                   telemetry.alertedHighRiskPort = true;
                               }

                               if (outbound && telemetry.smallOutboundCount >= 20 && !telemetry.alertedBeaconing) {
                                   EmitAlert(out, &alertStream, "MEDIA", "Patron beaconing: multiples paquetes pequenos salientes en flujo " + key);
                                   telemetry.alertedBeaconing = true;
                               }

                               if (outbound && telemetry.packetCount >= 120 && unknownProvider && !telemetry.alertedUnknownPersistent) {
                                   EmitAlert(out, &alertStream, "BAJA", "Flujo persistente hacia destino sin proveedor identificado: " + key);
                                   telemetry.alertedUnknownPersistent = true;
                               }
                           }

                           if (http.has_value()) {
                               out << "  HTTP " << http->requestLine;
                               if (http->host.has_value()) {
                                   out << " | host=" << *http->host;
                               }
                               if (http->basicCredentials.has_value()) {
                                   out << " | basic=" << *http->basicCredentials;
                               }
                               if (http->passwordLikeField.has_value()) {
                                   out << " | pass=" << *http->passwordLikeField;
                               }
                               out << "\n";
                           }
                       },
                       err);
}

}
