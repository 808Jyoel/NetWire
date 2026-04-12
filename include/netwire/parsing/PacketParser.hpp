#pragma once

#include "netwire/core/PacketModel.hpp"

#include <pcap.h>

#include <string>

namespace netwire::parsing {

bool IsValidIPv4(const std::string& ip);
bool IsPrivateOrLoopback(uint32_t ipNetworkOrder);
std::string FormatTimestamp(const timeval& timestamp);
bool TryParsePacket(const pcap_pkthdr* header, const u_char* packet, core::PacketModel& outPacket);

}
