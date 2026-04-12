cmake_minimum_required(VERSION 3.16)
project(netwire_sniffer_lite LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(NETWIRE_SOURCES
    src/main.cpp
    src/app/SnifferApp.cpp
    src/capture/PcapSession.cpp
    src/cli/Arguments.cpp
    src/core/HostnameResolver.cpp
    src/core/Text.cpp
    src/filter/BpfBuilder.cpp
    src/parsing/HttpParser.cpp
    src/parsing/PacketParser.cpp
    src/parsing/TlsParser.cpp
)

add_executable(sniffer_lite ${NETWIRE_SOURCES})
target_include_directories(sniffer_lite PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
    target_compile_definitions(sniffer_lite PRIVATE _WINSOCK_DEPRECATED_NO_WARNINGS)
    set(NPCAP_SDK_PATH "" CACHE PATH "Ruta al SDK de Npcap/WinPcap")

    set(_pcap_hints
        "${NPCAP_SDK_PATH}"
        "$ENV{NPCAP_SDK_PATH}"
        "C:/Program Files/Npcap SDK"
        "C:/Program Files (x86)/Npcap SDK"
    )

    find_path(PCAP_INCLUDE_DIR
        NAMES pcap.h
        HINTS ${_pcap_hints}
        PATH_SUFFIXES Include include
    )

    find_library(PCAP_WPCAP_LIB
        NAMES wpcap
        HINTS ${_pcap_hints}
        PATH_SUFFIXES Lib/x64 Lib lib
    )

    find_library(PCAP_PACKET_LIB
        NAMES Packet
        HINTS ${_pcap_hints}
        PATH_SUFFIXES Lib/x64 Lib lib
    )

    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_WPCAP_LIB OR NOT PCAP_PACKET_LIB)
        message(FATAL_ERROR "No se encontro el SDK de Npcap/WinPcap. Define NPCAP_SDK_PATH con la ruta del SDK.")
    endif()

    target_include_directories(sniffer_lite PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(sniffer_lite PRIVATE ${PCAP_WPCAP_LIB} ${PCAP_PACKET_LIB} Ws2_32)
endif()
