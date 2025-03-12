cmake_minimum_required(VERSION 3.30)
project(DoorScan)

set(CMAKE_CXX_STANDARD 20)


add_executable(DoorScan main.cpp
        Network/PacketHandler.cpp
        Network/PacketHandler.h
        Helpers/helpers.h
        Helpers/helpers.cpp
        Network/ScanTCPSocket.cpp
        Network/ScanTCPSocket.h
        Network/ScanSocketPool.cpp
        Network/ScanSocketPool.h
        Network/ScanStrategy/ScanStrategy.h
        Network/ScanStrategy/SynScan.cpp
        Network/ScanStrategy/SynScan.h
        Network/PacketBuilder.cpp
        Network/PacketBuilder.h
        Network/ProtocolType.h

        Network/RawSocket/RawSocket.cpp
        Network/RawSocket/RawSocket.h
        Helpers/PortStatus.h
        Network/Datastructures/ScanResult.h
        Helpers/ReceiveStatus.h
        Network/PcapReceiver/PcapReceiver.cpp
        Network/PcapReceiver/PcapReceiver.h
)

target_link_libraries(DoorScan -lpcap)
