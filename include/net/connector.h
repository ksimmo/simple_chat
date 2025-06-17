#ifndef CONNECTOR_H
#define CONNECTOR_H

#include <mutex>

#include "net/secure_socket.h"
#include "net/packet.h"
#include "net/peer.h"

struct ConnectorEvent
{
    int fd;
    PeerEvent ev;
};

struct ConnectorPacket
{
    int fd;
    Packet* packet;
};

//base class for host & client (currently they are sharing a lot of stuff)
class Connector
{
private:
    Peer* peer = nullptr; //main socket 

    int epoll_fd = -1;
    int epoll_max_events = -1;
    struct epoll_event* epoll_evs = nullptr;
   
    char* rw_buffer = nullptr;

    std::queue<ConnectorEvent> events;
    std::queue<ConnectorPacket> incomming_packets;
    std::queue<ConnectorPacket> outgoing_packets;
    std::mutex mutex;
public:
    ~Connector();
    bool is_initialized() { return this->peer!=nullptr; }
    void shutdown();

    void add_packet(int sender, Packet* packet);
    ConnectorPacket pop_packet();
};

#endif