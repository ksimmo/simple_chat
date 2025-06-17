#ifndef CLIENT_H
#define CLIENT_H

#include <mutex>

#include "net/secure_socket.h"
#include "net/packet.h"
#include "net/peer.h"

class Client
{
private:
    Peer* peer = nullptr;
    int epoll_fd = -1;
    int epoll_max_events = -1;
    struct epoll_event* epoll_evs = nullptr;
   
    char* rw_buffer = nullptr;

    std::mutex mutex;
    std::queue<PeerEvent> events;
    std::queue<Packet*> incomming_packets;
    std::queue<Packet*> outgoing_packets;
    
public:
    Client();
    ~Client();

    bool initialize(std::string, int port, int maxevents=100, SSL_CTX* ctx=nullptr);
    bool is_initialized() {return this->peer!=nullptr;}

    void shutdown();

    void handle_events(int timeout=100);
    PeerEvent pop_event();

    void add_packet(Packet* packet);
    Packet* pop_packet();
};

#endif