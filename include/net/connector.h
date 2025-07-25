#ifndef CONNECTOR_H
#define CONNECTOR_H

#include <unordered_map>
#include <atomic>
#include <mutex>

#include "net/secure_socket.h"
#include "net/packet.h"
#include "net/peer.h"

enum ConnectorType {CONN_CLIENT, CONN_SERVER};

struct ConnectorEvent
{
    int fd;
    PeerEvent ev;
};

//base class for host & client (currently they are sharing a lot of stuff)
class Connector
{
private:
    ConnectorType type = CONN_CLIENT;
    SSL_CTX* ctx = nullptr;
    Peer* main_peer = nullptr; //main socket
    std::unordered_map<int, Peer*> connections; //Server: accepted connections 
    std::atomic<bool> established;

#ifdef USE_EPOLL
    int epoll_fd = -1;
    int epoll_max_events = -1;
    struct epoll_event* epoll_evs = nullptr;
#elif USE_KQUEUE
    int kq_fd = -1;
    int kq_max_events = -1;
    struct kevent* kq_evs = nullptr;
#endif
   
    char* rw_buffer = nullptr; //fixed read-write buffer

    std::queue<ConnectorEvent> events;
    std::queue<Packet*> incomming_packets;
    std::queue<Packet*> outgoing_packets;
    std::mutex mutex;

    void accept_client();
    void disconnect_client(int fd);
public:
    Connector(SSL_CTX* ctx=nullptr);
    ~Connector();
    bool initialize(ConnectorType conn_type, const std::string& address, int port, int maxevents=100);
    bool is_initialized() { return this->established; } //{ return this->main_peer!=nullptr; }
    bool should_disconnect() { return this->main_peer->should_disconnect; }
    void shutdown();

    void step(int timeout=100);

    void initiate_clean_disconnect(int fd);

    void add_event(int fd, PeerEvent ev);
    ConnectorEvent pop_event();
    void add_packet(Packet* packet);
    Packet* pop_packet();
};

#endif