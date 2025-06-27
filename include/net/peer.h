#ifndef PEER_H
#define PEER_H

#include <chrono>

#include "net/secure_socket.h"
#include "net/packet.h"



#ifdef _WIN32 //we are on windows
#elif __unix__ //we are on unix systems
#define USE_EPOLL
#elif __APPLE__
#define USE_KQUEUE
#endif

enum PeerEvent {PE_NONE, PE_CONNECTED, PE_DISCONNECTED, PE_HANDSHAKE_FINISHED, PE_AUTHENTICATED};

//class handling socket and incoming and outgoing packets
class Peer
{
private:
    SSL_CTX* ctx = nullptr;
    SecureSocket* sock = nullptr;
    std::string address = "";
    int port = -1;
    std::queue<PeerEvent> events;
    std::chrono::time_point<std::chrono::system_clock> time_conn; //time since connect/accept -> use to check ssl handshake time
    std::chrono::time_point<std::chrono::system_clock> time_ssl_conn;
    bool connected = false;
    bool ssl_connected = false;

public:
    Peer(SSL_CTX* ctx);
    ~Peer();

    PacketBuffer buffer_in;
    PacketBuffer buffer_out;

    bool get_connected() { return this->connected; }
    bool get_ssl_connected() { return this->ssl_connected;}
    std::chrono::time_point<std::chrono::system_clock> get_time_conn() { return this->time_conn; }
    void set_connected();
    void set_ssl_connected();
    bool should_disconnect = false; //should disconnect
    bool should_disconnect_clean = false; //should disconnect but only when all outgoing packets are send!

    SecureSocket* get_socket() { return this->sock; }
    bool create();

    void shutdown();

    void handle_secure_connect();
    void handle_secure_accept();
    void handle_events(uint32_t evs, char* rw_buffer, int buffer_length);

    void add_event(PeerEvent ev) { this->events.push(ev); }
    PeerEvent pop_event();
    void clear_events();
};

#endif