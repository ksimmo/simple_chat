#ifndef PEER_H
#define PEER_H

#include "net/secure_socket.h"
#include "net/packet.h"

enum PeerEvent {PE_NONE, PE_CONNECTED, PE_HANDSHAKE_FINISHED, PE_DISCONNECTED};

//class handling socket and incoming and outgoing packets
class Peer
{
private:
    SSL_CTX* ctx = nullptr;
    SecureSocket* sock = nullptr;
    std::string address = "";
    int port = -1;
    std::queue<PeerEvent> events;
    
public:
    Peer(SSL_CTX* ctx);
    ~Peer();

    PacketBuffer buffer_in;
    PacketBuffer buffer_out;
    bool is_connected = false;
    bool is_ssl_connected = false;
    bool should_disconnect = false;

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