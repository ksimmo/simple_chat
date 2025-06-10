#ifndef HOST_H
#define HOST_H

#include <unordered_map>

#include "net/secure_socket.h"
#include "net/packet.h"

class Peer
{
private:
    SecureSocket* sock = nullptr;
    PacketBuffer buffer_in;
    PacketBuffer buffer_out;
    
public:
    Peer(SSL_CTX* ctx);
    ~Peer();

    bool is_ssl_connected = false;
    bool should_disconnect = false;

    SecureSocket* get_socket() { return this->sock; }
    void add_to_buffer(char* buffer, int buffer_length);
    void assemble_packages();
};

class Host
{
private:
    SecureSocket* sock_listen = nullptr;
    SSL_CTX* ctx = nullptr;
    int epoll_fd = -1;
    int epoll_max_events = -1;
    struct epoll_event* epoll_evs = nullptr;

    std::unordered_map<int, Peer*> connections;
    char* rw_buffer = nullptr;

    void accept_client();
    void disconnect_client(int fd);
public:
    Host();
    ~Host();

    bool initialize(int port, int maxevents=1000, SSL_CTX* ctx=nullptr);
    bool is_initialized() {return this->sock_listen!=nullptr;}

    void handle_events(int timeout=-1); //by default server does not timeout

    void shutdown();
};

#endif