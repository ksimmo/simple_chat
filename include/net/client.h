#ifndef CLIENT_H
#define CLIENT_H

#include "net/secure_socket.h"

class Client
{
private:
    SecureSocket* sock = nullptr;
    int epoll_fd = -1;
    int epoll_max_events = -1;
    struct epoll_event* epoll_evs = nullptr;

    bool is_connected = false;
    bool is_ssl_connected = false;
    
public:
    Client();
    ~Client();

    bool initialize(std::string, int port, int maxevents=100, SSL_CTX* ctx=nullptr);
    bool is_initialized() {return this->sock!=nullptr;}

    void shutdown();

    void handle_events();
};

#endif