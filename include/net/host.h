#ifndef HOST_H
#define HOST_H

#include <unordered_map>

#include "net/secure_socket.h"

class Host
{
private:
    SecureSocket* sock_listen = nullptr;
    SSL_CTX* ctx = nullptr;
    int epoll_fd = -1;
    int epoll_max_events = -1;
    struct epoll_event* epoll_evs = nullptr;

    std::unordered_map<int, SecureSocket*> connections;

    void accept_client();
    void disconnect_client(int fd);
public:
    Host();
    ~Host();

    bool initialize(int port, int maxevents=1000, SSL_CTX* ctx=nullptr);
    bool is_initialized() {return this->sock_listen!=nullptr;}

    void handle_events();

    void shutdown();
};

#endif