#include <iostream>
#include <unistd.h> //close
#include <errno.h>
#include <cstring>
#include <sys/epoll.h>
#include "net/client.h"

Client::Client()
{
}

Client::~Client()
{
    this->shutdown();
}

bool Client::initialize(std::string host, int port, int maxevents, SSL_CTX* ctx)
{
    if(this->is_initialized())
    {
        std::cout << "[+] Client is already initialized!" << std::endl;
        return true;
    }

    this->peer = new Peer(ctx);
    bool status = this->peer->create();
    if(!status)
    {
        this->shutdown();
        return status;
    }

    //create epoll
    this->epoll_fd = epoll_create1(0);
    if(this->epoll_fd==-1)
    {
        std::cerr << "[-]Cannot create epoll: " << strerror(errno) << "(" << errno << ") !" << std::endl;
        this->shutdown();
        return false;
    }

    //add client socket to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP; //technically ERR and HUP are queried by default
    ev.data.fd = this->peer->get_socket()->get_fd();
    int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
    if(result==-1) 
    {
        std::cerr << "[-]Cannot create epoll ctl: " << strerror(errno) << "(" << errno << ") !" << std::endl;
        this->shutdown();
        return false;
    }

    this->epoll_evs = new epoll_event[maxevents];
    this->epoll_max_events = maxevents;

    StatusType st = this->peer->get_socket()->connect(host, port);
    if(st==ST_SUCCESS)
    {
        std::cout << "[+] Succesfully bound to " << host << ":" << port << "!" << std::endl;
        status = true;
    }
    else if(st==ST_INPROGRESS)
    {
        std::cout << "[+] Connection in progress ..." << std::endl;
        status = true;
    }
    else
    {
        std::cerr << "[-] Failed connecting to " << host << ":" << port << "!" << std::endl;
        this->shutdown();
        return status;
    }

    this->rw_buffer = new char[RW_BUFFER_SIZE];

    return status;
}


void Client::shutdown()
{
    if(!this->is_initialized())
        return; //nothing to do

    //shutdown client socket
    delete this->peer;
    this->peer = nullptr;

    if(this->epoll_fd>=0)
        close(this->epoll_fd);

    if(this->epoll_evs!=nullptr)
    {
        delete[] this->epoll_evs;
        this->epoll_evs = nullptr;
    }
    this->epoll_max_events = -1;

    if(this->rw_buffer!=nullptr)
    {
        delete[] this->rw_buffer;
        this->rw_buffer = nullptr;
    }
}

///////////////////////////////////////////////////
void Client::handle_events(int timeout)
{
    int n_fd = epoll_wait(this->epoll_fd, this->epoll_evs, this->epoll_max_events, timeout);
    if(n_fd==-1)
    {
        if(errno!=EINTR)
        {
            std::cerr << "[-]Cannot wait for epoll: " << strerror(errno) << "(" << errno << ") !" << std::endl;
            this->shutdown();
            return;
        }
    }
    else if(n_fd==0)
    {
        std::cerr << "[-] Epoll timed out!" << std::endl;
        this->shutdown();
        return;
    }

    for(int i=0;i<n_fd;i++)
    {
        this->peer->handle_secure_connect();
        this->peer->handle_events(this->epoll_evs[i].events, this->rw_buffer, RW_BUFFER_SIZE);
        if(this->peer->should_disconnect)
            break;
    }

    if(this->peer->should_disconnect)
    {
        this->shutdown();
        return;
    }

    //parse packets
    this->peer->buffer_in.parse_packets();
    
}
