#include <iostream>
#include <unistd.h> //close
#include <errno.h>
#include <cstring>
#include <sys/epoll.h>
#include "net/host.h"

Host::Host()
{
}

Host::~Host()
{
    this->shutdown();
}

bool Host::initialize(int port, int maxevents, SSL_CTX* ctx)
{
    if(this->is_initialized())
    {
        std::cout << "[+] Server is already initialized!" << std::endl;
        return true;
    }

    this->ctx = ctx;
    this->sock_listen = new SecureSocket(AF_INET, SOCK_STREAM, 0, ctx);
    bool status = this->sock_listen->is_valid();
    if(!status)
    {
        std::cerr << "[-] Cannot create socket!" << std::endl;
        this->shutdown();
        return status;
    }

    status = this->sock_listen->set_blocking(false);
    if(status)
        std::cout << "[+] Succesfully set to non-blocking mode!" << std::endl;
    else
    {
        std::cerr << "[-] Failed set to non-blocking mode!" << std::endl;
        this->shutdown();
        return status;
    }

    status = this->sock_listen->bind(port);
    if(status)
        std::cout << "[+] Succesfully bound to port " << port << "!" << std::endl;
    else
    {
        std::cerr << "[-] Failed binding server to port " << port << "!" << std::endl;
        this->shutdown();
        return status;
    }

    status = this->sock_listen->listen();
    if(status)
        std::cout << "[+] Succesfully listen!" << std::endl;
    else
    {
        std::cerr << "[-] Failed listen!" << std::endl;
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

    //add server listen socket to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = this->sock_listen->get_fd();
    int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, this->sock_listen->get_fd(), &ev);
    if(result==-1) 
    {
        std::cerr << "[-]Cannot create epoll ctl: " << strerror(errno) << "(" << errno << ") !" << std::endl;
        this->shutdown();
        return false;
    }

    this->epoll_evs = new epoll_event[maxevents];
    this->epoll_max_events = maxevents;

    return status;
}


void Host::shutdown()
{
    if(!this->is_initialized())
        return; //nothing to do

    //disconnect clients
    for(const auto &p:this->connections)
        delete p.second; //delete socket
    this->connections.clear(); 

    //shutdown server socket
    delete this->sock_listen;
    this->sock_listen = nullptr;

    if(this->epoll_fd>=0)
        close(this->epoll_fd);

    if(this->epoll_evs!=nullptr)
    {
        delete[] this->epoll_evs;
        this->epoll_evs = nullptr;
    }
    this->epoll_max_events = -1;
}

//////////////////////////////
void Host::accept_client()
{
    SecureSocket* client = new SecureSocket(this->ctx);
    StatusType status = this->sock_listen->accept(client);
    if(status==ST_SUCCESS)
    {
        bool temp = client->set_blocking(false);
        if(temp)
        {
            //add client to epoll
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
            ev.data.fd = client->get_fd();
            int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, client->get_fd(), &ev);
            if(result==-1) 
            {
                delete client;
                std::cerr << "[-]Cannot add client to epoll: " << strerror(errno) << "(" << errno << ") !" << std::endl;
            }
            else
            {
                std::cout << "Client connected!" << std::endl;
                this->connections.insert(std::make_pair(client->get_fd(), client));
            }
        }
    }
    else
    {
        std::cerr << "[-]Cannot accept client: " << strerror(errno) << "(" << errno << ") !" << std::endl;
        delete client;
    }
}

void Host::disconnect_client(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd; //this->connections[fd]->get_fd();
    int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_DEL, fd, &ev);
    if(result==-1)
    {
        std::cerr << "[-]Cannot remove client from epoll!: " << strerror(errno) << "(" << errno << ") !" << std::endl;
    }

    //close connection and remove from active clients
    delete this->connections[fd];
    this->connections.erase(fd);
    std::cout << "Client disconnected" << std::endl;
}

void Host::handle_events()
{
    int n_fd = epoll_wait(this->epoll_fd, this->epoll_evs, this->epoll_max_events, -1);
    if(n_fd==-1)
    {
        if(n_fd!=EINTR)
        {
            std::cerr << "[-]Cannot wait for epoll: " << strerror(errno) << "(" << errno << ") !" << std::endl;
            return;
        }
    }
    for(int i=0;i<n_fd;i++)
    {
        if(this->epoll_evs[i].data.fd==this->sock_listen->get_fd() && this->epoll_evs[i].events & EPOLLIN)
        {
            //accept new client
            this->accept_client();
            
        }
        else if(this->epoll_evs[i].events==EPOLLIN)
        {
            //handle client data

            //if read fails = 0 -> client is disconnected, -1 also disconnect client
        }
        else if(this->epoll_evs[i].events==EPOLLOUT)
        {
            //write out to client
        }
    }
}