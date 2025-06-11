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

    this->is_connected = false; //connect will not always happen in time! we extra need to check first
    this->is_ssl_connected = false;
    this->ssl_available = (ctx!=nullptr);

    this->sock = new SecureSocket(AF_INET, SOCK_STREAM, 0, ctx);
    bool status = this->sock->is_valid();
    if(!status)
    {
        std::cerr << "[-] Cannot create socket!" << std::endl;
        this->shutdown();
        return status;
    }

    status = this->sock->set_blocking(false);
    if(status)
        std::cout << "[+] Succesfully set to non-blocking mode!" << std::endl;
    else
    {
        std::cerr << "[-] Failed set to non-blocking mode!" << std::endl;
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
    ev.data.fd = this->sock->get_fd();
    int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, this->sock->get_fd(), &ev);
    if(result==-1) 
    {
        std::cerr << "[-]Cannot create epoll ctl: " << strerror(errno) << "(" << errno << ") !" << std::endl;
        this->shutdown();
        return false;
    }

    this->epoll_evs = new epoll_event[maxevents];
    this->epoll_max_events = maxevents;

    StatusType st = this->sock->connect(host, port);
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
    delete this->sock;
    this->sock = nullptr;

    if(this->epoll_fd>=0)
        close(this->epoll_fd);

    if(this->epoll_evs!=nullptr)
    {
        delete[] this->epoll_evs;
        this->epoll_evs = nullptr;
    }
    this->epoll_max_events = -1;

    this->is_connected = false;
    this->is_ssl_connected = false;

    delete[] this->rw_buffer;
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
        if(this->epoll_evs[i].events & EPOLLERR || this->epoll_evs[i].events & EPOLLHUP)
        {
            std::cerr << "[-] Server closed connection!" << std::endl;
            this->shutdown();
            return;
        }

        if(this->is_connected && !this->is_ssl_connected && this->ssl_available)
        {
            StatusType st = this->sock->connect_secure();
            if(st==ST_SUCCESS)
            {
                this->is_ssl_connected = true;
                std::cout << "SSL connected!" << std::endl;
            }
            else if(st==ST_FAIL)
            {
                this->shutdown();
                return;
            }
        }

        if (this->epoll_evs[i].events & EPOLLOUT)
        {
            if(!this->is_connected)
            {
                std::cout << "Successfully connected!" << std::endl;
                this->is_connected = true;
                continue;
            }

            //ok we can send again
        }
        if(this->epoll_evs[i].events & EPOLLIN)
        {
            //is there data to receive?
            if(this->is_ssl_connected && this->ssl_available || this->is_connected && !this->ssl_available)
            {
                //read
                int result = this->sock->read(this->rw_buffer, RW_BUFFER_SIZE);
                if(result<=0)
                {
                    if(result==-1)
                    {
                        this->shutdown();
                        std::cerr << "[-]Read error!" << std::endl;
                    }
                    continue;
                    
                }
                else if(result==0)
                {
                    this->shutdown();
                    std::cerr << "[-] Server disconnected" << std::endl;
                }
                else
                {
                    this->buffer_in.append(this->rw_buffer, result);
                }
            }
        }
    }

    //parse packets
    
}
