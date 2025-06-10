#include <iostream>
#include <unistd.h> //close
#include <errno.h>
#include <cstring>
#include <sys/epoll.h>

#include "net/host.h"


Peer::Peer(SSL_CTX* ctx)
{
    this->sock = new SecureSocket(ctx);
}

Peer::~Peer()
{
    if(this->sock!=nullptr)
        delete this->sock;
}

void Peer::add_to_buffer(char* buffer, int buffer_length)
{
    this->buffer_in.append(buffer, buffer_length);
}

void Peer::assemble_packages()
{
    
}

////////////////////////////////////////////////////////

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

    this->rw_buffer =  new char[RW_BUFFER_SIZE];

    return status;
}


void Host::shutdown()
{
    if(!this->is_initialized())
        return; //nothing to do

    //disconnect clients
    for(auto p : this->connections)
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

    if(this->rw_buffer!=nullptr)
    {
        delete[] this->rw_buffer;
        this->rw_buffer = nullptr;
    }

}

//////////////////////////////
void Host::accept_client()
{
    Peer* peer = new Peer(this->ctx);
    StatusType status = this->sock_listen->accept(peer->get_socket());
    if(status==ST_SUCCESS)
    {
        bool temp = peer->get_socket()->set_blocking(false);
        if(temp)
        {
            //add client to epoll
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
            ev.data.fd = peer->get_socket()->get_fd();
            int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
            if(result==-1) 
            {
                delete peer;
                std::cerr << "[-]Cannot add client to epoll: " << strerror(errno) << "(" << errno << ") !" << std::endl;
            }
            else
            {
                std::cout << "New client connected!" << std::endl;
                this->connections.insert(std::make_pair(peer->get_socket()->get_fd(), peer));
            }
        }
        else
        {
            delete peer;
        }
    }
    else
    {
        std::cerr << "[-]Cannot accept client: " << strerror(errno) << "(" << errno << ") !" << std::endl;
        delete peer;
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
    auto entry = this->connections.find(fd);
    delete entry->second;
    entry->second = nullptr;
    std::cout << "Client disconnected" << std::endl;
}

void Host::handle_events(int timeout)
{
    int n_fd = epoll_wait(this->epoll_fd, this->epoll_evs, this->epoll_max_events, timeout);
    if(n_fd==-1)
    {
        if(n_fd!=EINTR)
        {
            std::cerr << "[-]Cannot wait for epoll: " << strerror(errno) << "(" << errno << ") !" << std::endl;
            this->shutdown();
            return;
        }
    }
    if(n_fd==0)
    {
        std::cerr << "[+]Epoll timed out!" << std::endl;
        return;
    }
    for(int i=0;i<n_fd;i++)
    {
        if(this->epoll_evs[i].data.fd==this->sock_listen->get_fd()) //our listen socket
        {
            if(this->epoll_evs[i].events & EPOLLIN)
                this->accept_client();
        }
        else //all other clients
        {
            //get peer
            Peer* peer = this->connections[this->epoll_evs[i].data.fd];
            if(peer->should_disconnect)
                continue;
            if(this->epoll_evs[i].events & EPOLLERR || this->epoll_evs[i].events & EPOLLHUP)
            {
                std::cerr << "[-] Client closed connection!" << std::endl;
                peer->should_disconnect = true;
                continue;
            }

            //ok first check if ssl is established
            if(!peer->is_ssl_connected && this->ctx!=nullptr) //only use SSL if available
            {
                StatusType st = peer->get_socket()->accept_secure();
                if(st==ST_SUCCESS)
                {
                    peer->is_ssl_connected = true;
                    std::cout << "SSL established!" << std::endl;
                }
                else if(st==ST_FAIL)
                {
                    peer->should_disconnect = true; 
                    continue;
                }
            }

            if(this->epoll_evs[i].events & EPOLLIN)
            {
                if((peer->is_ssl_connected && this->ctx!=nullptr) ||
                    (!peer->is_ssl_connected && this->ctx==nullptr))
                {
                    //read
                    int result = peer->get_socket()->read(this->rw_buffer, RW_BUFFER_SIZE);
                    if(result<0)
                    {
                        if(result==-1)
                        {
                            peer->should_disconnect = true;
                            std::cerr << "[-]Read error!" << std::endl;
                        }
                        continue;
                    }
                    else if(result==0)
                    {
                        peer->should_disconnect = true;
                    }
                    else
                    {
                        peer->add_to_buffer(this->rw_buffer, result);
                    }
                }
            }
            if(this->epoll_evs[i].events & EPOLLOUT)
            {
                if((peer->is_ssl_connected && this->ctx!=nullptr) ||
                    (!peer->is_ssl_connected && this->ctx==nullptr))
                {
                    //write
                }
            }


        }
    }

    for(auto it=this->connections.begin();it!=this->connections.end();)
    {
        //assemble packages
        it->second->assemble_packages();

        //handle disconnects here
        if(it->second->should_disconnect)
        {
            this->disconnect_client(it->first);
            it = this->connections.erase(it);
        }
        else
            it++;
    }
}