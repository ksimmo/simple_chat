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

    //delete leftover packets
    while(!this->incomming_packets.empty())
    {
        delete this->incomming_packets.front().packet;
        this->incomming_packets.pop();
    }

    while(!this->outgoing_packets.empty())
    {
        delete this->outgoing_packets.front().packet;
        this->outgoing_packets.pop();
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
                peer->is_connected = true;
                this->connections.insert(std::make_pair(peer->get_socket()->get_fd(), peer));
                peer->add_event(PE_CONNECTED);
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
    //check sockets
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
    if(n_fd==0)
    {
        //std::cerr << "[+]Epoll timed out!" << std::endl;
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
            peer->handle_secure_accept();
            peer->handle_events(this->epoll_evs[i].events, this->rw_buffer, RW_BUFFER_SIZE);

        }
    }

    //complete packages and remove clients if necessary
    for(auto it=this->connections.begin();it!=this->connections.end();)
    {
        //collect events
        PeerEvent ev = it->second->pop_event();
        while(ev!=PE_NONE)
        {
            HostEvent temp;
            temp.fd = it->first;
            temp.ev = ev;
            std::lock_guard<std::mutex> lock(this->mutex); //make sure that events are also thread safe
            this->events.push(temp);
            ev = it->second->pop_event();
        }

        //assemble packages
        it->second->buffer_in.parse_packets();

        //put packet into list and forward
        Packet* packet = it->second->buffer_in.pop_packet();
        while(packet!=nullptr)
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            HostPacket temp;
            temp.fd = it->first;
            temp.packet = packet;
            this->incomming_packets.push(temp);
            packet = it->second->buffer_in.pop_packet();
        }


        //handle disconnects here
        if(it->second->should_disconnect)
        {
            this->disconnect_client(it->first);
            it = this->connections.erase(it);
        }
        else
            it++;
    }

    //distribute outgoing packets
    std::lock_guard<std::mutex> lock(this->mutex);
    while(!this->outgoing_packets.empty())
    {
        HostPacket host_packet = this->outgoing_packets.front();
        if(this->connections.find(host_packet.fd)==this->connections.end())
        {
            //receiver has already disconnected?
            delete host_packet.packet;
        }
        else
        {
            this->connections[host_packet.fd]->buffer_out.add_packet(host_packet.packet);
        }
        this->outgoing_packets.pop();
    }
}


void Host::add_packet(int sender, Packet* packet)
{
    std::lock_guard<std::mutex> lock(this->mutex);
    HostPacket temp;
    temp.fd = sender;
    temp.packet = packet;
    this->outgoing_packets.push(temp);
}

HostPacket Host::pop_packet()
{
    std::lock_guard<std::mutex> lock(this->mutex);
    if(this->incomming_packets.empty())
    {
        HostPacket temp;
        temp.fd = -1;
        temp.packet = nullptr;
        return temp;
    }

    HostPacket packet = this->incomming_packets.front();
    this->incomming_packets.pop();

    return packet;
}