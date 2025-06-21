#include <iostream>
#include <unistd.h> //close
#include <errno.h>
#include <cstring>
#include <sys/epoll.h>

#include "net/connector.h"

Connector::Connector(SSL_CTX* ctx)
{
    this->ctx = ctx;
}

Connector::~Connector()
{
    this->shutdown();
}

void Connector::shutdown()
{
    if(!this->is_initialized())
        return; //nothing to do

    //disconnect clients (only server)
    for(auto p : this->connections)
        delete p.second; //delete socket
    this->connections.clear(); 

    //close main peer
    delete this->main_peer;
    this->main_peer = nullptr;

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
        delete this->incomming_packets.front();
        this->incomming_packets.pop();
    }

    while(!this->outgoing_packets.empty())
    {
        delete this->outgoing_packets.front();
        this->outgoing_packets.pop();
    }

    while(!this->events.empty())
    {
        this->events.pop();
    }
}

bool Connector::initialize(ConnectorType conn_type, std::string address,int port, int maxevents)
{
    if(this->is_initialized())
    {
        std::cout << "[+] Connector is already initialized!" << std::endl;
        return true;
    }

    this->type = conn_type;

    this->main_peer = new Peer(this->ctx);

    bool status = this->main_peer->create();
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

    if(this->type==CONN_SERVER)
    {
        //bind socket to port
        status = this->main_peer->get_socket()->bind(port);
        if(status)
            std::cout << "[+] Succesfully bound to port " << port << "!" << std::endl;
        else
        {
            std::cerr << "[-] Failed binding server to port " << port << "!" << std::endl;
            this->shutdown();
            return status;
        }

        //start listen for incomming connections
        status = this->main_peer->get_socket()->listen();
        if(status)
            std::cout << "[+] Succesfully listen!" << std::endl;
        else
        {
            std::cerr << "[-] Failed listen!" << std::endl;
            this->shutdown();
            return status;
        }
    }
    else if(this->type==CONN_CLIENT)
    {
        StatusType st = this->main_peer->get_socket()->connect(address, port);
        if(st==ST_SUCCESS)
        {
            std::cout << "[+] Succesfully connected to " << address << ":" << port << "!" << std::endl;
            status = true;
        }
        else if(st==ST_INPROGRESS)
        {
            std::cout << "[+] Connection in progress ..." << std::endl;
            status = true;
        }
        else
        {
            std::cerr << "[-] Failed connecting to " << address << ":" << port << "!" << std::endl;
            this->shutdown();
            return status;
        }
    }


    //add server listen socket to epoll
    struct epoll_event ev;
    //ERR and HUP are queried by default
    ev.events = this->type==CONN_SERVER ? EPOLLIN : EPOLLIN | EPOLLOUT; //server only needs listen
    ev.data.fd = *this->main_peer->get_socket();
    int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
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

//////////////////////////////
void Connector::accept_client()
{
    Peer* peer = new Peer(this->ctx);

    StatusType status = this->main_peer->get_socket()->accept(peer->get_socket());
    if(status==ST_SUCCESS)
    {
        bool temp = peer->get_socket()->set_blocking(false);
        if(temp)
        {
            //add client to epoll
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
            ev.data.fd = *peer->get_socket();
            int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
            if(result==-1) 
            {
                delete peer;
                std::cerr << "[-]Cannot add client to epoll: " << strerror(errno) << "(" << errno << ") !" << std::endl;
            }
            else
            {
                peer->is_connected = true;
                this->connections.insert(std::make_pair((int)*peer->get_socket(), peer)); //here we need explicit conversion to int!!!
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

void Connector::disconnect_client(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_DEL, fd, &ev);
    if(result==-1)
    {
        std::cerr << "[-]Cannot remove client from epoll!: " << strerror(errno) << "(" << errno << ") !" << std::endl;
    }

    //close connection and remove from active clients
    auto entry = this->connections.find(fd);
    delete entry->second;
    entry->second = nullptr;
}

void Connector::initiate_clean_disconnect(int fd)
{
    auto p = this->connections.find(fd);
    if(p!=this->connections.end())
        p->second->should_disconnect_clean = true;
}

ConnectorEvent Connector::pop_event()
{
    std::lock_guard<std::mutex> lock(this->mutex);
    if(this->events.empty())
    {
        ConnectorEvent temp;
        temp.fd = -1;
        temp.ev = PE_NONE;
        return temp;
    }

    ConnectorEvent ev = this->events.front();
    this->events.pop();

    return ev;
}

void Connector::add_packet(Packet* packet)
{
    std::lock_guard<std::mutex> lock(this->mutex);
    this->outgoing_packets.push(packet);
}

Packet* Connector::pop_packet()
{
    std::lock_guard<std::mutex> lock(this->mutex);
    if(this->incomming_packets.empty())
    {
        return nullptr;
    }

    Packet* packet = this->incomming_packets.front();
    this->incomming_packets.pop();

    return packet;
}

////////////////////////////////////////////////////
//main loop
void Connector::step(int timeout)
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
    else if(n_fd==0)
    {
        //std::cerr << "[-] Epoll timed out!" << std::endl;
        if(this->type==CONN_CLIENT)
            this->shutdown();
        return;
    }

    for(int i=0;i<n_fd;i++)
    {
        if(this->type==CONN_CLIENT)
        {
            this->main_peer->handle_secure_connect();
            this->main_peer->handle_events(this->epoll_evs[i].events, this->rw_buffer, RW_BUFFER_SIZE);
            if(this->main_peer->should_disconnect)
                break;
        }
        else if(this->type==CONN_SERVER)
        {
            if(this->epoll_evs[i].data.fd==*this->main_peer->get_socket()) //our listen socket
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
    }

    if(this->main_peer->should_disconnect)
    {
        this->shutdown();
        return;
    }

    //look for packages on main peer (only necessary if client)
    if(this->type==CONN_CLIENT)
    {
        PeerEvent ev = this->main_peer->pop_event();
        while(ev!=PE_NONE)
        {
            ConnectorEvent ce;
            ce.fd = *this->main_peer->get_socket();
            ce.ev = ev;
            std::lock_guard<std::mutex> lock(this->mutex);
            this->events.push(ce);
            ev = this->main_peer->pop_event();
        }

        //parse packets
        this->main_peer->buffer_in.parse_packets(*this->main_peer->get_socket()); //we could ignore fd here
        Packet* packet = this->main_peer->buffer_in.pop_packet();
        while(packet!=nullptr)
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->incomming_packets.push(packet);
            packet = this->main_peer->buffer_in.pop_packet();
        }

        std::lock_guard<std::mutex> lock(this->mutex);
        while(!this->outgoing_packets.empty())
        {
            this->main_peer->buffer_out.add_packet(this->outgoing_packets.front());
            this->outgoing_packets.pop();
        }
    }
    else if(this->type==CONN_SERVER)
    {
        //complete packages and remove clients if necessary
        for(auto it=this->connections.begin();it!=this->connections.end();)
        {
            //collect events
            PeerEvent ev = it->second->pop_event();
            while(ev!=PE_NONE)
            {
                ConnectorEvent temp;
                temp.fd = it->first;
                temp.ev = ev;
                std::lock_guard<std::mutex> lock(this->mutex); //make sure that events are also thread safe
                this->events.push(temp);
                ev = it->second->pop_event();
            }

            //TODO: what should we do if client is disconnecting? -> drop or keep packets?
            //assemble packages
            it->second->buffer_in.parse_packets(*it->second->get_socket());

            //put packet into list and forward
            Packet* packet = it->second->buffer_in.pop_packet();
            while(packet!=nullptr)
            {
                std::lock_guard<std::mutex> lock(this->mutex);
                this->incomming_packets.push(packet);
                packet = it->second->buffer_in.pop_packet();
            }


            //handle disconnects here
            if(it->second->should_disconnect)
            {
                //create disconnect event
                ConnectorEvent ce_ev;
                ce_ev.fd = it->first;
                ce_ev.ev = PE_DISCONNECTED;

                this->disconnect_client(it->first);
                it = this->connections.erase(it);

                std::lock_guard<std::mutex> lock(this->mutex);
                this->events.push(ce_ev);
            }
            else
                it++;
        }
    }

    //distribute outgoing packets
    {
        std::lock_guard<std::mutex> lock(this->mutex);
        while(!this->outgoing_packets.empty())
        {
            Packet* packet = this->outgoing_packets.front();
            if(this->connections.find(packet->get_fd())==this->connections.end())
            {
                //receiver has already disconnected does not exist? -> remove package
                delete packet;
            }
            else
            {
                this->connections[packet->get_fd()]->buffer_out.add_packet(packet);
            }
            this->outgoing_packets.pop();
        }
    }

    /*
    if(this->type==CONN_SERVER)
    {
        for(auto it=this->connections.begin();it!=this->connections.end();)
        {
            if(it->second->should_disconnect && it->second->buffer_out.num_packets()==0)
                it->second->should_disconnect = true;
        }
    }
    */
}
