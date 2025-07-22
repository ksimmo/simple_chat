#include <iostream>
#include <unistd.h> //close
#include <errno.h>
#include <cstring>
#include <sys/epoll.h>

#include "logger.h"
#include "net/connector.h"

Connector::Connector(SSL_CTX* ctx) : established(false)
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

    this->established = false;

    //disconnect clients (only server)
    for(auto p : this->connections)
        delete p.second; //delete socket
    this->connections.clear(); 

    //close main peer
    delete this->main_peer;
    this->main_peer = nullptr;

#ifdef USE_EPOLL
    if(this->epoll_fd>=0)
        close(this->epoll_fd);

    if(this->epoll_evs!=nullptr)
    {
        delete[] this->epoll_evs;
        this->epoll_evs = nullptr;
    }
    this->epoll_max_events = -1;
#elif USE_KQUEUE
    if(this->kq_fd>=0)
        close(this->kq_fd);

    if(this->kq_evs!=nullptr)
    {
        delete[] this->kq_evs;
        this->kq_evs = nullptr;
    }
    this->kq_max_events = -1;
#endif

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
    //ok on the client side we still need to add the disconnect event to process
    if(this->type==CONN_CLIENT)
    {
        std::lock_guard<std::mutex> lock(this->mutex);
        ConnectorEvent temp;
        temp.fd = -1;
        temp.ev = PE_DISCONNECTED;
        this->events.push(temp);
    }
}

bool Connector::initialize(ConnectorType conn_type, const std::string& address,int port, int maxevents)
{
    Logger& logger = Logger::instance();
    if(this->is_initialized())
    {
        logger << LogLevel::DEBUG << "Connector is already initialized!" << LogEnd();
        return true;
    }

    this->type = conn_type;
    this->established = false;

    this->main_peer = new Peer(this->ctx);

    bool status = this->main_peer->create();
    if(!status)
    {
        this->shutdown();
        return status;
    }

#ifdef USE_EPOLL
    //create epoll
    this->epoll_fd = epoll_create1(0);
    if(this->epoll_fd==-1)
    {
        logger << LogLevel::ERROR << "Cannot create epoll: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
        this->shutdown();
        return false;
    }
#elif USE_KQUEUE
    //create kqueue
    this->kq_fd = kqueue();
    if(this->kq_fd==-1)
    {
        logger << LogLevel::ERROR << "[-]Cannot create kqueue: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
        this->shutdown();
        return false;
    }
#endif

    if(this->type==CONN_SERVER)
    {
        //bind socket to port
        status = this->main_peer->get_socket()->bind(port);
        if(status)
            logger << LogLevel::DEBUG << "Succesfully bound to port " << port << "!" << LogEnd();
        else
        {
            logger << LogLevel::ERROR << "Failed binding server to port " << port << "!" << LogEnd();
            this->shutdown();
            return status;
        }

        //start listen for incomming connections
        status = this->main_peer->get_socket()->listen();
        if(status)
            logger << LogLevel::DEBUG << "Succesfully listen!" << LogEnd();
        else
        {
            logger << LogLevel::ERROR << "Failed listen!" << LogEnd();
            this->shutdown();
            return status;
        }
    }
    else if(this->type==CONN_CLIENT)
    {
        StatusType st = this->main_peer->get_socket()->connect(address, port);
        if(st==ST_SUCCESS)
        {
            logger << LogLevel::INFO << "Succesfully connected to " << address << ":" << port << "!" << LogEnd();
            status = true;
        }
        else if(st==ST_INPROGRESS)
        {
            logger << LogLevel::DEBUG << "Connection in progress ..." << LogEnd();
            status = true;
        }
        else
        {
            logger << LogLevel::ERROR << "Failed connecting to " << address << ":" << port << "!" << LogEnd();
            this->shutdown();
            return status;
        }
    }


    //add server listen socket to epoll
#ifdef USE_EPOLL
    struct epoll_event ev;
    //ERR and HUP are queried by default
    ev.events = this->type==CONN_SERVER ? EPOLLIN : EPOLLIN | EPOLLOUT; //server only needs listen
    ev.data.fd = *this->main_peer->get_socket();
    int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
    if(result==-1) 
    {
        logger << LogLevel::ERROR << "Cannot create epoll ctl: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
        this->shutdown();
        return false;
    }

    this->epoll_evs = new epoll_event[maxevents];
    this->epoll_max_events = maxevents;
#elif USE_KQUEUE
    struct kevent ev;
    EV_SET(&ev, this->main_peer->get_socket(), EVFILT_READ, EV_ADD, 0, 0, nullptr);
    if (kevent(kq, &ev, 1, nullptr, 0, nullptr) == -1) {
        logger << LogLevel::ERROR << "[-]Cannot register kqeueue: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
        this->shutdown();
        return false;
    }
    this->kq_evs = new kevent[maxevents];
    this->kq_max_events = maxevents;
#endif

    this->rw_buffer =  new char[RW_BUFFER_SIZE];

    this->established = status;

    return status;
}

//////////////////////////////
void Connector::accept_client()
{
    Logger& logger = Logger::instance();
    Peer* peer = new Peer(this->ctx);

    StatusType status = this->main_peer->get_socket()->accept(peer->get_socket());
    if(status==ST_SUCCESS)
    {
        bool temp = peer->get_socket()->set_blocking(false);
        if(temp)
        {
#ifdef USE_EPOLL
            //add client to epoll
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
            ev.data.fd = *peer->get_socket();
            int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
            if(result==-1) 
            {
                delete peer;
                logger << LogLevel::ERROR << "Cannot add client to epoll: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
                return;
            }
#elif USE_KQUEUE
            //add to reading queue
            struct kevent ev;
            EV_SET(&ev, *peer->get_socket(), EVFILT_READ, EV_ADD, 0, 0, nullptr);
            if (kevent(kq, &ev, 1, nullptr, 0, nullptr) == -1) {
                logger << LogLevel::ERROR << "[-]Cannot add client to kqueue: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
                delete peer;
                return;
            }

            //add to writing queue
            struct kevent ev2;
            EV_SET(&ev2, *peer->get_socket(), EVFILT_WRITE, EV_ADD, 0, 0, nullptr);
            if (kevent(kq, &ev, 1, nullptr, 0, nullptr) == -1) {
                logger << LogLevel::ERROR << "[-]Cannot add client to kqueue: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
                delete peer;
                return;
            }
#endif
            peer->set_connected(); //true
            logger << LogLevel::INFO << "Client (" << (int)*peer->get_socket() << ") connected from " << peer->get_socket()->get_address() << "!" << LogEnd();
            this->connections.insert(std::make_pair((int)*peer->get_socket(), peer)); //here we need explicit conversion to int!!!
            peer->add_event(PE_CONNECTED);
        }
        else
        {
            delete peer;
        }
    }
    else
    {
        logger << LogLevel::ERROR << "Cannot accept client: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
        delete peer;
    }
}

void Connector::disconnect_client(int fd)
{
    Logger& logger = Logger::instance();
#ifdef USE_EPOLL
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    int result = epoll_ctl(this->epoll_fd, EPOLL_CTL_DEL, fd, &ev);
    if(result==-1)
    {
        logger << LogLevel::ERROR << "Cannot remove client from epoll!: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
    }
#elif USE_KQUEUE
    //remove read notifier
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    if (kevent(kq, &ev, 1, nullptr, 0, nullptr) == -1) {
        std::cerr << "[-]Cannot register kqeueue: " << strerror(errno) << "(" << errno << ") !" << std::endl;
        this->shutdown();
        return false;
    }

    //remove write notifier
    struct kevent ev2;
    EV_SET(&ev2, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    if (kevent(kq, &ev2, 1, nullptr, 0, nullptr) == -1) {
        std::cerr << "[-]Cannot register kqeueue: " << strerror(errno) << "(" << errno << ") !" << std::endl;
        this->shutdown();
        return false;
    }
#endif

    //close connection and remove from active clients
    auto entry = this->connections.find(fd);
    delete entry->second;
    entry->second = nullptr;
}

void Connector::initiate_clean_disconnect(int fd)
{
    std::lock_guard<std::mutex> lock(this->mutex);
    auto p = this->connections.find(fd);
    if(p!=this->connections.end())
        p->second->should_disconnect_clean = true;
}


void Connector::add_event(int fd, PeerEvent ev)
{
    std::lock_guard<std::mutex> lock(this->mutex);
    ConnectorEvent ce_ev;
    ce_ev.fd = fd;
    ce_ev.ev = ev;
    this->events.push(ce_ev);
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
    Logger& logger = Logger::instance();
    if(!this->is_initialized())
        return;
#ifdef USE_EPOLL
    //check sockets
    int n_fd = epoll_wait(this->epoll_fd, this->epoll_evs, this->epoll_max_events, timeout);
    if(n_fd==-1)
    {
        if(errno!=EINTR)
        {
            logger << LogLevel::ERROR << "Cannot wait for epoll: " << strerror(errno) << "(" << errno << ")!" << LogEnd();
            this->shutdown();
            return;
        }
    }
    else if(n_fd==0)
    {
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
#elif USE_KQUEUE
    //TODO: set timeout
    struct timespec *timeout = nullptr;
    int n_fd = kevent(this->kq_fd, nullptr, 0, this->kq_evs, this->kq_max_events, timeout);
    if(n_fd==-1)
    {
        if(errno!=EINTR)
        {
            logger << LogLevel::ERROR << "Cannot wait for kqueue: " << strerror(errno) << "(" << errno << ") !" << LogEnd();
            this->shutdown();
            return;
        }
    }
    else if(n_fd==0)
    {
        //std::cerr << "[-] Kqeue timed out!" << std::endl;
        if(this->type==CONN_CLIENT)
            this->shutdown();
        return;
    }

    for(int i=0;i<n_fd;i++)
    {
        if(this->type==CONN_CLIENT)
        {
            this->main_peer->handle_secure_connect();
            this->main_peer->handle_events(this->kq_evs[i].filter, this->kq_evs[i].flags, this->rw_buffer, RW_BUFFER_SIZE);
            if(this->main_peer->should_disconnect)
                break;
        }
        else if(this->type==CONN_SERVER)
        {
            if(this->kq_evs[i].ident==*this->main_peer->get_socket()) //our listen socket
            {
                if(this->kq_evs[i].filter==EVFILT_READ)
                    this->accept_client();
            }
            else //all other clients
            {
                //get peer
                Peer* peer = this->connections[this->kq_evs[i].ident];
                peer->handle_secure_accept();
                peer->handle_events(this->kq_evs[i].filter, this->kq_evs[i].flags, this->rw_buffer, RW_BUFFER_SIZE);

            }
        }
    }
#endif

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
        auto now = std::chrono::system_clock::now();
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

            //check if clients ssl handshake idles too long
            if(!it->second->get_ssl_connected())
            {
                int64_t difference = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second->get_time_conn()).count();
                if(difference>=5000)
                {
                    logger << LogLevel::INFO << "" << it->first << "'s ssl handshake took too long!" << LogEnd();
                    it->second->should_disconnect = true;
                }
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

    if(this->type==CONN_SERVER)
    {
        //check if we should cleanly disconnect a client
        for(auto it=this->connections.begin();it!=this->connections.end();it++)
        {
            if(it->second->should_disconnect_clean && it->second->buffer_out.num_packets()==0)
                it->second->should_disconnect = true;
        }
    }
}
