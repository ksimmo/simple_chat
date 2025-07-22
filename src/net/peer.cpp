#include <unistd.h> //close
#include <errno.h>
#include <cstring>
#include <sys/epoll.h>

#include "logger.h"
#include "net/peer.h"

Peer::Peer(SSL_CTX* ctx)
{
    this->ctx = ctx;
    this->sock = new SecureSocket(this->ctx);
}

Peer::~Peer()
{
    this->shutdown();
}

void Peer::shutdown()
{
    if(this->sock!=nullptr)
        delete this->sock;

    this->address = "";
    this->port = -1;
}

bool Peer::create()
{
    Logger& logger = Logger::instance();
    bool status = this->sock->create();
    if(!status)
        return status;

    status = this->sock->set_blocking(false);
    if(status)
        logger << LogLevel::DEBUG << "Succesfully set to non-blocking mode!" << LogEnd();
    else
        return status;

    this->connected = false;
    this->ssl_connected = false;

    return true;
}

void Peer::set_connected()
{
    this->connected = true;
    this->time_conn = std::chrono::system_clock::now();
}

void Peer::set_ssl_connected()
{
    this->ssl_connected = true;
    this->time_ssl_conn = std::chrono::system_clock::now();
}

void Peer::handle_secure_connect()
{
    if(this->connected && !this->ssl_connected && this->ctx!=nullptr)
    {
        StatusType st = this->sock->connect_secure();
        if(st==ST_SUCCESS)
        {
            this->set_ssl_connected(); //true
            this->events.push(PE_HANDSHAKE_FINISHED);
        }
        else if(st==ST_FAIL)
        {
            this->should_disconnect = true;
        }
    }
}

void Peer::handle_secure_accept()
{
    //ok first check if ssl is established
    if(this->connected && !this->ssl_connected && this->ctx!=nullptr) //only use SSL if available
    {
        StatusType st = this->sock->accept_secure();
        if(st==ST_SUCCESS)
        {
            this->set_ssl_connected(); //true
            this->events.push(PE_HANDSHAKE_FINISHED);
        }
        else if(st==ST_FAIL)
        {
            this->should_disconnect = true; 
        }
    }
}

#ifdef USE_EPOLL
void Peer::handle_events(uint32_t evs, char* rw_buffer, int buffer_length)
{
    Logger& logger = Logger::instance();
    if(this->should_disconnect)
        return;
    
    if(evs & EPOLLERR || evs & EPOLLHUP)
    {
        logger << LogLevel::INFO << "Client(" << (int)*this->sock << ") closed connection!" << LogEnd();
        this->should_disconnect = true;
        return;
    }

    //we can read
    if(evs & EPOLLIN && !this->should_disconnect_clean) //only read if we should not disconnect
    {
        if((this->ssl_connected && this->ctx!=nullptr) ||
            (!this->ssl_connected && this->ctx==nullptr))
        {
            //read
            int result = this->get_socket()->read(rw_buffer, buffer_length);
            if(result<0)
            {
                if(result==-1)
                {
                    this->should_disconnect = true;
                    logger << LogLevel::ERROR << "Read error on (" << (int)*this->sock << ")!" << LogEnd();
                }
                return;
            }
            else if(result==0)
            {
                this->should_disconnect = true;
            }
            else
            {
                this->buffer_in.append(rw_buffer, result);
            }
        }
    }

    //ok we can write
    if(evs & EPOLLOUT)
    {
        if(!this->connected)
        {
            this->set_connected();
            this->events.push(PE_CONNECTED);
            //return;
        }

        if((this->ssl_connected && this->ctx!=nullptr) ||
            (this->connected && this->ctx==nullptr))
        {
            //write
            int result = this->buffer_out.write_packets(rw_buffer, buffer_length);
            if(result>0)
            {
                result = this->sock->write(rw_buffer, result);
                if(result<0)
                {
                    if(result==-1)
                    {
                        this->should_disconnect = true;
                        logger << LogLevel::ERROR << "Write error on (" << (int)*this->sock << ")!" << LogEnd();
                    }
                    return;
                }
            }
        }
    }
}
#elif USE_KQUEUE
void Peer::handle_events(ushort evs, u_short flags, char* rw_buffer, int buffer_length)
{
    if(this->should_disconnect)
        return;
    
    //we need to check the flags
    if(flags & EV_ERROR)
    {
        std::cerr << "[-]Client closed connection!" << std::endl;
        this->should_disconnect = true;
        return;
    }

    //we can read
    if(evs==EVFILT_READ && !this->should_disconnect_clean) //only read if we should not disconnect
    {
        if((this->ssl_connected && this->ctx!=nullptr) ||
            (!this->ssl_connected && this->ctx==nullptr))
        {
            //read
            int result = this->get_socket()->read(rw_buffer, buffer_length);
            if(result<0)
            {
                if(result==-1)
                {
                    this->should_disconnect = true;
                    std::cerr << "[-]Read error!" << std::endl;
                }
                return;
            }
            else if(result==0)
            {
                this->should_disconnect = true;
            }
            else
            {
                this->buffer_in.append(rw_buffer, result);
            }
        }
    }

    //ok we can write
    if(evs==EVFILT_WRITE)
    {
        if(!this->connected)
        {
            //std::cout << "Successfully connected!" << std::endl;
            this->set_connected();
            this->events.push(PE_CONNECTED);
            //return;
        }

        if((this->ssl_connected && this->ctx!=nullptr) ||
            (this->connected && this->ctx==nullptr))
        {
            //write
            int result = this->buffer_out.write_packets(rw_buffer, buffer_length);
            if(result>0)
            {
                result = this->sock->write(rw_buffer, result);
                if(result<0)
                {
                    if(result==-1)
                    {
                        this->should_disconnect = true;
                        std::cerr << "[-]Write error!" << std::endl;
                    }
                    return;
                }
            }
        }
    }
}
#endif

PeerEvent Peer::pop_event()
{
    PeerEvent ev = PE_NONE;
    if(!this->events.empty())
    {
        ev = this->events.front();
        this->events.pop();
    }

    return ev;
}

void Peer::clear_events()
{
    while(!this->events.empty())
    {
        this->events.pop();
    }
}