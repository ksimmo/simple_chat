#include <iostream>
#include <unistd.h> //close
#include <errno.h>
#include <cstring>
#include <sys/epoll.h>

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
    bool status = this->sock->create();
    if(!status)
    {
        std::cerr << "[-] Cannot create socket!" << std::endl;
        return status;
    }

    status = this->sock->set_blocking(false);
    if(status)
        std::cout << "[+] Succesfully set to non-blocking mode!" << std::endl;
    else
    {
        std::cerr << "[-] Failed set to non-blocking mode!" << std::endl;
        return status;
    }

    return true;
}

void Peer::handle_secure_connect()
{
    if(this->is_connected && !this->is_ssl_connected && this->ctx!=nullptr)
    {
        StatusType st = this->sock->connect_secure();
        if(st==ST_SUCCESS)
        {
            this->is_ssl_connected = true;
            std::cout << "SSL established!" << std::endl;
            this->events.push_back(PE_CONNECTED);
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
    if(this->is_connected && !this->is_ssl_connected && this->ctx!=nullptr) //only use SSL if available
    {
        StatusType st = this->sock->accept_secure();
        if(st==ST_SUCCESS)
        {
            this->is_ssl_connected = true;
            std::cout << "SSL established!" << std::endl;
            this->events.push_back(PE_CONNECTED);
        }
        else if(st==ST_FAIL)
        {
            this->should_disconnect = true; 
        }
    }
}

void Peer::handle_events(uint32_t evs, char* rw_buffer, int buffer_length)
{
    if(this->should_disconnect)
        return;
    if(evs & EPOLLERR || evs & EPOLLHUP)
    {
        std::cerr << "[-] Client closed connection!" << std::endl;
        this->should_disconnect = true;
        return;
    }

    //we can read
    if(evs & EPOLLIN)
    {
        if((this->is_ssl_connected && this->ctx!=nullptr) ||
            (!this->is_ssl_connected && this->ctx==nullptr))
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
    if(evs & EPOLLOUT)
    {
        if(!this->is_connected)
        {
            //std::cout << "Successfully connected!" << std::endl;
            this->is_connected = true;
            //return;
        }

        if((this->is_ssl_connected && this->ctx!=nullptr) ||
            (this->is_connected && this->ctx==nullptr))
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