#include <iostream>
#include <unistd.h> //close
#include <errno.h>
#include <cstring>
#include <sys/epoll.h>

#include "net/connector.h"

Connector::~Connector()
{
    this->shutdown();
}

void Connector::shutdown()
{
    if(!this->is_initialized())
        return; //nothing to do

    //close main socket
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