#include <iostream>
#ifdef __unix__
#include <arpa/inet.h>
#include <unistd.h> //close
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#endif

#include "net/socket.h"

//constructors
Socket::Socket()
{
    this->sock = -1;
}

Socket::Socket(int sock)
{
    this->sock = sock;
}

Socket::Socket(int family, int type, int protocol)
{
    this->sock = socket(family, type, protocol);
    if(this->sock<0)
        std::cerr << "Cannot create socket: " << strerror(errno) << "(" << errno << ") !" << std::endl;
}

//desctructor
Socket::~Socket()
{
    if(this->is_valid())
        this->shutdown();
        close(this->sock);
}

//connect socket to address (client)
StatusType Socket::connect(std::string host, int port)
{
    //only connect if we have a working socket
    if(!this->is_valid())
        return ST_FAIL;

    //do a adress lookup
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &(address.sin_addr));
    address.sin_port = htons(port);

    int result = ::connect(this->sock, (sockaddr*)&address, sizeof(address));

    //error handling
    StatusType status = ST_SUCCESS;
    if(result==-1)
    {
        if(errno==EINPROGRESS && !this->is_blocking())
        status = ST_INPROGRESS;
        else
        {
            std::cerr << "Cannot connect to " << host << ": " << strerror(errno) << "(" << errno << ") !" << std::endl;
            status = ST_FAIL; 
        }
    }   

    return status;
}

//bind socket to port (server)
bool Socket::bind(int port)
{
    //only bind if we have a working socket
    if(!this->is_valid())
        return false;

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    const int y = 1;
    setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(int));

    int result = ::bind(this->sock, (sockaddr*)&address, sizeof(address));

    //error handling
    bool status = (result==0);
    if(!status)
        std::cerr << "Cannot bind to port " << port << ": " << strerror(errno) << "(" << errno << ") !" << std::endl;

    return status;
}

//listen on socket (server)
bool Socket::listen(int queue_size)
{
    //only listen if we have a working socket
    if(!this->is_valid())
        return false;

    int result = ::listen(this->sock, queue_size);

    bool status = (result==0);
    if(!status)
        std::cerr << "Cannot listen: " << strerror(errno) << "(" << errno << ") !" << std::endl;

    return status;
}

StatusType Socket::accept(Socket* newsock)
{
    if(!this->is_valid())
        return ST_FAIL;

    struct sockaddr_in client;
    socklen_t size = sizeof(client);
    int result = ::accept(this->sock, (sockaddr*)&client, &size);

    StatusType status = ST_SUCCESS;
    if(result==-1)
    {
        if(errno==EWOULDBLOCK || errno==EAGAIN)
            status = ST_INPROGRESS;
        else
        {
            std::cerr << " Cannot accept client: " << strerror(errno) << "(" << errno << ") !" << std::endl;
            status = ST_FAIL;
        }
    }
    else
        newsock->link(result);

    return status;
}

//check if socket is in blocking or non-blocking mode
bool Socket::is_blocking()
{
    if(!this->is_valid())
        return false;

    int flags = fcntl(this->sock, F_GETFL, 0);
    bool nonblocking = (flags & O_NONBLOCK); //check if non-blocking flag is set

    return !nonblocking;
}

//change socket blocking mode
bool Socket::set_blocking(bool status)
{
    if(!this->is_valid())
        return false;

    int flags = fcntl(this->sock, F_GETFL, 0); //current flags
    int result = 0;
    if ((flags & O_NONBLOCK) && status)
        //ok we have a non-blocking and want to set to blocking
        result = fcntl(this->sock, F_SETFL, flags ^ SOCK_NONBLOCK);
    else if(!(flags & O_NONBLOCK) && !status)
        //ok we have a blocking socket and want to set it to non-blocking
        result = fcntl(this->sock, F_SETFL, flags | SOCK_NONBLOCK);
    
    bool ret = (result==0);
    if(!ret)
        std::cerr << "Cannot switch socket behaviour: " << strerror(errno) << "(" << errno << ") !" << std::endl;

    return ret;
}

bool Socket::shutdown(int how)
{
    if(!this->is_valid())
        return false;

    int result = ::shutdown(this->sock, how);

    bool status = (result==0);
    if(!status)
        std::cerr << "Cannot shutdown: " << strerror(errno) << "(" << errno << ") !" << std::endl;

    return status;
}