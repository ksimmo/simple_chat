#include <iostream>
#ifdef __unix__
#include <arpa/inet.h>
#include <unistd.h> //close
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#endif

#include "logger.h"
#include "net/socket.h"

void initialize_socket()
{
    Logger& logger = Logger::instance();
#ifdef WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    logger << LogLevel::DEBUG << "Socket library initialized!" << LogEnd();
}

//constructors
Socket::Socket()
{
    this->fd = -1;
}

Socket::Socket(int fd)
{
    this->fd = fd;
}

Socket::Socket(int family, int type, int protocol)
{
    Logger& logger = Logger::instance();
    this->fd = socket(family, type, protocol);
    if(this->fd<0)
        logger << LogLevel::ERROR << "Cannot create socket: " << strerror(errno) << "(" << errno << ")!" << LogEnd();
    else
        logger << LogLevel::DEBUG << "Socket(" << this->fd << ") created successfully!" << LogEnd();
}

//desctructor
Socket::~Socket()
{
    if(this->is_valid())
        this->shutdown();
        close(this->fd);
}

bool Socket::create(int family, int type, int protocol, bool recreate)
{
    if(this->is_valid())
    {
        if(recreate)
        {
            this->shutdown();
            close(this->fd);
        }
        else
            return true;
    }
    Logger& logger = Logger::instance();
    this->fd = socket(family, type, protocol);
    bool status = true;
    if(this->fd<0)
    {
        logger << LogLevel::ERROR << "Cannot create socket: " << strerror(errno) << "(" << errno << ")!" << LogEnd();
        status = false;
    }
    else
        logger << LogLevel::DEBUG << "Socket(" << this->fd << ") created successfully!" << LogEnd();

    return status;
}

//connect socket to address (client)
StatusType Socket::connect(const std::string& host, int port)
{
    //only connect if we have a working socket
    if(!this->is_valid())
        return ST_FAIL;

    //do a adress lookup
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &(address.sin_addr));
    address.sin_port = htons(port);

    int result = ::connect(this->fd, (sockaddr*)&address, sizeof(address));
    this->address = host;
    this->port = port;

    //error handling
    StatusType status = ST_SUCCESS;
    Logger& logger = Logger::instance();
    if(result==-1)
    {
        if(errno==EINPROGRESS && !this->is_blocking())
        {
            status = ST_INPROGRESS;
            logger << LogLevel::ERROR << "Connecting socket(" << this->fd << ") to " << host << " ..." << LogEnd();
        }
        else
        {
            logger << LogLevel::ERROR << "Cannot connect (" << this->fd << ") to " << host << ": " << strerror(errno) << "(" << errno << ")!" << LogEnd();
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
    setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(int));

    int result = ::bind(this->fd, (sockaddr*)&address, sizeof(address));

    //error handling
    Logger& logger = Logger::instance();
    bool status = (result==0);
    if(!status)
        logger << LogLevel::ERROR << "Cannot bind(" << this->fd << ") to port " << port << ": " << strerror(errno) << "(" << errno << ")!" << LogEnd();
    else
    {
        this->port = port;
        logger << LogLevel::DEBUG << "Bound (" << this->fd << ") to port " << port << "!" << LogEnd();
    }

    return status;
}

//listen on socket (server)
bool Socket::listen(int queue_size)
{
    //only listen if we have a working socket
    if(!this->is_valid())
        return false;

    int result = ::listen(this->fd, queue_size);

    Logger& logger = Logger::instance();
    bool status = (result==0);
    if(!status)
        logger << LogLevel::ERROR << "Cannot listen(" << this->fd << "): " << strerror(errno) << "(" << errno << ")!" << LogEnd();
    else
        logger << LogLevel::DEBUG << "Listen on " << this->fd << "..." << LogEnd();

    return status;
}

StatusType Socket::accept(Socket* newsock)
{
    if(!this->is_valid())
        return ST_FAIL;

    struct sockaddr_in client;
    socklen_t size = sizeof(client);
    int result = ::accept(this->fd, (sockaddr*)&client, &size);

    newsock->port = ntohs(client.sin_port);
    char temp[INET_ADDRSTRLEN];
    Logger& logger = Logger::instance();
    if(inet_ntop(AF_INET, &client.sin_addr, temp, INET_ADDRSTRLEN)!=nullptr)
        newsock->address = std::string(temp);
    else
        logger << LogLevel::ERROR << "Cannot query clients ip address: " << strerror(errno) << "(" << errno << ")!" << LogEnd();

    StatusType status = ST_SUCCESS;
    if(result==-1)
    {
        if(errno==EWOULDBLOCK || errno==EAGAIN)
            status = ST_INPROGRESS;
        else
        {
            logger << LogLevel::ERROR << "Cannot accept client: " << strerror(errno) << "(" << errno << ")!" << LogEnd();
            status = ST_FAIL;
        }
    }
    else
        newsock->link(result); //let new sock handle the file descriptor

    return status;
}

//just wrap read
int Socket::read(char* buffer, int buffer_length)
{
    int result = recv(this->fd, buffer, buffer_length, 0);
    if(result==-1)
    {
        if(errno==EWOULDBLOCK || errno==EAGAIN)
            result = -2; //in progress
    }

    return result;
}

//just wrap write
int Socket::write(char*buffer, int buffer_length)
{
    int result = send(this->fd, buffer, buffer_length, 0);
    if(result==-1)
    {
        if(errno==EWOULDBLOCK || errno==EAGAIN)
            result = -2; //in progress
    }

    return result;
}

//check if socket is in blocking or non-blocking mode
bool Socket::is_blocking()
{
    if(!this->is_valid())
        return false;

    int flags = fcntl(this->fd, F_GETFL, 0);
    bool nonblocking = (flags & O_NONBLOCK); //check if non-blocking flag is set

    return !nonblocking;
}

//change socket blocking mode
bool Socket::set_blocking(bool status)
{
    if(!this->is_valid())
        return false;

    int flags = fcntl(this->fd, F_GETFL, 0); //current flags
    int result = 0;
    if ((flags & O_NONBLOCK) && status)
        //ok we have a non-blocking and want to set to blocking
        result = fcntl(this->fd, F_SETFL, flags ^ SOCK_NONBLOCK);
    else if(!(flags & O_NONBLOCK) && !status)
        //ok we have a blocking socket and want to set it to non-blocking
        result = fcntl(this->fd, F_SETFL, flags | SOCK_NONBLOCK);
    
    Logger& logger = Logger::instance();
    bool ret = (result==0);
    if(!ret)
        logger << LogLevel::ERROR << "Cannot switch socket(" << this->fd << ") behaviour: " << strerror(errno) << "(" << errno << ")!" << LogEnd();

    return ret;
}

bool Socket::shutdown(int how)
{
    if(!this->is_valid())
        return false;

    int result = ::shutdown(this->fd, how);

    Logger& logger = Logger::instance();
    bool status = (result==0);
    if(!status)
        if(errno!=ENOTCONN) //ENOTCONN is not that bad as the other side could have closed the connection
            logger << LogLevel::ERROR << "Cannot shutdown (" << this->fd << "): " << strerror(errno) << "(" << errno << ")!" << LogEnd();
    else
        logger << LogLevel::DEBUG << "Shut down (" << this->fd << ") successfully!" << LogEnd();

    return status;
}
