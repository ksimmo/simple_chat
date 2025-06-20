#ifndef SOCKET_H
#define SOCKET_H

#include<string>

#ifdef _WIN32 //we are on windows
#include <winsock2.h>
#elif __unix__ //we are on unix systems
#include <sys/socket.h>
#endif

#define RW_BUFFER_SIZE 16*1024 //do not make packages too large

enum StatusType {ST_FAIL=-1, ST_INPROGRESS=0, ST_SUCCESS=1}; //we mainly need this due to asynchronous calls may not finish in time

//wrapper class for basic socket operations
class Socket
{
private:
    //int fd = -1;
    std::string address;
    int port = -1;
protected:
    int fd = -1;
public:
    Socket();
    Socket(int fd); //create a socket from a socket descriptor
    Socket(int family, int type, int protocol);
    ~Socket();

    //operators
    operator int() { return this->fd; }

    bool is_valid() { return this->fd>=0; } //check if we have a valid socket
    int get_port() { return this->port; }
    const char* get_address() { return this->address.c_str(); }

    void link(int fd) { this->fd = fd; }
    void unlink() { this->fd = -1; } //careful when using this -> prevent closing of socket upon delete
    bool create(int family=AF_INET, int type=SOCK_STREAM, int protocol=0, bool recreate=false);

    bool is_blocking();
    bool set_blocking(bool status);

    StatusType connect(std::string host, int port); //connect to an adress (client)
    bool bind(int port);
    bool listen(int queue_size=SOMAXCONN);
    StatusType accept(Socket* newsock);
    int read(char* buffer, int buffer_length);
    int write(char* buffer, int buffer_length);

    bool shutdown(int how=SHUT_RDWR);
};

#endif