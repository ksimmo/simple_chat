#ifndef SECURE_SOCKET_H
#define SECURE_SOCKET_H

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "socket.h"

void init_openssl();
void cleanup_openssl();

class SecureSocket : public Socket
{
private:
    SSL* ssl = nullptr;
    SSL_CTX* ctx = nullptr;
public:
    SecureSocket(SSL_CTX* ctx);
    SecureSocket(int socket, SSL_CTX* ctx);
    SecureSocket(int family, int type, int protocol, SSL_CTX* ctx);
    ~SecureSocket();

    SSL* get_ssl() { return this->ssl; }

    StatusType connect_secure();
    StatusType accept_secure();

    bool shutdown_secure();

    //overwrite read & write
    int read(char* buffer, int buffer_length);
    int write(char* buffer, int buffer_length);
};

#endif