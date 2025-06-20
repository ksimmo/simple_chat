#ifndef SECURE_SOCKET_H
#define SECURE_SOCKET_H

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "socket.h"

SSL_CTX* init_openssl(bool is_client=true, const std::string& cert=std::string(), const std::string& key=std::string());
void cleanup_openssl(SSL_CTX* ctx);

class SecureSocket : public Socket
{
private:
    SSL* ssl = nullptr;
    SSL_CTX* ctx = nullptr;
public:
    SecureSocket(SSL_CTX* ctx);
    SecureSocket(int fd, SSL_CTX* ctx);
    SecureSocket(int family, int type, int protocol, SSL_CTX* ctx);
    ~SecureSocket();

    StatusType connect_secure();
    StatusType accept_secure();

    bool shutdown_secure();

    //overwrite read & write
    int read(char* buffer, int buffer_length);
    int write(char* buffer, int buffer_length);
};

#endif