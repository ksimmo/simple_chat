#include <iostream>
#include "net/secure_socket.h"

void init_openssl()
{
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SecureSocket::SecureSocket(SSL_CTX* ctx) : Socket()
{
    this->ctx = ctx;
    if(ctx!=nullptr) //only make this Socket secure if a valid ctx pointer is given
        this->ssl = SSL_new(ctx);
}

SecureSocket::SecureSocket(int sock, SSL_CTX* ctx) : Socket(sock)
{
    this->ctx = ctx;
    if(ctx!=nullptr)
        this->ssl = SSL_new(ctx);
}

SecureSocket::SecureSocket(int family, int type, int protocol, SSL_CTX* ctx) : Socket(family, type, protocol)
{
    this->ctx = ctx;
    if(ctx!=nullptr)
        this->ssl = SSL_new(ctx);
}

SecureSocket::~SecureSocket()
{
    if(this->ssl!=nullptr)
        SSL_free(this->ssl);
}