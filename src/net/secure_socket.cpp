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
        this->shutdown_secure();
        SSL_free(this->ssl);
}

StatusType SecureSocket::connect_secure()
{
    if(this->ssl==nullptr)
    {
        std::cout << "[-]SSL is not available!" << std::endl;
        return ST_FAIL;
    }
    SSL_set_fd(this->ssl, this->get_fd());
    int result = SSL_connect(this->ssl);

    StatusType st = ST_SUCCESS;
    if(result<=0)
    {
        int error = SSL_get_error(this->ssl, result);
        switch(error)
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                st = ST_INPROGRESS;
                break;
            default:
                st = ST_FAIL;
                std::cerr << "SSL handshake failed: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
                break;
        }
    }

    return st;
}


StatusType SecureSocket::accept_secure()
{
    if(this->ssl==nullptr)
    {
        std::cout << "[-]SSL is not available!" << std::endl;
        return ST_FAIL;
    }
    SSL_set_fd(this->ssl, this->get_fd());
    int result = SSL_accept(this->ssl);

    StatusType st = ST_SUCCESS;
    if(result<=0)
    {
        int error = SSL_get_error(this->ssl, result);
        switch(error)
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                st = ST_INPROGRESS;
                break;
            default:
                st = ST_FAIL;
                std::cerr << "SSL handshake failed: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
                break;
        }
    }

    return st;
}

bool SecureSocket::shutdown_secure()
{
    if(this->ssl==nullptr)
        return true;

    int result = SSL_shutdown(this->ssl);
    bool status = true;
    if(result<=0)
    {
        int error = SSL_get_error(this->ssl, result);
        switch(error)
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                break;
            default:
                status = false;
                break;
        }
    }

    return status;
}

int SecureSocket::read(char* buffer, int buffer_length)
{
    if(this->ctx==nullptr)
        return Socket::read(buffer, buffer_length);

    int result = SSL_read(this->ssl, buffer, buffer_length);
    if(result==-1)
    {
        int error = SSL_get_error(this->ssl, result);
        switch(error)
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                result = -2;
                break;
        }
    }

    return result;
}

int SecureSocket::write(char* buffer, int buffer_length)
{
    if(this->ctx==nullptr)
        return Socket::write(buffer, buffer_length);

    int result = SSL_write(this->ssl, buffer, buffer_length);
    if(result==-1)
    {
        int error = SSL_get_error(this->ssl, result);
        switch(error)
        {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                result = -2;
                break;
        }
    }

    return result;
}