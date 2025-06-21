#include <iostream>
#include "net/secure_socket.h"

SSL_CTX* init_openssl(bool is_client, const std::string& cert, const std::string& key)
{
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ctx = nullptr;

    if(is_client)
        ctx = SSL_CTX_new(TLS_client_method());
    else
        ctx = SSL_CTX_new(TLS_server_method());
    if(!ctx)
    {
        std::cerr << "[-]Cannot create CTX: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return nullptr;
    }
    
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) //we want to use TLS v1.3!
    {
        std::cerr << "[-]Cannot use TLS v1.3: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }
    
    if(!is_client && !cert.empty() && !key.empty())
    {
        if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
            std::cerr << "[-]Cannot load cert and key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }

    return ctx;
}

void cleanup_openssl(SSL_CTX* ctx)
{
    if(ctx!=nullptr)
        SSL_CTX_free(ctx);
    EVP_cleanup();
}

////////////////////////////////////////

SecureSocket::SecureSocket(SSL_CTX* ctx) : Socket()
{
    this->ctx = ctx;
    if(ctx!=nullptr) //only make this Socket secure if a valid ctx pointer is given
        this->ssl = SSL_new(ctx);
}

SecureSocket::SecureSocket(int fd, SSL_CTX* ctx) : Socket(fd)
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
    SSL_set_fd(this->ssl, this->fd);
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
                std::cerr << "[-]SSL handshake failed: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
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
    SSL_set_fd(this->ssl, this->fd);
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
                std::cerr << "[-]SSL handshake failed: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
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