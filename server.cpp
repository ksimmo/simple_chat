#include <iostream>
#include <signal.h>
#include "net/net.h"

bool main_loop_run = true;

void quit_loop(int sig)
{
    main_loop_run = false;
}

int main(int argc, char* argv[])
{
    signal(SIGINT, &quit_loop);
    init_openssl();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if(!ctx)
        std::cerr << "Cannot create CTX!" << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    Host* host = new Host();
    bool status = host->initialize(69100, 1000, ctx);
    if(!status)
    {
        std::cerr << "Cannot create host!" << std::endl;
    }
    while(main_loop_run && host->is_initialized())
    {
        //send packets and receive data
        host->handle_events();

        //ok now process packets

        //after processing packets delete used packages
    }
    delete host;

    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}