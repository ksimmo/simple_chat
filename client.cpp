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

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx)
        std::cerr << "Cannot create CTX!" << ERR_error_string(ERR_get_error(), NULL) << std::endl;


    Client* client = new Client();
    client->initialize("127.0.0.1", 69100, 100, ctx);

    while(main_loop_run && client->is_initialized())
    {
        client->handle_events();
    }
    delete client;

    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}