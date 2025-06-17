#include <iostream>
#include <signal.h>

#include <QtCore/QCoreApplication>
#include "net/net.h"

bool main_loop_run = true;

void quit_loop(int sig)
{
    main_loop_run = false;
}

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    signal(SIGINT, &quit_loop);
    SSL_CTX* ctx = init_openssl();

    //if not exists -> create private/public key pair (long term identity key)

    Client* client = new Client();
    client->initialize("127.0.0.1", 69100, 100, ctx);

    while(main_loop_run && client->is_initialized())
    {
        client->handle_events();

        //pop events and check if we have handshake established
        PeerEvent ev = client->pop_event();
        while (ev!=PE_NONE)
        {
            switch (ev)
            {
                case PE_HANDSHAKE_FINISHED:
                {
                    std::cout << "[+]Sending login ..." << std::endl;
                    Packet* packet = new Packet(PK_LOGIN);
                    packet->append_string("Username");
                    client->add_packet(packet);
                    //maybe also send key
                    break;
                }
            }
            ev = client->pop_event();
        }

        //check packets
        Packet* packet = client->pop_packet();
        while(packet!=nullptr)
        {
            switch(packet->get_type())
            {
                case PK_AUTH_CHALLENGE:
                {
                    std::string s;
                    packet->read_string(s);
                    std::cout << "[+]Received Challenge: " << s << std::endl;
                    break;
                }
            }
            delete packet;
            packet = client->pop_packet();
        }
        
    }
    delete client;

    cleanup_openssl(ctx);

    return 0;
}