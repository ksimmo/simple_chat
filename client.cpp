#include <iostream>
#include <filesystem>
#include <signal.h>

#include <QtCore/QCoreApplication>
#include "net/net.h"
#include "db/database.h"

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

    Database* db = new Database();
    db->connect("user.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE); //create if not exists

    //if not exists -> create private/public key pair (long term identity key)

    //Client* client = new Client();
    //client->initialize("127.0.0.1", 69100, 100, ctx);
    Connector* connector = new Connector(ctx);
    connector->initialize(CONN_CLIENT, "127.0.0.1", 69100, 100);

    while(main_loop_run && connector->is_initialized())
    {
        connector->step(100);

        //pop events and check if we have handshake established
        ConnectorEvent ev = connector->pop_event();
        while (ev.ev!=PE_NONE) //no need to check for fd
        {
            switch (ev.ev)
            {
                case PE_HANDSHAKE_FINISHED:
                {
                    std::cout << "[+]Sending login ..." << std::endl;
                    Packet* packet = new Packet(-1, PK_LOGIN);
                    packet->append_string("Username");
                    connector->add_packet(packet);
                    //maybe also send key
                    break;
                }
            }
            ev = connector->pop_event();
        }

        //check packets
        Packet* packet = connector->pop_packet();
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
            packet = connector->pop_packet();
        }
        
    }
    delete connector;
    delete db;

    cleanup_openssl(ctx);

    return 0;
}