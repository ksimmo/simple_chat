#include <iostream>
#include <signal.h>
#include <thread>
#include <atomic>
#include <mutex>

#include <sqlite3.h>
#include "net/net.h"

std::atomic<bool> main_loop_run(true);
Connector* connector = nullptr;
//Host* host = nullptr;

void quit_loop(int sig)
{
    main_loop_run = false;
}

void network_worker()
{
    while(main_loop_run && connector->is_initialized())
    {
        //send packets and receive packets
        connector->step(1000); // define a timeout otherwise we will never catch the signal
    }
}

int main(int argc, char* argv[])
{
    signal(SIGINT, &quit_loop);

    //setup host
    SSL_CTX* ctx = init_openssl(false, std::string("cert.pem"), std::string("key.pem"));
    connector = new Connector(ctx);
    //bool status = host->initialize(69100, 1000, ctx);
    bool status = connector->initialize(CONN_SERVER, std::string(""), 69100, 1000);
    if(!status)
    {
        std::cerr << "Cannot create host!" << std::endl;
        delete connector;
        cleanup_openssl(ctx);
        return -1;
    }

    std::thread network_thread(network_worker);
    while(main_loop_run)
    {
        //pop events and check if we have handshake established

        //do processing of packets
        Packet* packet = connector->pop_packet();
        while(packet!=nullptr)
        {
            switch(packet->get_type())
            {
            case PK_LOGIN:
            {
                std::cout << "[+] Login received from " << packet->get_fd() << "!" << std::endl;
                std::string s;
                packet->read_string(s);
                std::cout << s << std::endl;

                //check if user exists and then send challenge
                Packet* newpacket = new Packet(packet->get_fd(), PK_AUTH_CHALLENGE);
                newpacket->append_string("Challenge");
                connector->add_packet(newpacket);
                break;
            }
            default:
                break;
            }

            delete packet;
            packet = connector->pop_packet();
        }

        //maybe wait here a few milliseconds
    }
    network_thread.join();

    //clean up
    delete connector;

    cleanup_openssl(ctx);

    return 0;
}