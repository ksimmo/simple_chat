#include <iostream>
#include <signal.h>
#include <thread>
#include <atomic>
#include <mutex>

#include <sqlite3.h>
#include "net/net.h"

std::atomic<bool> main_loop_run(true);
Host* host = nullptr;

void quit_loop(int sig)
{
    main_loop_run = false;
}

void network_worker()
{
    while(main_loop_run && host->is_initialized())
    {
        //send packets and receive packets
        host->handle_events(1000); // define a timeout otherwise we will never catch the signal
    }
}

int main(int argc, char* argv[])
{
    signal(SIGINT, &quit_loop);

    //setup host
    SSL_CTX* ctx = init_openssl(false, std::string("cert.pem"), std::string("key.pem"));
    host = new Host();
    bool status = host->initialize(69100, 1000, ctx);
    if(!status)
    {
        std::cerr << "Cannot create host!" << std::endl;
        delete host;
        cleanup_openssl(ctx);
        return -1;
    }

    std::thread network_thread(network_worker);

    while(main_loop_run)
    {
        //pop events and check if we have handshake established
        /*HostEvent ev = host->pop_event();
        while (ev.fd>=0)
        {
            switch (ev.ev)
            {
            }
            ev = host->pop_event();
        }*/

        //do processing of packets
        HostPacket temp = host->pop_packet();
        while(temp.fd>=0)
        {
            switch(temp.packet->get_type())
            {
            case PK_LOGIN:
            {
                std::cout << "[+] Login received from " << temp.fd << "!" << std::endl;
                std::string s;
                temp.packet->read_string(s);
                std::cout << s << std::endl;

                //check if user exists and then send challenge
                Packet* packet = new Packet(PK_AUTH_CHALLENGE);
                packet->append_string("Challenge");
                host->add_packet(temp.fd, packet);
                break;
            }
            default:
                break;
            }

            delete temp.packet;
            temp = host->pop_packet();
        }
    }

    network_thread.join();

    //clean up
    delete host;

    cleanup_openssl(ctx);

    return 0;
}