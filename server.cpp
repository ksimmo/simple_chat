#include <iostream>
#include <signal.h>
#include <thread>
#include <atomic>
#include <mutex>

#include <sqlite3.h>
#include "net/net.h"
#include "crypto/crypto.h"
#include "db/database.h"
#include "server/user.h"

std::atomic<bool> main_loop_run(true);
Connector* connector = nullptr;

void quit_loop(int sig)
{
    main_loop_run = false;
}

void network_worker()
{
    while(main_loop_run && connector->is_initialized())
    {
        //send packets and receive packets
        connector->step(100); // define a timeout otherwise we will never catch signals
    }
}

int main(int argc, char* argv[])
{
    signal(SIGINT, &quit_loop);

    std::vector<unsigned char> pub = {71,130,169,175,37,119,84,77,211,33,86,176,125,7,109,171,150,179,34,32,59,161,196,197,178,90,96,18,20,246,14,211};
    Key* k = new Key();
    k->create_from_public(k->get_id(), pub.data(), pub.size());

    std::vector<unsigned char> challenge(32);
    if (RAND_bytes(challenge.data(), 32) != 1) {
        throw std::runtime_error("Failed to generate random challenge.");
    }

    //initialize database
    Database* db = new Database();
    db->connect("server.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    //register user (test)
    db->run_query("CREATE TABLE IF NOT EXISTS users (name TEXT NOT NULL UNIQUE, key BLOB NOT NULL, last_login TEXT NOT NULL);", nullptr);
    db->run_query("INSERT INTO users (name, key, last_login) VALUES(?, ?, ?);", "tbt", "TestUser", pub.size(), pub.data(), "never");

    //setup host
    SSL_CTX* ctx = init_openssl(false, std::string("cert.pem"), std::string("key.pem"));
    connector = new Connector(ctx);
    bool status = connector->initialize(CONN_SERVER, std::string(""), 69100, 1000);
    if(!status)
    {
        std::cerr << "Cannot create host!" << std::endl;
        delete connector;
        cleanup_openssl(ctx);
        return -1;
    }

    //create users to store information
    std::unordered_map<int, User*> users;

    std::thread network_thread(network_worker);
    while(main_loop_run && connector->is_initialized())
    {
        //pop events and check if we have handshake established
        ConnectorEvent ev = connector->pop_event();
        while (ev.ev!=PE_NONE) //no need to check for fd
        {
            switch (ev.ev)
            {
                case PE_HANDSHAKE_FINISHED:
                {
                    User* user = new User(std::chrono::system_clock::now());
                    users.insert(std::make_pair(ev.fd, user));
                    std::cout << "[+] Client " << ev.fd << " is ready" << std::endl;
                    break;
                }
                case PE_DISCONNECTED:
                {
                    auto entry = users.find(ev.fd);
                    //finalize user
                    delete entry->second;
                    users.erase(entry);
                    std::cout << "[+] Client " << ev.fd << " disconnected" << std::endl;
                    break;
                }
            }
            ev = connector->pop_event();
        }

        //do processing of packets
        Packet* packet = connector->pop_packet();
        while(packet!=nullptr)
        {
            switch(packet->get_type())
            {
            case PK_LOGIN:
            {
                std::cout << "[+] Login attempt received from " << packet->get_fd() << "!" << std::endl;
                std::string s;
                packet->read_string(s);
                std::cout << s << std::endl;

                //check if user exists



                //check if user exists and then send challenge
                Packet* newpacket = new Packet(packet->get_fd(), PK_AUTH_CHALLENGE);
                //newpacket->append_string("Challenge");
                newpacket->append_buffer(challenge.data(), challenge.size());
                connector->add_packet(newpacket);
                //TODO save timepoint of challenge creation
                break;
            }
            case PK_AUTH_CHALLENGE:
            {
                std::cout << "[+] Received signed challenge from " << packet->get_fd() << std::endl;
                std::size_t length = 0;
                packet->read(length);
                std::vector<unsigned char> signed_challenge(length);
                packet->read_raw(signed_challenge.data(), length);

                bool status = k->verify_signature(challenge, signed_challenge);
                std::cout << "[+]Challenge status: " << status << std::endl;

                //TODO: check time since sending of challenge to make sure answer happens fast enough
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

    delete k;

    //clear users
    for(auto p : users)
        delete p.second; //delete socket

    cleanup_openssl(ctx);

    delete db;

    return 0;
}