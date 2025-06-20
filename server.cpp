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

void disconnect_user(int fd)
{
    //connector->initiate_clean_disconnect(fd);
}

int main(int argc, char* argv[])
{
    signal(SIGINT, &quit_loop);

    //for test case
    std::vector<unsigned char> pub = {71,130,169,175,37,119,84,77,211,33,86,176,125,7,109,171,150,179,34,32,59,161,196,197,178,90,96,18,20,246,14,211};

    //initialize database
    Database* db = new Database();
    db->connect("server.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    //register user (test)
    db->run_query("CREATE TABLE IF NOT EXISTS users (name TEXT NOT NULL UNIQUE, key BLOB NOT NULL, key_type INTEGER NOT NULL, last_login TEXT NOT NULL);", nullptr);
    db->run_query("INSERT INTO users (name, key, key_type, last_login) VALUES(?, ?, ?, ?);", "tbit", "TestUser", pub.size(), pub.data(), EVP_PKEY_ED25519, "never");

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
                    std::cout << "[+]Client " << ev.fd << " is ready!" << std::endl;
                    break;
                }
                case PE_DISCONNECTED:
                {
                    auto entry = users.find(ev.fd);
                    //finalize user
                    delete entry->second;
                    users.erase(entry);
                    std::cout << "[+]Client " << ev.fd << " disconnected!" << std::endl;
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
                std::cout << "[+]Login attempt received from " << packet->get_fd() << "!" << std::endl;
                std::string s;
                packet->read_string(s);

                //check if user exists
                db->run_query("SELECT key, key_type from users WHERE name='"+s+"';", nullptr);
                if(db->values.size()==0) //ok user does not exist!
                {
                    std::cout << "[-]Non existent user " << s << std::endl;
                    Packet* newpacket = new Packet(packet->get_fd(), PK_ERROR);
                    newpacket->append_string("User "+s+" is not registered!");
                    connector->add_packet(newpacket);
                    //disconnect
                    disconnect_user(packet->get_fd());
                }
                else
                {
                    User* user = users[packet->get_fd()];
                    user->set_name(s);

                    //extract key
                    std::vector<unsigned char> data;
                    data.resize(db->values[0][0]->get_length());
                    std::copy(db->values[0][0]->get_data(), db->values[0][0]->get_data()+data.size(), data.data());
                    user->set_key(*((int*)db->values[0][1]->get_data()), data);

                    //check if user exists and then send challenge
                    std::vector<unsigned char> challenge = user->create_challenge(32);
                    if(challenge.size()==32)
                    {
                        Packet* newpacket = new Packet(packet->get_fd(), PK_LOGIN_CHALLENGE);
                        newpacket->append_buffer(challenge);
                        connector->add_packet(newpacket);
                    }
                    else
                    {
                        //disconnect
                    }
                }
                break;
            }
            case PK_LOGIN_CHALLENGE:
            {
                User* user = users[packet->get_fd()];
                std::cout << "[+] Received signed challenge from " << packet->get_fd() << std::endl;
                std::vector<unsigned char> signed_challenge;
                bool status = packet->read_buffer(signed_challenge);

                status = user->check_challenge(signed_challenge);
                std::cout << "[+]Challenge status: " << status << std::endl;
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

    //clear users
    for(auto p : users)
        delete p.second; //delete socket

    cleanup_openssl(ctx);

    delete db;

    return 0;
}