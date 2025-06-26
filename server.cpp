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
    connector->initiate_clean_disconnect(fd);
}

int main(int argc, char* argv[])
{
    signal(SIGINT, &quit_loop);

    //for test case
    std::vector<unsigned char> pub = {71,130,169,175,37,119,84,77,211,33,86,176,125,7,109,171,150,179,34,32,59,161,196,197,178,90,96,18,20,246,14,211};

    //initialize database
    Database* db = new Database();
    db->connect("server.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    db->run_query("CREATE TABLE IF NOT EXISTS users (name TEXT NOT NULL UNIQUE, key BLOB NOT NULL, key_type TEXT NOT NULL, last_login TEXT NOT NULL);", nullptr);
    //register user (test)
    db->run_query("INSERT INTO users (name, key, key_type, last_login) VALUES(?, ?, ?, ?);", "tbtt", "TestUser", pub.size(), pub.data(), "ED25519", "never");

    //create db for storing undelivered messages
    db->run_query("CREATE TABLE IF NOT EXISTS messages (name TEXT NOT NULL, key BLOB NOT NULL, date TEXT NOT NULL);", nullptr);

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
    std::unordered_map<int, User*> users; //link user to socket fd
    //std::unordered_map<std::string, User*user>; //link user to name

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
                    User* user = new User(ev.fd, std::chrono::system_clock::now());
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
                case PE_AUTHENTICATED:
                {
                    std::cout << "[+]Checking if " << ev.fd << " has undelivered messages!" << std::endl;
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
                    newpacket->append((int)PK_ERROR_UNREGISTERED);
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
                    
                    std::string name; //extract key_type
                    db->values[0][1]->get_string(name);
                    user->set_key(name, data);

                    //check if user exists and then send challenge
                    bool status = user->create_challenge(32);
                    if(status)
                    {
                        std::vector<unsigned char> challenge = user->get_challenge();
                        Packet* newpacket = new Packet(packet->get_fd(), PK_LOGIN_CHALLENGE);
                        newpacket->append_buffer(challenge);
                        connector->add_packet(newpacket);
                    }
                    else
                    {
                        //disconnect
                        Packet* newpacket = new Packet(packet->get_fd(), PK_ERROR);
                        newpacket->append((int)PK_ERROR_SERVER);
                        newpacket->append_string("Server error!");
                        connector->add_packet(newpacket);
                        disconnect_user(packet->get_fd());

                        //TODO: fatal error we should close the server
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
                if(!status)
                {
                    Packet* newpacket = new Packet(packet->get_fd(), PK_ERROR);
                    newpacket->append((int)PK_ERROR_AUTH);
                    newpacket->append_string("Authentification failed!");
                    connector->add_packet(newpacket);
                    //disconnect
                    disconnect_user(packet->get_fd());
                }
                else
                {
                    //ok nice client is successfully authenticated
                    user->set_verified();
                    connector->add_event(packet->get_fd(), PE_AUTHENTICATED);
                    Packet* newpacket = new Packet(packet->get_fd(), PK_LOGIN_SUCCESSFULL);
                    connector->add_packet(newpacket);
                }
                break;
            }
            case PK_USER_SEARCH:
            {
                User* user = users[packet->get_fd()];
                if(!user->is_verified())
                {
                    break;
                }
                std::string query;
                packet->read_string(query);
                db->run_query("SELECT DISTINCT name from users WHERE LOWER(name) LIKE LOWER('"+query+"%') LIMIT 10;", nullptr);
                int num = db->values.size();

                Packet* newpacket = new Packet(packet->get_fd(), PK_USER_SEARCH);
                newpacket->append(num); //number of search results
                for(int i=0;i<num;i++)
                {
                    std::string temp;
                    db->values[i][0]->get_string(temp);
                    newpacket->append_string(temp);
                }
                connector->add_packet(newpacket);
                break;
            }
            case PK_ONLINE_STATUS:
            {
                User* user = users[packet->get_fd()];
                if(!user->is_verified())
                {
                    break;
                }
                break;
            }
            case PK_MSG:
            {
                User* user = users[packet->get_fd()];
                if(!user->is_verified())
                {
                    break;
                }
                std::string name;
                packet->read_string(name);
                //check if user exists
                db->run_query("SELECT key from users WHERE name='"+name+"';", nullptr);
                if(db->values.size()==0)
                {
                    Packet* newpacket = new Packet(packet->get_fd(), PK_ERROR);
                    newpacket->append((int)PK_ERROR_USER);
                    newpacket->append_string("User "+name+" is not registered!");
                    connector->add_packet(newpacket);
                    break;
                }

                //check if receiver is online -> otherwise store message for later deliverage

                //if online send packet
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