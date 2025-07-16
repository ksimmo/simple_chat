#include <iostream>
#include <signal.h>
#include <thread>
#include <atomic>
#include <mutex>

#include <sqlite3.h>
#include "logger.h"

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
    Logger& logger = Logger::instance(LogLevel::DEBUG, "server.log");
    signal(SIGINT, &quit_loop);

    //for test case (bob, alice)
    std::vector<unsigned char> pub = {71,130,169,175,37,119,84,77,211,33,86,176,125,7,109,171,150,179,34,32,59,161,196,197,178,90,96,18,20,246,14,211};
    std::vector<unsigned char> pub2 = {242,166,74,118,251,209,138,140,15,177,96,237,234,0,148,242,120,50,97,254,145,4,18,93,218,239,245,215,175,44,197,202};

    //initialize database
    Database* db = new Database();
    db->connect("server.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    db->run_query("CREATE TABLE IF NOT EXISTS users (name TEXT NOT NULL UNIQUE, key BLOB NOT NULL, key_type TEXT NOT NULL, last_login TEXT NOT NULL);", nullptr);
    //register user (test)
    std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
    db->run_query("INSERT INTO users (name, key, key_type, last_login) VALUES(?, ?, ?, ?);", "sbst", "TestUser", pub.size(), pub.data(), "ED25519", &tp);
    db->run_query("INSERT INTO users (name, key, key_type, last_login) VALUES(?, ?, ?, ?);", "sbst", "TestUser2", pub2.size(), pub2.data(), "ED25519", &tp);

    db->run_query("CREATE TABLE IF NOT EXISTS prekeys (name TEXT NOT NULL UNIQUE, key BLOB NOT NULL, key_type TEXT NOT NULL, signature BLOB NOT NULL, date TEXT NOT NULL);", nullptr);
    db->run_query("CREATE TABLE IF NOT EXISTS otkeys (name TEXT NOT NULL, key BLOB NOT NULL UNIQUE, key_type TEXT NOT NULL, date TEXT NOT NULL);", nullptr);

    //create db for storing undelivered messages
    db->run_query("CREATE TABLE IF NOT EXISTS messages (receiver TEXT NOT NULL, sender TEXT NOT NULL, date TEXT NOT NULL, msg BLOB NOT NULL);", nullptr);

    //setup host
    initialize_socket();
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
    std::unordered_map<std::string, User*> active_names; //link user to name

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
                    User* user = new User(ev.fd);
                    users.insert(std::make_pair(ev.fd, user));
                    std::cout << "[+]Client " << ev.fd << " is ready!" << std::endl;
                    break;
                }
                case PE_DISCONNECTED:
                {
                    auto entry = users.find(ev.fd);
                    if(entry==users.end()) //check if user exists
                        break;

                    //check if user was logged in
                    if(entry->second->is_verified())
                    {
                        //ok also remove from active names
                        auto entry2 = active_names.find(entry->second->get_name());
                        if(entry2!=active_names.end())
                            active_names.erase(entry2);
                    }
                    //finalize user
                    delete entry->second;
                    users.erase(entry);
                    std::cout << "[+]Client " << ev.fd << " disconnected!" << std::endl;
                    break;
                }
                case PE_AUTHENTICATED:
                {
                    //check if enough OT keys are uploaded
                    auto entry = users.find(ev.fd);
                    if(entry==users.end()) //check if user exists
                        break;
                    db->run_query("SELECT date from otkeys WHERE name='"+entry->second->get_name()+"';", nullptr);
                    std::size_t num_ots = db->values.size();
                    if(num_ots<10) //we require more ots #TODO: set this via config
                    {
                        Packet* newpacket = new Packet(ev.fd, PK_UPLOAD_KEYS);
                        newpacket->append(10-num_ots);
                        connector->add_packet(newpacket);
                    }

                    std::cout << "[+]Checking if " << ev.fd << " has undelivered messages!" << std::endl;
                    db->run_query("SELECT sender, msg, date from messages WHERE receiver='"+entry->second->get_name()+"';", nullptr);
                    for(auto i=0;i<db->values.size();i++)
                    {
                        //delete message or mark as sended!
                        
                        //send message
                    }
                    break;
                }
            }
            ev = connector->pop_event();
        }

        //do processing of packets
        Packet* packet = connector->pop_packet();
        while(packet!=nullptr)
        {
            bool parse_error = false; //set this to true if parsing a packet fails

            switch(packet->get_type())
            {
            case PK_LOGIN:
            {
                std::cout << "[+]Login attempt received from " << packet->get_fd() << "!" << std::endl;
                std::string s;
                parse_error = !packet->read_string(s);
                if(parse_error)
                    break;

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
                        connector->shutdown();
                    }
                }
                break;
            }
            case PK_LOGIN_CHALLENGE:
            {
                User* user = users[packet->get_fd()];
                std::cout << "[+] Received signed challenge from " << packet->get_fd() << std::endl;
                std::vector<unsigned char> signed_challenge;
                parse_error = !packet->read_buffer(signed_challenge);
                if(parse_error)
                    break;

                bool status = user->check_challenge(signed_challenge);
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
                    active_names.insert(std::make_pair(user->get_name(), user));
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
                parse_error = !packet->read_string(query);
                if(parse_error)
                    break;

                //TODO: allow more flexible user search
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
                std::string name;
                parse_error = !packet->read_string(name);
                if(parse_error)
                    break;

                db->run_query("SELECT key from users WHERE name='"+name+"';", nullptr);
                if(db->values.size()==0)
                {
                    Packet* newpacket = new Packet(packet->get_fd(), PK_ERROR);
                    newpacket->append((int)PK_ERROR_USER);
                    newpacket->append_string("User "+name+" is not registered!");
                    connector->add_packet(newpacket);
                    break;
                }

                auto entry = active_names.find(name);
                bool status = (entry!=active_names.end());
                Packet* newpacket = new Packet(packet->get_fd(), PK_ONLINE_STATUS);
                newpacket->append_string(name);
                newpacket->append((char)status);
                connector->add_packet(newpacket);

                break;
            }
            case PK_UPLOAD_KEYS:
            {
                User* user = users[packet->get_fd()];
                if(!user->is_verified())
                {
                    break;
                }
                unsigned char byte;
                parse_error = !packet->read(byte);
                if(parse_error)
                    break;
                if(byte)
                {
                    std::vector<unsigned char> prekey;
                    std::vector<unsigned char> signature;
                    std::string type;
                    parse_error |= !packet->read_buffer(prekey);
                    parse_error |= !packet->read_string(type);
                    parse_error |= !packet->read_buffer(signature);
                    if(parse_error)
                        break;

                    //get date
                    std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();

                    //save
                    db->run_query("INSERT INTO prekeys(name,key,key_type,signature,date) VALUES(?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET key=excluded.key, key_type=excluded.key_type, signature=excluded.signature, date=excluded.date",
                                "sbsbt", user->get_name().c_str(), prekey.size(), prekey.data(), type.c_str(), signature.size(), signature.data(), &tp);
                }
                else
                {
                    //get date
                    std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
                    std::size_t num_keys;
                    packet->read(num_keys);
                    for(std::size_t i=0;i<num_keys;i++)
                    {
                        std::vector<unsigned char> onetime;
                        parse_error |= !packet->read_buffer(onetime);
                        std::string type;
                        parse_error |= !packet->read_string(type);
                        if(parse_error)
                            break;

                        //save
                        db->run_query("INSERT INTO otkeys(name,key,key_type,date) VALUES(?,?,?,?) ON CONFLICT(key) DO NOTHING;",
                                    "sbst", user->get_name().c_str(), onetime.size(), onetime.data(), type.c_str(), &tp);
                    }
                }
                break;
            }
            case PK_USER_KEYS:
            {
                std::string name;
                parse_error = !packet->read_string(name);
                if(parse_error)
                    break;
                db->run_query("SELECT key, key_type from users WHERE name='"+name+"';", nullptr);
                if(db->values.size()==0)
                {
                    Packet* newpacket = new Packet(packet->get_fd(), PK_ERROR);
                    newpacket->append((int)PK_ERROR_USER);
                    newpacket->append_string("User "+name+" is not registered!");
                    connector->add_packet(newpacket);
                    break;
                }

                //get user identity key
                std::vector<unsigned char> data;
                data.resize(db->values[0][0]->get_length());
                std::copy(db->values[0][0]->get_data(), db->values[0][0]->get_data()+data.size(), data.data());

                std::string type;
                db->values[0][1]->get_string(type);

                //get user prekey & signature
                db->run_query("SELECT key, key_type, signature from prekeys WHERE name='"+name+"';", nullptr);
                std::vector<unsigned char> prekey;
                prekey.resize(db->values[0][0]->get_length());
                std::copy(db->values[0][0]->get_data(), db->values[0][0]->get_data()+prekey.size(), prekey.data());

                std::string prekey_type;
                db->values[0][1]->get_string(prekey_type);

                std::vector<unsigned char> signature;
                signature.resize(db->values[0][2]->get_length());
                std::copy(db->values[0][2]->get_data(), db->values[0][2]->get_data()+signature.size(), signature.data());

                //check if user has uploaded onetime-prekeys
                db->run_query("SELECT key, key_type, date from otkeys WHERE name='"+name+"';", nullptr);
                std::vector<unsigned char> otkey;
                std::string ot_type;
                if(db->values.size()>0) //ok we have a ot key available
                {
                    db->values[0][1]->get_string(ot_type); //check if format matches
                    otkey.resize(db->values[0][0]->get_length());
                    std::copy(db->values[0][0]->get_data(), db->values[0][0]->get_data()+otkey.size(), otkey.data());

                    //delete otkey from db
                    db->run_query("DELETE FROM otkeys WHERE key=?", "b", otkey.size(), otkey.data());
                }

                Packet* newpacket = new Packet(packet->get_fd(), PK_USER_KEYS);
                newpacket->append_string(name);
                newpacket->append_buffer(data);
                newpacket->append_string(type);
                newpacket->append_buffer(prekey);
                newpacket->append_string(prekey_type);
                newpacket->append_buffer(signature);

                newpacket->append_byte(otkey.size()>0); //1 for available onetime prekey
                if(otkey.size()>0)
                    newpacket->append_buffer(otkey);
                connector->add_packet(newpacket);
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
                parse_error = !packet->read_string(name);
                if(parse_error)
                    break;
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
                std::vector<unsigned char> msg_data;
                packet->read_remaining(msg_data);

                auto entry = active_names.find(name);
                if(entry!=active_names.end())
                {
                    //send message
                    Packet* newpacket = new Packet(entry->second->get_fd(), PK_MSG);
                    newpacket->append_string(user->get_name());
                    newpacket->append_buffer(msg_data, false); //append raw bytes but not as buffer
                    connector->add_packet(newpacket);
                }
                else
                {
                    //store message
                    std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
                    db->run_query("INSERT INTO messages (receiver,sender,date,msg) VALUES(?,?,?,?);", "sstb",
                            name.c_str(), user->get_name().c_str(), &tp, msg_data.size(), msg_data.data());
                }

                break;
            }
            default:
            {
                Packet* newpacket = new Packet(packet->get_fd(), PK_ERROR);
                newpacket->append((int)PK_ERROR_UNDEFINED);
                newpacket->append_string("Packet type "+std::to_string(packet->get_type())+" not valid!");
                connector->add_packet(newpacket);
                break;
            }
            }

            if(parse_error)
            {
                std::cout << "Parsing Error detected!" << std::endl;
                Packet* newpacket = new Packet(packet->get_fd(), PK_ERROR);
                newpacket->append((int)PK_ERROR_PARSE);
                connector->add_packet(newpacket);
            }

            delete packet;
            packet = connector->pop_packet();
        }

        //check if user waits too long for login
        auto now = std::chrono::system_clock::now();
        for(auto it=users.begin();it!=users.end();it++)
        {
            if(!it->second->is_verified())
            {
                int64_t difference = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second->get_time_conn()).count();
                if(difference>=5000) //ok client took too long to authentifiy
                {
                    std::cout << "[-] User " << it->first << " took too long to login!" << std::endl;
                    disconnect_user(it->first);
                }
            }
        }

        //check for undelivered messages beeing too old -> delete

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