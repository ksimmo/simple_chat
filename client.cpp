#include <iostream>
#include <filesystem>
#include <signal.h>

#include <QtCore/QCoreApplication>
#include "net/net.h"
#include "db/database.h"
#include "crypto/crypto.h"

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
    Key* k = new Key();
    k->create();
    std::vector<unsigned char> priv = k->extract_private();
    std::vector<unsigned char> pub = k->extract_public();
    std::string s1 = "";
    std::string s2 = "";
    for (std::size_t i = 0; i < priv.size(); i++)
    {
        //printf("%02x", priv[i]);
        s1 += std::to_string((int)priv[i]) + ",";
        s2 += std::to_string((int)pub[i]) + ","; 
    }
    std::cout << s1 << std::endl;
    std::cout << s2 << std::endl;
    //delete k;

    priv = {238,86,202,231,84,24,213,231,248,202,216,220,193,41,139,180,92,242,29,113,238,233,125,141,62,121,163,208,85,209,27,123};
    pub = {71,130,169,175,37,119,84,77,211,33,86,176,125,7,109,171,150,179,34,32,59,161,196,197,178,90,96,18,20,246,14,211};
    //k = new Key();
    k->create_from_private(k->get_id(), priv.data(), priv.size());

    Database* db = new Database();
    db->connect("user.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE); //create if not exists
    db->run_query("CREATE TABLE IF NOT EXISTS keys (type TEXT NOT NULL, id INTEGER, key BLOB NOT NULL, date TEXT);", nullptr);
    db->run_query("INSERT INTO keys (type, id, key, date) VALUES(?, ?, ?);", "tibt", "TestUser", priv.size(), priv.data(), "-");

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
                    packet->append_string("TestUser");
                    connector->add_packet(packet);
                    //maybe also send key
                    break;
                }
                case PE_DISCONNECTED:
                {
                    std::cout << "[+] Disconnected!" << std::endl;
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
                    std::cout << "[+]Received Challenge!" << std::endl;
                    std::size_t length = 0;
                    packet->read(length);
                    std::vector<unsigned char> challenge(length);
                    packet->read_raw(challenge.data(), length);

                    //sign challenge
                    std::vector<unsigned char> signed_data;
                    bool status = k->sign_data(challenge, signed_data);
                    std::cout << "Challenge signed " << signed_data.size() << std::endl;

                    Packet* newpacket = new Packet(-1, PK_AUTH_CHALLENGE);
                    newpacket->append_buffer(signed_data.data(), signed_data.size());
                    connector->add_packet(newpacket);

                    break;
                }
            }
            delete packet;
            packet = connector->pop_packet();
        }
        
    }
    delete connector;
    delete db;

    delete k;

    cleanup_openssl(ctx);

    return 0;
}