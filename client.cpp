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

    //lets run a few tests here
    std::string a = "ML-DSA-87";

    //if not exists -> create private/public key pair (long term identity key)
    Key* k = new Key();
    k->create(a);
    std::vector<unsigned char> priv;
    std::vector<unsigned char> pub;
    std::cout << "test" << std::endl;
    k->extract_private(priv);
    std::cout << "test2 " << priv.size() << std::endl;
    k->extract_public(pub);
    std::cout << "test3 " << pub.size() << std::endl;
    std::string s1 = "";
    std::string s2 = "";
    for (std::size_t i = 0; i < priv.size(); i++)
    {
        //printf("%02x", priv[i]);
        //s1 += std::to_string((int)priv[i]) + ",";
        //s2 += std::to_string((int)pub[i]) + ","; 
    }
    std::cout << s1 << std::endl;
    std::cout << s2 << std::endl;


    std::vector<unsigned char> priv2;
    std::vector<unsigned char> pub2;

    Key* kk = new Key();
    bool test1 = kk->create_from_private(a, priv);
    kk->extract_private(priv2);

    Key* kkk = new Key();
    bool test2 = kkk->create_from_public(a, pub);
    kkk->extract_public(pub2);

    std::cout << "create " << test1 << " " << test2 << std::endl;

    test1 = true;
    for(int i=0;i<priv.size();i++)
    {
        if(priv[i]!=priv2[i])
        {
            test1 = false;
            break;
        }
    }

    test2 = true;
    for(int i=0;i<pub.size();i++)
    {
        if(pub[i]!=pub2[i])
        {
            test1 = false;
            break;
        }
    }
    std::cout << "extract " << test1 << " " << test2 << std::endl;

    //test signature
    std::vector<unsigned char> message = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<unsigned char> signed_message;
    test1 = kk->sign_data(message, signed_message);
    test2 = kk->verify_signature(message, signed_message);
    std::cout << "sign " << test1 << " " << test2 << std::endl;

    Key* k3 = new Key();
    k3->create(a);
    test2 = k3->verify_signature(message, signed_message);
    std::cout << "sign " << test1 << " " << test2 << std::endl;


    delete kk;
    delete kkk;
    delete k3;

    a = "ML-KEM-768";
    k3 = new Key();
    k3->create(a);
    delete k3;
    
    a = "ED25519";
    priv = {238,86,202,231,84,24,213,231,248,202,216,220,193,41,139,180,92,242,29,113,238,233,125,141,62,121,163,208,85,209,27,123};
    pub = {71,130,169,175,37,119,84,77,211,33,86,176,125,7,109,171,150,179,34,32,59,161,196,197,178,90,96,18,20,246,14,211};

    Database* db = new Database();
    db->connect("user.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE); //create if not exists
    db->run_query("CREATE TABLE IF NOT EXISTS keys (type TEXT NOT NULL, id INTEGER, key BLOB NOT NULL, date TEXT);", nullptr);
    //db->run_query("INSERT INTO keys (type, id, key, date) VALUES(?, ?, ?);", "tibt", "TestUser", priv.size(), priv.data(), "-");

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
                case PK_ERROR:
                {
                    std::string s;
                    packet->read_string(s);
                    std::cout << "[-]Received error: " << s << std::endl;
                    break;
                }
                case PK_LOGIN_CHALLENGE:
                {
                    std::cout << "[+]Received Challenge!" << std::endl;
                    std::vector<unsigned char> challenge;
                    bool status = packet->read_buffer(challenge);

                    //sign challenge
                    Key* kk = new Key();
                    kk->create_from_private(a, priv);

                    std::vector<unsigned char> signed_data;
                    status = kk->sign_data(challenge, signed_data);

                    Packet* newpacket = new Packet(-1, PK_LOGIN_CHALLENGE);
                    newpacket->append_buffer(signed_data);
                    connector->add_packet(newpacket);

                    delete kk;

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