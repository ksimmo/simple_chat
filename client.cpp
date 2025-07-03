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

    bool alice = false; //is this client alice or bob (just for test case!)
    if(argc>1)
    {
        alice = true;
    }

    QCoreApplication app(argc, argv);
    signal(SIGINT, &quit_loop);
    initialize_socket();
    SSL_CTX* ctx = init_openssl();
    
    std::string a = "ED25519";
    //bob
    std::vector<unsigned char> priv = {238,86,202,231,84,24,213,231,248,202,216,220,193,41,139,180,92,242,29,113,238,233,125,141,62,121,163,208,85,209,27,123};
    std::vector<unsigned char> pub = {71,130,169,175,37,119,84,77,211,33,86,176,125,7,109,171,150,179,34,32,59,161,196,197,178,90,96,18,20,246,14,211};

    //alice
    std::vector<unsigned char> priv2 = {225,33,75,219,68,188,91,49,118,196,141,173,113,65,160,182,185,195,237,205,12,81,152,141,23,152,75,111,16,227,88,62};
    std::vector<unsigned char> pub2 = {242,166,74,118,251,209,138,140,15,177,96,237,234,0,148,242,120,50,97,254,145,4,18,93,218,239,245,215,175,44,197,202};

    //bobs prekeys
    std::vector<unsigned char> prekey_priv = {8,83,187,43,148,19,188,53,99,229,107,144,43,158,179,170,128,167,169,231,66,88,146,73,158,51,83,189,223,188,212,66};
    std::vector<unsigned char> prekey_pub = {58,77,177,71,18,83,130,156,204,19,166,43,156,242,109,19,120,85,32,154,154,129,143,6,173,80,127,29,222,216,9,94};

    std::vector<unsigned char> onetime_priv = {88,115,84,179,246,20,191,184,91,57,90,53,105,250,226,166,183,97,54,46,11,104,14,1,170,9,66,98,70,79,166,70};
    std::vector<unsigned char> onetime_pub = {171,47,165,177,245,20,57,109,110,195,226,118,168,96,230,119,250,129,93,148,28,103,14,173,215,245,232,129,136,225,128,33};

    Database* db = new Database();
    db->connect("user.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE); //create if not exists
    db->run_query("CREATE TABLE IF NOT EXISTS keys (type TEXT NOT NULL, id INTEGER, key BLOB NOT NULL, date TEXT);", nullptr);
    //db->run_query("INSERT INTO keys (type, id, key, date) VALUES(?, ?, ?);", "tibt", "TestUser", priv.size(), priv.data(), "-");

    //table for contacts
    db->run_query("CREATE TABLE IF NOT EXISTS contacts (type TEXT NOT NULL UNIQUE, key BLOB NOT NULL, key_type TEXT NOT NULL, last_online TEXT);", nullptr);

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
                    if(alice)
                        packet->append_string("TestUser2");
                    else
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
                    int type;
                    packet->read(type);
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
                    if(alice)
                        kk->create_from_private(a, priv2);
                    else
                        kk->create_from_private(a, priv);

                    std::vector<unsigned char> signed_data;
                    status = kk->sign_data(challenge, signed_data);

                    Packet* newpacket = new Packet(-1, PK_LOGIN_CHALLENGE);
                    newpacket->append_buffer(signed_data);
                    connector->add_packet(newpacket);

                    delete kk;

                    break;
                }
                case PK_LOGIN_SUCCESSFULL:
                {
                    std::cout << "[+] Login successfull!" << std::endl;
                    //now we can send all unsend messages and query if our contacts are online

                    //query online status
                    Packet* newpacket = new Packet(-1, PK_ONLINE_STATUS);
                    if(alice)
                        newpacket->append_string("TestUser");
                    else
                        newpacket->append_string("TestUser2");
                    connector->add_packet(newpacket);

                    break;
                }
                case PK_ONLINE_STATUS:
                {
                    std::string name;
                    packet->read_string(name);
                    char status;
                    packet->read(status);
                    std::cout << name << " online status: " << (bool)status << std::endl;

                    //ok upload keys
                    if(!alice)
                    {
                        //calculate prekey signature
                        Key* kk = new Key();
                        kk->create_from_private(a, priv);
                        std::vector<unsigned char> prekey_signature;
                        kk->sign_data(prekey_pub, prekey_signature);
                        delete kk;

                        //send signed prekey + signature
                        Packet* newpacket = new Packet(-1, PK_UPLOAD_KEYS);
                        newpacket->append_byte(1); //signed prekey
                        newpacket->append_buffer(prekey_pub);
                        newpacket->append_string("X25519");
                        newpacket->append_buffer(prekey_signature);
                        connector->add_packet(newpacket);

                        //also send onetime prekey
                        Packet* newpacket2 = new Packet(-1, PK_UPLOAD_KEYS);
                        newpacket2->append_byte(0); //signed prekey
                        newpacket2->append_buffer(onetime_pub);
                        newpacket2->append_string("X25519");
                        connector->add_packet(newpacket2);
                    }
                    else
                    {
                        Packet* newpacket = new Packet(-1, PK_USER_KEYS);
                        newpacket->append_string("TestUser");
                        connector->add_packet(newpacket);
                    }
                    break;
                }
                case PK_USER_KEYS:
                {
                    std::string name;
                    packet->read_string(name);

                    std::vector<unsigned char> idkey;
                    packet->read_buffer(idkey);
                    std::string id_type;
                    packet->read_string(id_type);
                    std::vector<unsigned char> prekey;
                    packet->read_buffer(prekey);
                    std::string prekey_type;
                    packet->read_string(prekey_type);
                    std::vector<unsigned char> signature;
                    packet->read_buffer(signature);

                    unsigned char byte;
                    packet->read(byte);

                    if(alice)
                    {
                       std::vector<unsigned char> secret;
                       std::vector<unsigned char> epkey;
                       std::vector<unsigned char> ot;
                       x3dh_alice(priv2, epkey, idkey, prekey, ot, signature, id_type, prekey_type, secret);

                        std::string temp;
                        for(int i=0;i<secret.size();i++)
                            temp += std::to_string((int)secret[i])+",";
                        std::cout << temp << std::endl;

                        //use AEAD scheme to encrypt both identity keys to 
                        std::vector<unsigned char> comb;
                        comb.insert(comb.end(), pub2.begin(), pub2.end()); //id pub alice
                        comb.insert(comb.end(), idkey.begin(), idkey.end()); //id pub bob
                        std::vector<unsigned char> iv;
                        create_iv(iv);
                        std::vector<unsigned char> tag;
                        std::vector<unsigned char> cipher;
                        aead_encrypt(secret, comb, cipher, iv, tag);

                        
                        //generate initial message
                        Packet* newpacket = new Packet(-1, PK_MSG);
                        newpacket->append_string("TestUser");
                        newpacket->append((std::size_t)0); //message number
                        newpacket->append_buffer(pub2);
                        newpacket->append_string(a);
                        newpacket->append_buffer(epkey);
                        newpacket->append_string(prekey_type);
                        //TODO: notify if and which onetime prekey we have used
                        newpacket->append_buffer(iv);
                        newpacket->append_buffer(tag);
                        newpacket->append_buffer(cipher);
                        connector->add_packet(newpacket);

                        std::cout << "Sending packet " << newpacket->get_length() << std::endl;
                    }
                    break;
                }
                case PK_MSG:
                {
                    std::string name;
                    packet->read_string(name);

                    std::cout << "received message from " << name << " length=" << packet->get_length() << std::endl;

                    std::size_t number;
                    packet->read(number);
                    if(number==0) //initial message
                    {
                        //get id key
                        std::vector<unsigned char> idkey;
                        packet->read_buffer(idkey);

                        std::string idtype;
                        packet->read_string(idtype);

                        //get ephermeal public key
                        std::vector<unsigned char> epkey;
                        packet->read_buffer(epkey);

                        std::string type;
                        packet->read_string(type);

                        //check if a onetime prekey was used


                        std::vector<unsigned char> secret;
                        std::vector<unsigned char> ot;
                        x3dh_bob(priv, prekey_priv, ot, idkey, epkey, idtype, type, secret);

                        std::string temp;
                        for(int i=0;i<secret.size();i++)
                            temp += std::to_string((int)secret[i])+",";
                        std::cout << temp << std::endl;

                        //use secret to decrypt initial message and verify if public keys match
                        std::vector<unsigned char> iv;
                        packet->read_buffer(iv);
                        std::vector<unsigned char> tag;
                        packet->read_buffer(tag);

                        std::vector<unsigned char> cipher;
                        packet->read_buffer(cipher);

                        std::vector<unsigned char> plain;
                        aead_decrypt(secret, plain, cipher, iv, tag);

                        //check if we got the secret right
                        std::vector<unsigned char> comb;
                        comb.insert(comb.end(), idkey.begin(), idkey.end()); //id pub alice
                        comb.insert(comb.end(), pub.begin(), pub.end()); //id pub bob

                        //compare
                        bool is_equal = true;
                        for(int i=0;i<comb.size();i++)
                        {
                            if(comb[i]!=plain[i])
                            {
                                is_equal = false;
                                break;
                            }
                        }

                        std::cout << "Cipher is equal: " << is_equal << std::endl;
                        if(!is_equal)
                        {
                            //abort creating chat with Alice
                        }

                    }
                    else
                    {
                        //ok perform double ratchet
                    }
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