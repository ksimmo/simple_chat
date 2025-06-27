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

                    //verify signature
                    Key* kk = new Key();
                    kk->create_from_public(id_type, idkey);

                    bool verified = kk->verify_signature(prekey, signature);
                    if(verified)
                        std::cout << "Prekey signature is valid!" << std::endl;
                    else
                    {
                        std::cout << "Prekey signature invalid!" << std::endl;
                    }

                    Key* k2 = convert_ed25519_to_x25519_public(kk); //needed for dh exchange

                    delete kk;

                    if(alice)
                    {
                        kk = new Key();
                        kk->create_from_public(prekey_type, prekey);

                        Key* ephemeral = new Key();
                        ephemeral->create(prekey_type);
                        std::vector<unsigned char> epkey; //needed for initial message
                        ephemeral->extract_public(epkey);

                        //convert alice identity key
                        Key* bla = new Key();
                        bla->create_from_private(a, priv2);
                        Key* conv = convert_ed25519_to_x25519_private(bla);
                        delete bla;

                        //calculate dh
                        std::vector<unsigned char> secret1;
                        std::vector<unsigned char> secret2;
                        std::vector<unsigned char> secret3;
                        dh(conv, kk, secret1); //signed prekey
                        dh(ephemeral, k2, secret2); //identity
                        dh(ephemeral, kk, secret3); //signed prekey
                        //one time key currently not supported

                        delete ephemeral;
                        delete kk;
                        delete conv;

                        //concatenate secrets
                        std::vector<unsigned char> secret_combined;
                        secret_combined.insert(secret_combined.end(), secret1.begin(), secret1.end());
                        secret_combined.insert(secret_combined.end(), secret2.begin(), secret2.end());
                        secret_combined.insert(secret_combined.end(), secret3.begin(), secret3.end());

                        std::vector<unsigned char> out_alice;
                        kdf(secret_combined, out_alice, 32);

                        std::string temp;
                        for(int i=0;i<out_alice.size();i++)
                            temp += std::to_string((int)out_alice[i])+",";
                        std::cout << temp << std::endl;

                        //use AEAD scheme to encrypt both identity keys to 

                        
                        //generate initial message
                        Packet* newpacket = new Packet(-1, PK_MSG);
                        newpacket->append_string("TestUser");
                        newpacket->append_byte(1); //initial message
                        newpacket->append_buffer(pub2);
                        newpacket->append_string(a);
                        newpacket->append_buffer(epkey);
                        newpacket->append_string(prekey_type);
                        connector->add_packet(newpacket);

                        std::cout << "Sending packet " << newpacket->get_length() << std::endl;
                    }
                    delete k2;
                    break;
                }
                case PK_MSG:
                {
                    std::string name;
                    packet->read_string(name);

                    std::cout << "received message from " << name << " length=" << packet->get_length() << std::endl;

                    unsigned char byte;
                    packet->read(byte);
                    if(byte)
                    {
                        //get id key
                        std::vector<unsigned char> idkey;
                        packet->read_buffer(idkey);

                        std::string idtype;
                        packet->read_string(idtype);
                        std::cout << "idkey size=" << idkey.size() << " type=" << idtype << std::endl;

                        //get ephermeal public key
                        std::vector<unsigned char> epkey;
                        packet->read_buffer(epkey);

                        std::string type;
                        packet->read_string(type);
                        std::cout << "epkey size=" << epkey.size() << " type=" << type << std::endl;

                        //perform dh
                        Key* bla = new Key();
                        bla->create_from_private(a, priv);
                        Key* kp = convert_ed25519_to_x25519_private(bla);
                        delete bla;

                        Key* ep = new Key();
                        ep->create_from_public(type, epkey);

                        Key* sig = new Key();
                        sig->create_from_private(type, prekey_priv);

                        Key* kkk = new Key();
                        kkk->create_from_public(idtype, idkey);

                        Key* x = convert_ed25519_to_x25519_public(kkk);
                        delete kkk;

                        //calculate dh
                        std::vector<unsigned char> secret1;
                        std::vector<unsigned char> secret2;
                        std::vector<unsigned char> secret3;
                        dh(sig, x, secret1); //this seems problematic
                        dh(kp, ep, secret2);
                        dh(sig, ep, secret3);

                        //concatenate secrets
                        std::vector<unsigned char> secret_combined;
                        secret_combined.insert(secret_combined.end(), secret1.begin(), secret1.end());
                        secret_combined.insert(secret_combined.end(), secret2.begin(), secret2.end());
                        secret_combined.insert(secret_combined.end(), secret3.begin(), secret3.end());

                        std::vector<unsigned char> out_alice;
                        kdf(secret_combined, out_alice, 32);

                        std::string temp;
                        for(int i=0;i<out_alice.size();i++)
                            temp += std::to_string((int)out_alice[i])+",";
                        std::cout << temp << std::endl;

                        delete ep;
                        delete sig;
                        delete x;

                        //use secret to decrypt initial message and verify if public keys match
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