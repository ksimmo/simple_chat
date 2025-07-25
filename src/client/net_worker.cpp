#include <iostream>
#include <QtCore/QCoreApplication>
#include <QThread>

#include "logger.h"
#include "client/net_worker.h"


//bobs prekeys
std::vector<unsigned char> prekey_priv = {8,83,187,43,148,19,188,53,99,229,107,144,43,158,179,170,128,167,169,231,66,88,146,73,158,51,83,189,223,188,212,66};
std::vector<unsigned char> prekey_pub = {58,77,177,71,18,83,130,156,204,19,166,43,156,242,109,19,120,85,32,154,154,129,143,6,173,80,127,29,222,216,9,94};

std::vector<unsigned char> onetime_priv = {88,115,84,179,246,20,191,184,91,57,90,53,105,250,226,166,183,97,54,46,11,104,14,1,170,9,66,98,70,79,166,70};
std::vector<unsigned char> onetime_pub = {171,47,165,177,245,20,57,109,110,195,226,118,168,96,230,119,250,129,93,148,28,103,14,173,215,245,232,129,136,225,128,33};


NetWorker::NetWorker(QObject* parent, Connector* connector, Database* db, bool is_alice) : connector(connector), db(db)
{
    this->alice = is_alice;

    //load double ratchet information for existing conversations
    
    db->run_query("SELECT * FROM dr_params;", nullptr);
    for(std::size_t i=0;i<db->values.size();i++)
    {
        //DoubleRatchet* dr = new DoubleRatchet(db);
        //dr->load_state(db->values[i]);

        std::string name;
        db->values[i][0]->get_string(name);
        //this->ratchets.insert(std::make_pair(name, dr)); //TODO: uncomment for normal use!
        std::cout << "Found state of DR for " << name << std::endl;
    }
}

NetWorker::~NetWorker()
{
    //delete
    for(auto it=this->ratchets.begin();it!=this->ratchets.end();it++)
    {   
        if(it->second!=nullptr)
            delete it->second;
    }
    this->ratchets.clear();
}

void NetWorker::process()
{
    //initialize connector
    this->is_active = true;
    while(this->is_active)
    {
        if(this->connector->is_initialized())
        {
            this->connector->step(100);
        }
        else
            //wait a bit
            QThread::msleep(100);
        this->process_events();
        this->process_packets();
        QCoreApplication::processEvents();
    }
}

void NetWorker::connect(std::string host, int port, const std::string& name, const std::string& key_type, const std::vector<unsigned char>& key_priv)
{
    //initialize connector
    this->user_name.clear();
    this->user_name.insert(this->user_name.end(), name.begin(), name.end());

    this->key_identity.create_from_private(key_type, key_priv);

    this->is_connected = this->connector->initialize(CONN_CLIENT, host, port, 100);
}

void NetWorker::disconnect()
{
    this->is_connected = false;
    this->user_name.clear();
    
    this->connector->shutdown();
}

void NetWorker::stop()
{
    this->disconnect();
    this->is_active = false;
}

void NetWorker::request_online_status(std::string name)
{
    Packet* newpacket = new Packet(-1, PK_ONLINE_STATUS);
    newpacket->append_string(name);
    connector->add_packet(newpacket);
}

void NetWorker::request_user_keys(std::string name)
{
    if(this->connector->is_initialized())
    {
        Packet* newpacket = new Packet(-1, PK_USER_KEYS);
        newpacket->append_string(name);
        this->connector->add_packet(newpacket);
    }
}

void NetWorker::update_prekey()
{

}

void NetWorker::update_otkeys(std::size_t num)
{

}

//////////////////////////////////////////////////
void NetWorker::process_events()
{
    Logger& logger = Logger::instance();
    ConnectorEvent ev = connector->pop_event();
    while (ev.ev!=PE_NONE) //no need to check for fd
    {
        switch (ev.ev)
        {
            case PE_HANDSHAKE_FINISHED:
            {
                logger << LogLevel::INFO << "Sending login ..." << LogEnd();
                Packet* packet = new Packet(-1, PK_LOGIN);
                packet->append_string(this->user_name);
                connector->add_packet(packet);
                break;
            }
            case PE_DISCONNECTED:
            {
                logger << LogLevel::INFO << "Disconnected!" << LogEnd();
                break;
            }
        }
        ev = connector->pop_event();
    }
}

void NetWorker::process_packets()
{
    Logger& logger = Logger::instance();
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
                logger << LogLevel::ERROR << "Received error from server: " << s << LogEnd();
                break;
            }
            case PK_LOGIN_CHALLENGE:
            {
                //we received the login challenge -> answer
                logger << LogLevel::INFO << "Received Challenge!" << LogEnd();
                std::vector<unsigned char> challenge;
                bool status = packet->read_buffer(challenge);

                //sign challenge
                std::vector<unsigned char> signed_data;
                status = this->key_identity.sign_data(challenge, signed_data);

                Packet* newpacket = new Packet(-1, PK_LOGIN_CHALLENGE);
                newpacket->append_buffer(signed_data);
                connector->add_packet(newpacket);

                break;
            }
            case PK_LOGIN_SUCCESSFULL:
            {
                logger << LogLevel::INFO << "Login successfull!" << LogEnd();
                //now we can send all unsend messages and query if our contacts are online

                //query online status (test)
                if(this->alice)
                    this->request_online_status("TestUser");
                else
                    this->request_online_status("TestUser2");

                break;
            }
            case PK_ONLINE_STATUS:
            {
                std::string name;
                packet->read_string(name);
                char status;
                packet->read(status);
                std::cout << name << " online status: " << (bool)status << std::endl;

                emit online_status_recevied(name, (bool)status); //notify GUI

                //ok upload keys (test)
                if(!this->alice)
                {
                    //TODO: also update keys in database
                    //calculate prekey signature
                    std::vector<unsigned char> prekey_signature;
                    this->key_identity.sign_data(prekey_pub, prekey_signature);

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
                    newpacket2->append((std::size_t)1); //we could theoretically send more
                    newpacket2->append_buffer(onetime_pub);
                    newpacket2->append_string("X25519");
                    connector->add_packet(newpacket2);
                }
                else
                {
                    this->request_user_keys("TestUser");
                }
                break;
            }
            case PK_UPLOAD_KEYS:
            {
                unsigned char update_prekey;
                packet->read(update_prekey);
                std::size_t num_keys;
                packet->read(num_keys);

                if(update_prekey)
                {
                    logger << LogLevel::INFO << "Server requested to update/upload signed prekey!" << LogEnd();
                    this->update_prekey();
                }
                if(num_keys>0)
                {
                    logger << "Server requested to upload onetime keys: " << num_keys << LogEnd(); 
                    this->update_otkeys(num_keys);
                }

                //ok create and upload onetime keys
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

                std::vector<unsigned char> otkey;
                if(byte==1)
                    packet->read_buffer(otkey);

                if(this->alice)
                {
                    std::vector<unsigned char> secret;
                    std::vector<unsigned char> epkey;
                    x3dh_alice(this->key_identity.get_private(), epkey, idkey, prekey, otkey, signature, id_type, prekey_type, secret);

                    //ok create double ratchet
                    DoubleRatchet* dr = new DoubleRatchet(db);
                    dr->initialize_alice(secret, prekey, name, "X25519");
                    //encrypt initial message
                    this->ratchets.insert(std::make_pair(name, dr)); //currently only 1to1 messages are supported (no groups)

                    //use AEAD scheme to encrypt both identity keys to 
                    std::vector<unsigned char> comb;
                    comb.insert(comb.end(), this->key_identity.get_public().begin(), this->key_identity.get_public().end()); //id pub alice
                    comb.insert(comb.end(), idkey.begin(), idkey.end()); //id pub bob
                    //std::vector<unsigned char> iv;
                    //create_iv(iv);
                    //std::vector<unsigned char> cipher;
                    //aead_encrypt(secret, comb, cipher, iv);
                    //aead_encrypt(secret, dr->get_key(), cipher, iv);

                    
                    //generate initial message
                    Packet* newpacket = new Packet(-1, PK_MSG);
                    newpacket->append_string("TestUser");
                    newpacket->append_byte(RMT_X3DH); //message number
                    newpacket->append_buffer(this->key_identity.get_public());
                    newpacket->append_string("ED25519");
                    newpacket->append_buffer(epkey);
                    newpacket->append_string(prekey_type);
                    newpacket->append_byte(byte); //notify if we have used an ot key
                    newpacket->append_buffer(otkey);
                    //newpacket->append_buffer(iv);
                    //newpacket->append_buffer(cipher);
                    //initial double ratchet message: both identity keys
                    newpacket->append_string("X25519"); //the key type we use for double ratchet
                    dr->send_message(newpacket, comb);
                    connector->add_packet(newpacket);
                }
                break;
            }
            case PK_MSG:
            {
                std::string name;
                packet->read_string(name);

                //TODO: add some information if this is a group or not

                //TODO: check for blacklist

                std::vector<unsigned char> msg;
                unsigned char type;
                packet->read(type);
                if(type==RMT_UNENCRYPTED)
                {
                    packet->read_remaining(msg);
                }
                else if(type==RMT_ABORT)
                {
                    //remove ratchet from database and clear current instance
                    auto entry = this->ratchets.find(name);
                    this->db->lock();
                    this->db->run_query("DELETE FROM dr_params WHERE name=?;", "s", name.c_str());
                    this->db->unlock();
                    if(entry!=this->ratchets.end()) //ok this ratchet exists
                    {
                        //TODO: save some information, notify GUI, ...
                        //close this conversation for ever
                        delete entry->second;
                        this->ratchets.erase(entry);
                    }

                }
                else if(type==RMT_X3DH) //initial message
                {
                    //TODO: if dr is already established -> ignore or overwrite session?

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

                    std::vector<unsigned char> otkey;
                    unsigned char byte;
                    packet->read(byte);

                    if(byte)
                    {
                        packet->read_buffer(otkey);
                        //check if we have a matching private key
                        otkey.clear();
                        //in this test case we have one -> TODO: search in db
                        otkey.insert(otkey.begin(), onetime_priv.begin(), onetime_priv.end());
                    }

                    std::string dr_keytype;
                    packet->read_string(dr_keytype);

                    logger << LogLevel::INFO << "Received X3DH initialisation from " << name << "!" << LogEnd();


                    std::vector<unsigned char> secret;
                    x3dh_bob(this->key_identity.get_private(), prekey_priv, otkey, idkey, epkey, idtype, type, secret);

                    //use secret to decrypt initial message and verify if public keys match
                    //std::vector<unsigned char> iv;
                    //packet->read_buffer(iv);

                    //std::vector<unsigned char> cipher;
                    //packet->read_buffer(cipher);

                    //std::vector<unsigned char> plain;
                    //aead_decrypt(secret, plain, cipher, iv);

                    //ok create a new Ratchet
                    DoubleRatchet* dr = new DoubleRatchet(db);
                    dr->initialize_bob(secret, prekey_priv, name, dr_keytype);
                    this->ratchets.insert(std::make_pair(name, dr));

                    //check if initial message matches
                    unsigned char msg_type; //parse away msg type byte, as for initial message it is always RMT_MSG
                    packet->read(msg_type);
                    std::vector<unsigned char> plain;
                    dr->receive_message(packet, plain);

                    //check if we got the secret right
                    std::vector<unsigned char> comb;
                    comb.insert(comb.end(), idkey.begin(), idkey.end()); //id pub alice
                    comb.insert(comb.end(), this->key_identity.get_public().begin(), this->key_identity.get_public().end()); //id pub bob

                    //compare
                    bool is_equal = (comb==plain);

                    if(!is_equal)
                    {
                        logger << LogLevel::INFO << "X3DH handshake with " << name << " not successfull!" << LogEnd();
                        //abort creating chat with Alice
                        Packet* newpacket = new Packet(-1, PK_MSG);
                        newpacket->append_string(name);
                        newpacket->append_byte(RMT_ABORT);
                        //TODO: maybe append an error message here
                        connector->add_packet(newpacket);
                    }
                    else
                    {
                        logger << LogLevel::INFO << "X3DH handshake with " << name << " successfull!" << LogEnd();
                        Packet* newpacket = new Packet(-1, PK_MSG);
                        newpacket->append_string(name);
                        std::vector<unsigned char> test = {'h', 'e', 'l', 'l', 'o', '!'};
                        dr->send_message(newpacket,test);
                        connector->add_packet(newpacket);
                    }
                }
                else
                {
                    //ok encrypt message first
                    auto entry = this->ratchets.find(name);
                    if(entry!=this->ratchets.end())
                    {
                        entry->second->receive_message(packet, msg);
                        std::cout << name << ":";
                        for(auto i=0;i<msg.size();i++)
                            std::cout << (char)msg[i];
                        std::cout << std::endl; //test case: here should come hello!
                    }
                    else
                    {
                        //we do not have a valid ratchet for that user -> do handshake first or delete conversation!
                    }
                }

                //process message in client
                if(msg.size()>0)
                    emit message_received(name, msg);

                break;
            }
        }
        delete packet;
        packet = connector->pop_packet();
    }
}