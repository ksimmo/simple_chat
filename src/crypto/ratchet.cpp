#include "logger.h"
#include "crypto/ratchet.h"
#include "crypto/utilities.h"

KDFChain::KDFChain()
{

}

KDFChain::KDFChain(const std::vector<unsigned char>& data, std::size_t num_turns) : secret(data), num_turns(num_turns)
{

}

KDFChain::~KDFChain()
{

}

void KDFChain::initialize(const std::vector<unsigned char>& data, std::size_t num_turns)
{
    this->num_turns = num_turns;
    this->secret.clear();
    this->secret.insert(this->secret.end(), data.begin(), data.end());
}

//turn the ratchet one step
bool KDFChain::turn(const std::vector<unsigned char>& data, bool query_iv)
{
    Logger& logger = Logger::instance();
    if(this->secret.size()==0)
    {
        logger << LogLevel::ERROR << "KDFChain is not initialized!" << LogEnd();
        return false;
    }

    //append data to current secret
    std::vector<unsigned char> temp;
    temp.insert(temp.end(), this->secret.begin(), this->secret.end()); //copy that in case of a fail we have the unaltered secret
    temp.insert(temp.end(), data.begin(), data.end());
    std::vector<unsigned char> out; //buffer for getting the kdf output
    if(!kdf(temp, out, query_iv ? 80: 64)) //NOTE: we assume an iv of 12, however this might change in the future!
    {
        logger << LogLevel::ERROR << "Ratchet turn failed!" << LogEnd();
        return false;
    }

    this->secret.clear();
    this->secret.insert(this->secret.end(), out.begin(), out.begin()+32); //set new secret
    this->key.clear();
    this->key.insert(this->key.end(), out.begin()+32, out.begin()+64);

    this->iv.clear();
    if(query_iv)
        this->iv.insert(this->iv.end(), out.begin()+64, out.end());

    this->num_turns++;

    return true;
}

/////////////////////////////////////////////////////////////////////////////////////
SymmetricRatchet::SymmetricRatchet()
{

}

SymmetricRatchet::SymmetricRatchet(std::vector<unsigned char>& rootkey, bool is_alice) : root_chain(rootkey)
{
    this->is_alice = is_alice;

    this->root_chain.initialize(rootkey);
    if(is_alice)
    {
        this->root_chain.turn({});
        this->send_chain.initialize(this->root_chain.get_key());
        this->root_chain.turn({});
        this->recv_chain.initialize(this->root_chain.get_key());
    }
    else //Bob is the other way around
    {
        this->root_chain.turn({});
        this->recv_chain.initialize(this->root_chain.get_key());
        this->root_chain.turn({});
        this->send_chain.initialize(this->root_chain.get_key());
    }
}

SymmetricRatchet::~SymmetricRatchet()
{

}

bool SymmetricRatchet::send(bool query_iv) 
{ 
    return this->send_chain.turn({}, query_iv); 

}
bool SymmetricRatchet::recv(bool query_iv) 
{
    return this->recv_chain.turn({}, query_iv); 
}

//////////////////////////////////////////////////////////////
DoubleRatchet::DoubleRatchet(Database* db, std::size_t max_skip) : db(db), max_skip(max_skip)
{
}

DoubleRatchet::~DoubleRatchet()
{
    this->save_state();
}

bool DoubleRatchet::initialize_alice(const std::vector<unsigned char>& rootkey, const std::vector<unsigned char>& pubkey, const std::string& name, const std::string& key_type)
{
    this->name = name;
    this->key_type = key_type;
    this->skipped_keys.clear();
    this->self_key.create(this->key_type);
    this->remote_key.create_from_public(this->key_type, pubkey);

    this->root_chain.initialize(rootkey);
    this->old_turns = 0;

    std::vector<unsigned char> shared_secret;
    if(!dh(this->self_key, this->remote_key, shared_secret))
    {
        return false;
    }

    //alice will send the first (initial) message
    this->root_chain.turn(shared_secret, false);
    this->send_chain.initialize(this->root_chain.get_key());

    //create table for skipped messages
    db->lock();
    //name: dr=double rachet sm=skipped messages
    db->run_query("CREATE TABLE IF NOT EXISTS dr_"+name+"_sm (dhkey BLOB NOT NULL, n INTEGER NOT NULL, msgkey BLOB NOT NULL, iv BLOB NOT NULL);", nullptr);
    db->unlock();

    return true;
}

bool DoubleRatchet::initialize_bob(const std::vector<unsigned char>& rootkey, const std::vector<unsigned char>& privkey, const std::string& name, const std::string& key_type)
{
    this->name = name;
    this->key_type = key_type;
    this->skipped_keys.clear();
    this->self_key.create_from_private(this->key_type, privkey); //signed prekey

    this->root_chain.initialize(rootkey);
    this->old_turns = 0;

    //next step is to perform step_dh using the key we additionally got from x3dh init message

    //create table
    db->lock();
    //name: dr=double ratchet sm=skipped messages
    db->run_query("CREATE TABLE IF NOT EXISTS dr_"+name+"_sm (dhkey BLOB NOT NULL, n INTEGER NOT NULL, msgkey BLOB NOT NULL, iv BLOB NOT NULL);", nullptr);
    db->unlock();

    return true;
}

bool DoubleRatchet::step_dh(const std::vector<unsigned char>& pubkey)
{
    this->old_turns = this->get_send_turns(); //save state of current sending chain
    this->remote_key.create_from_public(this->key_type, pubkey); //generate key from received data

    //do dh exchange
    std::vector<unsigned char> shared_secret;
    dh(this->self_key, this->remote_key, shared_secret);

    this->root_chain.turn(shared_secret, false);
    this->recv_chain.initialize(this->root_chain.get_key());

    //create new key and perform dh again
    this->self_key.create(this->key_type);
    dh(this->self_key, this->remote_key, shared_secret);
    this->root_chain.turn(shared_secret, false);
    this->send_chain.initialize(this->root_chain.get_key());

    return true;
}

bool DoubleRatchet::check_skipped_keys(const std::vector<unsigned char>& key, std::size_t n, const std::vector<unsigned char>& cipher, std::vector<unsigned char>& out)
{
    db->lock();
    db->run_query("SELECT * FROM dr_"+this->name+"_sm WHERE dhkey=? AND n=?;", "bi", key.size(), key.data(), (int)n);

    bool result = false;
    if(db->values.size()==1)
    {
        aead_decrypt(db->values[0][2]->get_buffer(), out, cipher, db->values[0][3]->get_buffer()); //key and iv
        //remove this entry
        db->run_query("DELETE FROM dr_"+this->name+"_sm WHERE dhkey=? AND n=?;", "bi", key.size(), key.data(), (int)n);
        result = true;
    }
    db->unlock();

    return result;
}

bool DoubleRatchet::skip_keys(std::size_t until)
{
    if(!this->recv_chain.is_initialized()) //if chain is not initialized we cannot skip keys! (only happens once when Bob creates DR object)
        return false;

    if(this->get_recv_turns()+this->max_skip<until) //ok we skipped to much messages
        return false;

    while (this->get_recv_turns()<until)
    {
        this->recv(true);

        //save key for later usage
        db->lock();
        db->run_query("INSERT INTO dr_"+this->name+"_sm(dhkey,n,msgkey,iv) VALUES(?,?,?,?);", "bibb",this->remote_key.get_public().size(), this->remote_key.get_public().data(),
                    this->get_recv_turns(), this->get_recv_key().size(), this->get_recv_key().data(),
                    this->get_recv_iv().size(), this->get_recv_iv().data());
        db->unlock();
    }
    
    return true;
}

bool DoubleRatchet::receive_message(Packet* packet, std::vector<unsigned char>& out)
{
    //ok first of all extract sending and receiving numbers
    std::vector<unsigned char> key;
    bool status = !packet->read_buffer(key);
    std::size_t n;
    std::size_t pn;
    status |= !packet->read(n);
    status |= !packet->read(pn);
    
    std::vector<unsigned char> cipher;
    status |= !packet->read_buffer(cipher);

    if(status) //ok something went wrong during parsing!
        return false;

    //see if a skipped message key works
    status = this->check_skipped_keys(key, n, cipher, out);
    if(status)
        return true;

    //check if the key matches current used remote dh key
    bool is_key_new = (key!=this->remote_key.get_public());

    if(is_key_new)
    {
        //save keys for later decoding if necessary
        this->skip_keys(pn);
        this->step_dh(key);
    }
    
    this->skip_keys(n);

    //otherwise advance the symmetric ratchet
    this->recv(true);

    //decrypt
    aead_decrypt(this->get_recv_key(), out, cipher, this->get_recv_iv());

    return true;
}

bool DoubleRatchet::send_message(Packet* packet, const std::vector<unsigned char>& msg)
{
    this->send(true);  //perform a symmetric step on sending chain

    //encrypt message
    std::vector<unsigned char> cipher;
    aead_encrypt(this->get_send_key(), msg, cipher, this->get_send_iv());

    //create packet (we assume the raw, empty packet is created outside this function and already contains receiver)
    packet->append_byte(RMT_MSG);
    packet->append_buffer(this->self_key.get_public()); //always append current dh public key
    packet->append((std::size_t)this->get_send_turns()-1); //subtract 1 as we already increased the counter
    packet->append((std::size_t)this->old_turns);
    packet->append_buffer(cipher);

    return true;
}

void DoubleRatchet::save_state()
{
    if(this->db==nullptr)
        return;

    //update dr parameters in db
    db->lock();
    db->run_query("INSERT INTO dr_params(name,key_type,root_secret,send_secret,recv_secret,send_turns,recv_turns,old_turns,self_key,remote_key) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET key_type=excluded.key_type, root_secret=excluded.root_secret, send_secret=excluded.send_secret, recv_secret=excluded.recv_secret, send_turns=excluded.send_turns, recv_turns=excluded.recv_turns, old_turns=excluded.old_turns, self_key=excluded.self_key, remote_key=excluded.remote_key;", 
        "ssbbbiiibb", this->name.length(), this->name.c_str(), this->key_type.length(), this->key_type.c_str(), this->root_chain.get_hidden().size(), this->root_chain.get_hidden().data(), this->send_chain.get_hidden().size(), this->send_chain.get_hidden().data(),
        this->recv_chain.get_hidden().size(), this->recv_chain.get_hidden().data(), this->send_chain.get_turns(), this->recv_chain.get_turns(), this->old_turns,
        this->self_key.get_private().size(), this->self_key.get_private().data(), this->remote_key.get_public().size(), this->remote_key.get_public().data());
    db->unlock();
}

void DoubleRatchet::load_state(const std::vector<DBEntry*>& values)
{
    values[0]->get_string(this->name);
    values[1]->get_string(this->key_type);
    this->root_chain.initialize(values[2]->get_buffer()); //for root chain we do not care about num_turns
    this->send_chain.initialize(values[3]->get_buffer(), *((int*)values[5]->get_data()));
    this->recv_chain.initialize(values[4]->get_buffer(), *((int*)values[6]->get_data()));
    this->old_turns = *((int*)values[7]->get_data());

    this->self_key.create_from_private(this->key_type, values[8]->get_buffer());
    this->remote_key.create_from_public(this->key_type, values[9]->get_buffer());
}