#include <iostream>
#include "crypto/ratchet.h"
#include "crypto/utilities.h"

KDFChain::KDFChain()
{

}

KDFChain::KDFChain(const std::vector<unsigned char>& data) : secret(data)
{

}

KDFChain::~KDFChain()
{

}

void KDFChain::initialize(const std::vector<unsigned char>& data)
{
    this->num_turns = 0;
    this->secret.clear();
    this->secret.insert(this->secret.end(), data.begin(), data.end());
}

//turn the ratchet one step
bool KDFChain::turn(const std::vector<unsigned char>& data, bool query_iv)
{
    if(this->secret.size()==0)
    {
        std::cerr << "KDFChain is not initialized!" << std::endl;
        return false;
    }

    //append data to current secret
    std::vector<unsigned char> temp;
    temp.insert(temp.end(), this->secret.begin(), this->secret.end()); //copy that in case of a fail we have the unaltered secret
    temp.insert(temp.end(), data.begin(), data.end());
    std::vector<unsigned char> out; //buffer for getting the kdf output
    if(!kdf(temp, out, query_iv ? 80: 64)) //NOTE: we assume an iv of 12, however this might change in the future!
    {
        std::cerr << "[-]Ratchet turn failed!" << std::endl;
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
DoubleRatchet::DoubleRatchet(std::size_t max_skip) : max_skip(max_skip)
{
}

DoubleRatchet::~DoubleRatchet()
{

}

bool DoubleRatchet::initialize_alice(const std::vector<unsigned char>& rootkey, const std::vector<unsigned char>& pubkey)
{
    this->skipped_keys.clear();
    this->self_key.create("X25519");
    this->remote_key.create_from_public("X25519", pubkey);

    this->root_chain.initialize(rootkey);
    this->old_turns = 0;

    std::vector<unsigned char> shared_secret;
    if(!dh(&this->self_key, &this->remote_key, shared_secret))
    {
        return false;
    }

    //alice will send the first (initial) message
    this->root_chain.turn(shared_secret, false);
    this->send_chain.initialize(this->root_chain.get_key());

    return true;
}

bool DoubleRatchet::initialize_bob(const std::vector<unsigned char>& rootkey, const std::vector<unsigned char>& privkey)
{
    this->skipped_keys.clear();
    this->self_key.create_from_private("X25519", privkey); //signed prekey

    this->root_chain.initialize(rootkey);
    this->old_turns = 0;

    //next step is to perform step_dh using the key we additionally got from x3dh init message

    return true;
}

bool DoubleRatchet::step_dh(const std::vector<unsigned char>& pubkey)
{
    this->old_turns = this->get_send_turns(); //save state of current sending chain
    this->remote_key.create_from_public("X25519", pubkey); //generate key from received data

    //do dh exchange
    std::vector<unsigned char> shared_secret;
    dh(&this->self_key, &this->remote_key, shared_secret);

    this->root_chain.turn(shared_secret, false);
    this->recv_chain.initialize(this->root_chain.get_key());

    //create new key and perform dh again
    this->self_key.create("X25519");
    dh(&this->self_key, &this->remote_key, shared_secret);
    this->root_chain.turn(shared_secret, false);
    this->send_chain.initialize(this->root_chain.get_key());

    return true;
}

bool DoubleRatchet::check_skipped_keys(const std::vector<unsigned char>& key, std::size_t n, const std::vector<unsigned char>& cipher, std::vector<unsigned char>& out)
{
    //convert key
    std::string temp;
    temp.insert(temp.end(), (char*)key.data(), (char*)key.data()+key.size());
    temp.insert(temp.end(), (char*)&n, (char*)(&n+sizeof(std::size_t)));

    auto entry = this->skipped_keys.find(temp);
    if(entry!=this->skipped_keys.end()) //jup there is a key saved
    {
        //decode
        aead_decrypt(entry->second.first, out, cipher, entry->second.second);
        //remove entry
        this->skipped_keys.erase(entry);
        return true;
    }
    return false;
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
        std::string first;
        first.insert(first.end(), (char*)this->remote_key.get_public().data(), (char*)this->remote_key.get_public().data()+this->remote_key.get_public().size());
        std::size_t n = this->get_recv_turns();
        first.insert(first.end(), (char*)&n, (char*)(&n+sizeof(std::size_t)));

        this->skipped_keys.insert(std::make_pair(first, std::make_pair(this->get_recv_key(), this->get_recv_iv())));
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