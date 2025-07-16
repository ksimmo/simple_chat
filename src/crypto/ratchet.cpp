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
DoubleRatchet::DoubleRatchet()
{
}

DoubleRatchet::~DoubleRatchet()
{

}

bool DoubleRatchet::initialize_alice(const std::vector<unsigned char>& rootkey, const std::vector<unsigned char>& pubkey)
{
    this->self_key.create("X25519");
    this->remote_key.create_from_public("X25519", pubkey);

    this->root_chain.initialize(rootkey);

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
    this->self_key.create_from_private("X25519", privkey); //signed prekey

    this->root_chain.initialize(rootkey);

    //next step is to perform step_dh

    return true;
}

bool DoubleRatchet::step_dh(const std::vector<unsigned char>& pubkey)
{
    this->remote_key.create_from_public("X25519", pubkey);

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

bool DoubleRatchet::receive_message(Packet* packet, std::vector<unsigned char>& out)
{
    //ok first of all extract sending and receiving numbers
    std::size_t n;
    std::size_t pn;
    bool status = !packet->read(n);
    status |= !packet->read(pn);
    unsigned char contains_key;
    status |= !packet->read(contains_key);

    std::vector<unsigned char> key;
    if(contains_key)
        status != !packet->read_buffer(key);
    
    std::vector<unsigned char> cipher;
    status |= !packet->read_buffer(cipher);

    if(status) //ok something went wrong during parsing!
        return false;

    //check if we should use a skipped key

    if(contains_key)
    {
        std::size_t skipped = pn - this->get_recv_turns(); //missing in old chain

        //save keys for later decoding
        
        this->step_dh(key);
    }
    else
    {
        std::size_t skipped = n - this->get_recv_turns(); //missing in new chain
    }

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
    packet->append((std::size_t)1);
    packet->append((std::size_t)1);
    //TODO: check if we need to send our key to initiate a new dh ratchet step
    packet->append_byte(0); //does this message contain a dh key?
    packet->append_buffer(cipher);

    return true;
}