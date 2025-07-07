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
    if(!kdf(temp, out, query_iv ? 76: 64)) //NOTE: we assume an iv of 12, however this might change in the future!
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

    std::vector<unsigned char> temp;
    if(is_alice)
    {
        this->root_chain.turn(temp);
        this->send_chain.initialize(this->root_chain.get_key());
        this->root_chain.turn(temp);
        this->root_chain.initialize(this->root_chain.get_key());
    }
    else //Bob is the other way around
    {
        this->root_chain.turn(temp);
        this->recv_chain.initialize(this->root_chain.get_key());
        this->root_chain.turn(temp);
        this->send_chain.initialize(this->root_chain.get_key());
    }
}

SymmetricRatchet::~SymmetricRatchet()
{

}

bool SymmetricRatchet::send() 
{ 
    return this->send_chain.turn(); 

}
bool SymmetricRatchet::recv() 
{
    return this->recv_chain.turn(); 
}

//////////////////////////////////////////////////////////////
DoubleRatchet::DoubleRatchet()
{
    this->key.create("X25519");
}

DoubleRatchet::DoubleRatchet(const std::vector<unsigned char>& data)
{
    this->key.create("X25519");
    this->root_chain.initialize(data);
}

DoubleRatchet::~DoubleRatchet()
{

}

void DoubleRatchet::initialize(const std::vector<unsigned char>& data)
{
    this->key.create("X25519");
}

void DoubleRatchet::step_dh(const std::vector<unsigned char>& data, bool query_iv)
{
    //perform dh
    Key bob = Key();
    bob.create_from_public("X25519", data);

    std::vector<unsigned char> shared_secret;
    dh(&this->key, &bob, shared_secret);

    this->root_chain.turn(shared_secret, query_iv);
    this->recv_chain.initialize(this->root_chain.get_key());

    //create new key and perform dh again
    dh(&this->key, &bob, shared_secret);
    this->root_chain.turn(shared_secret, query_iv);
    this->send_chain.initialize(this->root_chain.get_key());
}