#include <iostream>
#include "crypto/ratchet.h"
#include "crypto/utilities.h"

Ratchet::Ratchet(const std::vector<unsigned char>& data) : secret(data)
{

}

Ratchet::~Ratchet()
{

}

//turn the ratchet one step
bool Ratchet::turn(const std::vector<unsigned char>& data)
{
    //append data to current secret
    this->secret.insert(this->secret.end(), data.begin(), data.end());
    std::vector<unsigned char> out; //buffer for getting the kdf output
    if(!kdf(secret, out, 64))
    {
        return false;
    }

    this->secret.clear();
    this->secret.insert(this->secret.end(), out.begin(), out.begin()+32);
    this->key.clear();
    this->key.insert(this->key.end(), out.begin()+32, out.begin()+64);

    this->iv.clear();
    this->iv.insert(this->iv.end(), out.begin()+64, out.end());

    return true;
}

/////////////////////////////////////////////////////////////////////////////////////
RatchetSession::RatchetSession(std::vector<unsigned char>& data, bool is_alice)
{
    this->is_alice = is_alice;
    this->root_ratchet = new Ratchet(data);

    std::vector<unsigned char> temp;
    if(is_alice)
    {
        this->root_ratchet->turn(temp);
        this->send_ratchet = new Ratchet(this->root_ratchet->get_key());
        this->root_ratchet->turn(temp);
        this->recv_ratchet = new Ratchet(this->root_ratchet->get_key());
    }
    else //Bob is the other way around
    {
        this->root_ratchet->turn(temp);
        this->recv_ratchet = new Ratchet(this->root_ratchet->get_key());
        this->root_ratchet->turn(temp);
        this->send_ratchet = new Ratchet(this->root_ratchet->get_key());
    }
}

RatchetSession::~RatchetSession()
{
    delete this->root_ratchet;
    delete this->send_ratchet;
    delete this->recv_ratchet;
}

bool RatchetSession::send()
{
    return this->send_ratchet->turn();
}

bool RatchetSession::recv()
{
    return this->recv_ratchet->turn();
}