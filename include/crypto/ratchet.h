#ifndef RATCHET_H
#define RATCHET_H

#include "key.h"

//class for a symmetric Ratchet (KDF chain)
class Ratchet
{
private:
    std::vector<unsigned char> secret;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
public:
    Ratchet(const std::vector<unsigned char>& data);
    ~Ratchet();
    bool turn(const std::vector<unsigned char>& data={});

    const std::vector<unsigned char>& get_key() { return this->key; }
    const std::vector<unsigned char>& get_iv() { return this->iv; }

};

//DhRatchet

//////////////////////////////////////////////////////////////

//class for handling multiple ratchets in a session
class RatchetSession
{
private:
    bool is_alice = true;
    Ratchet* root_ratchet; //only used to initialize send and receive ratchet
    Ratchet* send_ratchet;
    Ratchet* recv_ratchet;
public:
    RatchetSession(std::vector<unsigned char>& secret, bool is_alice=true);
    ~RatchetSession();

    bool send();
    bool recv();

    const std::vector<unsigned char>& get_send_key() { return this->send_ratchet->get_key(); }
    const std::vector<unsigned char>& get_send_iv() { return this->send_ratchet->get_iv(); }
    const std::vector<unsigned char>& get_recv_key() { return this->recv_ratchet->get_key(); }
    const std::vector<unsigned char>& get_recv_iv() { return this->recv_ratchet->get_iv(); }
};

//Double Ratchet

#endif