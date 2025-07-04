#ifndef RATCHET_H
#define RATCHET_H

#include "key.h"

enum RatchetMessageTypes {RMT_UNENCRYPTED,      //unencrypted message
                            RMT_ABORT,          //abort protocol
                            RMT_X3HD,           //performing x3hd
                            RMT_NORMAL,         //normal message
                            RMT_HEADER,         //message with header encryption
                        };

#pragma pack(push, 1) //make sure that the header is the same on all architectures and no padding occurs
struct RatchetHeader
{
    unsigned char type;
    std::size_t sending_number; //current number in sending chain N
    std::size_t message_keys; //number of messages in the previous chain PN
};
#pragma pack(pop)

//class for a KDF chain
class KDFChain
{
private:
    std::vector<unsigned char> secret;  //the chain key
    std::vector<unsigned char> key;     //the message_key -> can be stored
    std::vector<unsigned char> iv;
    std::size_t num_turns = 0;
public:
    KDFChain();
    KDFChain(const std::vector<unsigned char>& data);
    ~KDFChain();
    void initialize(const std::vector<unsigned char>& data);
    bool turn(const std::vector<unsigned char>& data={}, bool query_iv=false);

    const std::vector<unsigned char>& get_key() { return this->key; }
    const std::vector<unsigned char>& get_iv() { return this->iv; }
    std::size_t get_turns() { return this->num_turns; }

};

//////////////////////////////////////////////////////////////

//class for performing a symmetric ratchet
class SymmetricRatchet
{
protected:
    bool is_alice = true;
    KDFChain root_chain;
    KDFChain send_chain;
    KDFChain recv_chain;
public:
    SymmetricRatchet();
    SymmetricRatchet(std::vector<unsigned char>& rootkey, bool is_alice=true);
    ~SymmetricRatchet();

    const std::vector<unsigned char>& get_send_key() { return this->send_chain.get_key(); }
    const std::vector<unsigned char>& get_send_iv() { return this->send_chain.get_iv(); }
    const std::vector<unsigned char>& get_recv_key() { return this->recv_chain.get_key(); }
    const std::vector<unsigned char>& get_recv_iv() { return this->recv_chain.get_iv(); }

    void initialize(const std::vector<unsigned char>& data) { this->root_chain.initialize(data); };
    bool send();
    bool recv();
};

//Double Ratchet
class DoubleRatchet : public SymmetricRatchet
{
private:
    Key key;
public:
    DoubleRatchet();
    DoubleRatchet(const std::vector<unsigned char>& rootkey);
    ~DoubleRatchet();

    const std::vector<unsigned char>& get_key() { return this->key.get_public(); } //only returns public key!

    void initialize(const std::vector<unsigned char>& data);
    void step_dh(const std::vector<unsigned char>& data, bool query_iv=false);
    //handle_message()
};

#endif