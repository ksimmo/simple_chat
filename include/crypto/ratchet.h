#ifndef RATCHET_H
#define RATCHET_H

#include <unordered_map>

#include "key.h"
#include "net/packet.h"

enum RatchetMessageTypes {RMT_UNENCRYPTED,      //unencrypted message
                            RMT_ABORT,          //abort protocol
                            RMT_X3DH,           //performing x3dh
                            RMT_MSG,         //normal message
                        };

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
    std::size_t get_send_turns() { return this->send_chain.get_turns(); }
    std::size_t get_recv_turns() { return this->recv_chain.get_turns(); }

    void initialize(const std::vector<unsigned char>& data) { this->root_chain.initialize(data); };
    bool send(bool query_iv=false);
    bool recv(bool query_iv=false);
};

//Double Ratchet
class DoubleRatchet : public SymmetricRatchet
{
private:
    std::size_t max_skip;
    Key self_key;
    Key remote_key;

    std::size_t old_turns = 0;
    //keys are dh key and N and we store message key and
    std::unordered_map<std::pair<std::vector<unsigned char>, std::size_t>, std::pair<std::vector<unsigned char>,std::vector<unsigned char>>> skipped_keys;

    bool check_skipped_keys(const std::vector<unsigned char>& key, std::size_t n, const std::vector<unsigned char>& cipher, std::vector<unsigned char>& out);
    bool skip_keys(std::size_t n);
public:
    DoubleRatchet(std::size_t max_skip=1000);
    ~DoubleRatchet();

    const std::vector<unsigned char>& get_key() { return this->self_key.get_public(); } //only returns public key!

    bool initialize_alice(const std::vector<unsigned char>& rootkey, const std::vector<unsigned char>& pubkey);
    bool initialize_bob(const std::vector<unsigned char>& rootkey, const std::vector<unsigned char>& privkey);
    bool step_dh(const std::vector<unsigned char>& pubkey);
    bool receive_message(Packet* packet, std::vector<unsigned char>& out);
    bool send_message(Packet* packet, const std::vector<unsigned char>& msg);
};

#endif