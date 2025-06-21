#include <iostream>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "server/user.h"

User::User(std::chrono::time_point<std::chrono::system_clock> conn_time) : time_conn(conn_time)
{
}

User::~User()
{
    if(this->key_verify!=nullptr)
        delete this->key_verify;
}

void User::set_key(int type, std::vector<unsigned char>& data)
{
    this->key_verify = new Key();
    if(!this->key_verify->create_from_public(type, data))
    {
        delete this->key_verify;
        this->key_verify = nullptr;
    }
}

std::vector<unsigned char>& User::create_challenge(std::size_t length)
{
    this->challenge.resize(length);
    if (RAND_bytes(this->challenge.data(), length) != 1) {
        std::cerr << "[-]Cannot create random challenge: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }
    
    this->time_challenge = std::chrono::system_clock::now();

    return this->challenge;
}

bool User::check_challenge(std::vector<unsigned char>& signed_challenge, int64_t maxdiff)
{
    if(this->key_verify==nullptr || this->challenge.size()==0)
        return false;

    bool status = this->key_verify->verify_signature(this->challenge, signed_challenge);

    std::chrono::time_point<std::chrono::system_clock> end = std::chrono::system_clock::now();

    int64_t difference = std::chrono::duration_cast<std::chrono::milliseconds>(end - this->time_challenge).count();
    if(difference>maxdiff)
    {
        std::cerr << "Answer to challenge took too long!" << std::endl;
        status = false; //rejected due to taking too long
    }

    return status;
}