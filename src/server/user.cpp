#include <iostream>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "server/user.h"

User::User(int fd) : fd(fd), key_verify()
{
    this->time_conn = std::chrono::system_clock::now();
}

User::~User()
{
}

bool User::set_key(const std::string& name, const std::vector<unsigned char>& data)
{
    return this->key_verify.create_from_public(name, data);
}

bool User::create_challenge(std::size_t length)
{
    bool status = true;
    this->challenge.resize(length);
    if (RAND_bytes(this->challenge.data(), length) != 1) {
        std::cerr << "[-]Cannot create random challenge: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        status = false;
    }
    
    this->time_challenge = std::chrono::system_clock::now();

    return status;
}

bool User::check_challenge(std::vector<unsigned char>& signed_challenge, int64_t maxdiff)
{
    if(!this->key_verify.is_initialized() || this->challenge.size()==0)
        return false;
        
    bool status = this->key_verify.verify_signature(this->challenge, signed_challenge);

    std::chrono::time_point<std::chrono::system_clock> end = std::chrono::system_clock::now();

    int64_t difference = std::chrono::duration_cast<std::chrono::milliseconds>(end - this->time_challenge).count();
    if(difference>maxdiff)
    {
        std::cerr << "Answer to challenge took too long!" << std::endl;
        status = false; //rejected due to taking too long
    }

    return status;
}