#include <iostream>
#include <openssl/rand.h>

#include "server/user.h"

User::User(std::chrono::time_point<std::chrono::system_clock> conn_time) : time_conn(conn_time)
{
}

User::~User()
{
    if(this->verify_key!=nullptr)
        delete this->verify_key;

    if(this->challenge!=nullptr)
        delete[] this->challenge;
}

unsigned char* User::create_challenge(std::size_t length)
{
    this->challenge = new unsigned char[length];
    if (RAND_bytes(this->challenge, 32) != 1) {
        delete[] this->challenge;
        this->challenge = nullptr;
    }
    
    this->time_challenge = std::chrono::system_clock::now();

    return this->challenge;
}

bool User::check_challenge(unsigned char* signed_data, std::size_t length, int64_t maxdiff)
{
    if(this->verify_key==nullptr || this->challenge==nullptr)
        return false;

    bool status = this->verify_key->verify_signature(this->challenge, this->challenge_size, signed_data, length);

    std::chrono::time_point<std::chrono::system_clock> end = std::chrono::system_clock::now();

    int64_t difference = std::chrono::duration_cast<std::chrono::milliseconds>(end - this->time_challenge).count();
    if(difference>maxdiff)
    {
        std::cerr << "Answer to challenge took too long!" << std::endl;
        status = false; //rejected due to taking too long
    }

    return status;
}