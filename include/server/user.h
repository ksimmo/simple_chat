#ifndef SERVER_USER_H
#define SERVER_USER_H

#include <chrono>
#include <string>
#include <vector>

#include "crypto/key.h"

class User
{
private:
    bool verified = false;
    std::string name;
    std::chrono::time_point<std::chrono::system_clock> time_conn;

    Key* verify_key = nullptr;

    std::chrono::time_point<std::chrono::system_clock> time_challenge;
    unsigned char* challenge = nullptr;
    std::size_t challenge_size = 0;
public:
    User(std::chrono::time_point<std::chrono::system_clock> time_conn);
    ~User();

    bool is_verified() { return this->verified; }
    std::string get_name() { return this->name; }
    void set_name(std::string& s) { this->name = s; }

    unsigned char* create_challenge(std::size_t length);
    unsigned char* get_challenge() { return this->challenge; }
    std::size_t get_challenge_size() { return this->challenge_size; }
    bool check_challenge(unsigned char* signed_data, std::size_t length, int64_t maxdiff=5000);
};

#endif