#ifndef SERVER_USER_H
#define SERVER_USER_H

#include <chrono>
#include <string>
#include <vector>

#include "crypto/key.h"

class User
{
private:
    int fd = -1;
    bool verified = false;
    std::string name;
    std::chrono::time_point<std::chrono::system_clock> time_conn;

    Key* key_verify = nullptr;

    std::chrono::time_point<std::chrono::system_clock> time_challenge;
    std::vector<unsigned char> challenge;
public:
    User(int fd, std::chrono::time_point<std::chrono::system_clock> time_conn);
    ~User();

    int get_fd() { return this->fd; }
    void set_verified() { this->verified = true; }
    bool is_verified() { return this->verified; }
    std::string get_name() { return this->name; }
    void set_name(std::string& s) { this->name = s; }

    void set_key(std::string& name, std::vector<unsigned char>& data);

    bool create_challenge(std::size_t length);
    std::vector<unsigned char>& get_challenge() { return this->challenge; }
    std::size_t get_challenge_size() { return this->challenge.size(); }
    bool check_challenge(std::vector<unsigned char>& signed_challenge, int64_t maxdiff=5000);
};

#endif