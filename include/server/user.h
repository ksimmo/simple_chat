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

    Key key_verify;

    std::chrono::time_point<std::chrono::system_clock> time_challenge;
    std::vector<unsigned char> challenge;
public:
    User(int fd);
    ~User();

    int get_fd() { return this->fd; }
    void set_verified() { this->verified = true; }
    bool is_verified() { return this->verified; }
    std::string get_name() { return this->name; }
    std::chrono::time_point<std::chrono::system_clock> get_time_conn() { return this->time_conn; }

    void set_name(std::string& s) { this->name = s; }

    bool set_key(const std::string& name, const std::vector<unsigned char>& data);

    bool create_challenge(std::size_t length);
    const std::vector<unsigned char>& get_challenge() { return this->challenge; }
    std::size_t get_challenge_size() { return this->challenge.size(); }
    bool check_challenge(std::vector<unsigned char>& signed_challenge, int64_t maxdiff=5000);
};

#endif