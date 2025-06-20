#ifndef SERVER_USER_H
#define SERVER_USER_H

#include <chrono>

class User
{
private:
    bool verified = false;
    std::chrono::time_point<std::chrono::system_clock> conn_time;
public:
    User(std::chrono::time_point<std::chrono::system_clock> conn_time);
    ~User();

    bool is_verified() { return this->verified; }
    //void create_challenge();
};

#endif