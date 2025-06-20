#include "server/user.h"

User::User(std::chrono::time_point<std::chrono::system_clock> conn_time) : conn_time(conn_time)
{
}

User::~User()
{
}