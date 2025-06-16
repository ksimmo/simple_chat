#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

class Database
{
private:
    sqlite3* db;
public:
    Database();
    ~Database();

    bool connect(const char* name, int flags=SQLITE_OPEN_READWRITE);
    void disconnect();
};

#endif