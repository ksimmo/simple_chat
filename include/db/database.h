#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

class Database
{
private:
    sqlite3* db;
    static int callback(void* unused, int argc, char** argv, char** col_name);
public:
    Database();
    ~Database();

    bool connect(const char* name, int flags=SQLITE_OPEN_READWRITE);
    void disconnect();

    bool create_table(const char* name);
};

#endif