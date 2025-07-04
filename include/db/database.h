#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

#include <string>
#include <vector>

#include "entry.h"

class Database
{
private:
    sqlite3* db;

public:
    Database();
    ~Database();

    bool connect(const std::string& name, int flags=SQLITE_OPEN_READWRITE);
    void disconnect();

    //data from last query
    std::vector<std::string> column_names;
    std::vector<std::vector<DBEntry*>> values;

    bool run_query(const std::string& query, const char* fmt, ...);
    bool exists_table(const std::string& name);
};

#endif