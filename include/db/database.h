#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

#include <string>
#include <vector>

class Database
{
private:
    sqlite3* db;

public:
    Database();
    ~Database();

    bool connect(std::string name, int flags=SQLITE_OPEN_READWRITE);
    void disconnect();

    //data from last query
    std::vector<std::string> column_names;
    std::vector<int> column_datatypes; //datatype
    std::vector<std::vector<std::string>> values;

    bool run_query(std::string query);
    bool exists_table(std::string name);
    bool create_table(std::string name);
};

#endif