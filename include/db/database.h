#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

#include <string>
#include <vector>
#include <mutex>

#include "entry.h"

class Database
{
private:
    sqlite3* db;
    std::mutex mutex;

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

    int num_affected_rows() { return sqlite3_changes(this->db); }
    void copy_values(std::vector<std::vector<DBEntry*>>& entries); //copy needs to be deleted //TODO: use smart pointers?

    //TODO: this is not good practice, find a better solution
    //call these before running a query and after processing the queried data only in a multithread usage
    void lock() { this->mutex.lock(); }
    void unlock() { this->mutex.unlock(); }
};

#endif