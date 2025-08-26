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

    //TODO: give the result matrix via reference, so we can directly copy in it (->get rid of external mutex handling!)
    bool run_query(const std::string& query, std::vector<std::vector<DBEntry>>& results, const char* fmt, ...);
    bool exists_table(const std::string& name);

    int num_affected_rows() { return sqlite3_changes(this->db); } //be careful in a multi thread setting!
};

#endif