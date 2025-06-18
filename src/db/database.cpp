#include <iostream>
#include "db/database.h"

Database::Database()
{
}

Database::~Database()
{
    sqlite3_close(this->db);
}

bool Database::connect(const char* name, int flags)
{
    int status = sqlite3_open_v2(name, &this->db, flags, NULL);
    if(status!=SQLITE_OK)
    {
        std::cerr << "Could not open database " << name << ": " << sqlite3_errmsg(this->db) << " (" << status << ")!" << std::endl;
        return false;
    }

    return true;
}

void Database::disconnect()
{
    sqlite3_close(this->db);
}

int Database::callback(void* unused, int argc, char** argv, char** col_name)
{
    return 0;
}

bool Database::create_table(const char* name)
{
    return true;
}