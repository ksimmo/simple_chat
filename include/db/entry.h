#ifndef DB_ENTRY_H
#define DB_ENTRY_H

#include <cstddef>
#include <vector>
#include <sqlite3.h>

class DBEntry
{
private:
    int type = SQLITE_NULL;
    unsigned char* buffer = nullptr;
    std::size_t length = 0;
public:
    DBEntry(int type, const void* data=nullptr, std::size_t length=0);
    ~DBEntry();

    int get_type() { return this->type; }
    std::size_t get_length() { return this->length; }
    unsigned char* get_data() { return this->buffer; }
};

#endif