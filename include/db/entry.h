#ifndef DB_ENTRY_H
#define DB_ENTRY_H

#include <cstddef>
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

    std::size_t get_length() { return this->length; }
    const void* get_data() { return this->buffer; }
};

#endif