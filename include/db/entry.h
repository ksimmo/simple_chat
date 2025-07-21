#ifndef DB_ENTRY_H
#define DB_ENTRY_H

#include <cstddef>
#include <vector>
#include <string>
#include <chrono>
#include <sqlite3.h>

class DBEntry
{
private:
    int type = SQLITE_NULL;
    std::vector<unsigned char> buffer;
public:
    DBEntry(int type, const void* data=nullptr, std::size_t length=0);
    ~DBEntry();

    int get_type() { return this->type; }
    std::size_t get_length() { return this->buffer.size(); }
    unsigned char* get_data() { return this->buffer.data(); }
    const std::vector<unsigned char>& get_buffer() { return this->buffer; }

    void get_string(std::string& s);
    void get_time(std::chrono::system_clock::time_point& tp);
};

#endif