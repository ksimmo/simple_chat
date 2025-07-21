#include <algorithm>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

#include "db/entry.h"

DBEntry::DBEntry(int type, const void* data, std::size_t length) : type(type)
{
    if(type==SQLITE_INTEGER)
        length = sizeof(int);
    else if(type==SQLITE_FLOAT)
        length = sizeof(double);

    if(data==nullptr)
        length = 0;

    if(length!=0)
    {
        this->buffer.resize(length);
        std::copy((unsigned char*)data, (unsigned char*)data+this->buffer.size(), buffer.data());
    }
}

DBEntry::~DBEntry()
{
    //if(this->buffer!=nullptr)
    //    delete[] this->buffer;
}

void DBEntry::get_string(std::string& s)
{
    s.insert(s.begin(), (char*)this->buffer.data(), (char*)this->buffer.data()+this->buffer.size());
}

void DBEntry::get_time(std::chrono::system_clock::time_point& tp)
{
    std::tm tm = {};
    int microseconds = 0;
    char dot;

    std::string datetime;
    this->get_string(datetime);
    
    std::stringstream ss(datetime);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    //Parse the subseconds if present
    if (ss >> dot >> microseconds) {
        // Ensure the microseconds are in the range of [0, 999]
        microseconds = microseconds % 1000;
    }

    //Convert tm to time_t (seconds)
    std::time_t time = std::mktime(&tm);

    //Reconstruct the time_point, adding the subseconds (microseconds)
    auto time_point = std::chrono::system_clock::from_time_t(time);
    auto fractional_seconds = std::chrono::microseconds(microseconds);

    tp = time_point + fractional_seconds;
}