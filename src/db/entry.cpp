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
    //else keep length

    if(data==nullptr)
        length = 0;

    if(length!=0)
    {
        this->buffer.resize(length);
        std::copy((unsigned char*)data, (unsigned char*)data+length, this->buffer.data());
    }
}

DBEntry::DBEntry(const DBEntry& other)
{
    this->type = other.type;
    this->buffer.resize(other.buffer.size());
    std::copy(other.buffer.data(), other.buffer.data()+other.buffer.size(), this->buffer.data());
}

DBEntry::~DBEntry()
{
    //if(this->buffer!=nullptr)
    //    delete[] this->buffer;
}

void DBEntry::get_string(std::string& s)
{
    s.insert(s.begin(), (const char*)this->buffer.data(), (const char*)this->buffer.data()+this->buffer.size());
}

void DBEntry::get_time(std::chrono::system_clock::time_point& tp)
{
    std::tm tm = {};
    tm.tm_isdst = -1; //DST should be determined automatically
    int microseconds = 0;

    std::string datetime;
    this->get_string(datetime);
    
    std::stringstream ss(datetime);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    if(datetime.length()==23) //means we have appended microseconds
        microseconds = std::stoi(datetime.substr(20));

    //Convert tm to time_t (seconds)
    std::time_t time = std::mktime(&tm);

    //Reconstruct the time_point, adding the subseconds (microseconds)
    auto time_point = std::chrono::system_clock::from_time_t(time);
    auto fractional_seconds = std::chrono::microseconds(microseconds*1000); //microseconds are given in 10^6

    tp = time_point + fractional_seconds;
}