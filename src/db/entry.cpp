#include <algorithm>

#include "db/entry.h"

DBEntry::DBEntry(int type, const void* data, std::size_t length) : type(type)
{
    if(type==SQLITE_INTEGER)
        this->length = sizeof(int);
    else if(type==SQLITE_FLOAT)
        this->length = sizeof(double);
    else
        this->length = length;

    if(data==nullptr)
        this->length = 0;

    if(this->length!=0)
    {
        this->buffer = new unsigned char[this->length];
        std::copy((unsigned char*)data, (unsigned char*)data+this->length, buffer);
    }
}

DBEntry::~DBEntry()
{
    if(this->buffer!=nullptr)
        delete[] this->buffer;
}