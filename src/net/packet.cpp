#include <iostream>
#include "net/packet.h"

//create a new packet with specified length
Packet::Packet(unsigned char type, std::size_t length)
{
    this->data = new unsigned char[length+sizeof(PacketHeader)];
    this->header = (struct PacketHeader*)this->data;
    this->header->type = type;
    this->header->length = length;

    this->write_pos = 0; //we read and write after header - always!
    this->read_pos = 0;
}

Packet::~Packet()
{
    if(this->data!=nullptr)
        delete[] this->data;
}

void Packet::resize(std::size_t new_length)
{
    if(this->data==nullptr)
        return;
    unsigned char* temp = new unsigned char[new_length+sizeof(PacketHeader)];
    std::size_t to_copy = std::min(this->header->length, new_length)+sizeof(PacketHeader);
    std::copy(this->data, this->data+to_copy, temp);
    delete[] this->data;

    //reasign pointers
    this->data = temp;
    this->header = (struct PacketHeader*)this->data;
    this->header->length = new_length; //also adapt information in packet

    //clamp read and write pos if necessary
    this->read_pos = std::min(this->read_pos, new_length-1);
    this->write_pos = std::min(this->write_pos, new_length-1);

}

void Packet::resize_if_necessary(std::size_t write_length)
{
    if((this->write_pos+write_length)>this->header->length) //ok we cannot write further -> resize
        this->resize(this->header->length+write_length);
}

void Packet::append_byte(unsigned char byte)
{
    this->resize_if_necessary(sizeof(byte));
    this->data[this->write_pos+sizeof(PacketHeader)] = byte;
    this->write_pos = this->write_pos + 1;
}

//append any object
template<typename T>
void Packet::append(T t)
{
    this->resize_if_necessary(sizeof(t));
    std::copy((unsigned char*)&t, ((unsigned char*)&t)+sizeof(t), 
                this->data+this->write_pos+sizeof(PacketHeader));
    this->write_pos += sizeof(t);
}

//append string
void Packet::append_string(std::string s)
{
    this->resize_if_necessary(s.size()+1); //take care of '\0'
    std::copy((unsigned char*)s.c_str(), ((unsigned char*)s.c_str())+sizeof(s.size()+1), 
                this->data+this->write_pos+sizeof(PacketHeader));
    this->write_pos += s.size()+1;
}


//append multiple values onto packet (similar to printf)
void Packet::append_fmt(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    while(*fmt!='\0')
    {
        switch(*fmt)
        {
        case 'i': //integer
        {
            int i = va_arg(args, int);
            this->append(i);
            break;
        }
        case 'f': //float
        {
            float f = (float)va_arg(args, double);
            this->append(f);
            break;
        }
        case 'd': //double
        {
            double d = va_arg(args, double);
            this->append(d);
            break;
        }
        case 'c': //char
        {
            char c = (char)va_arg(args, int);
            this->append(c);
            break;
        }
        case 's': //string
        {
            char* c = va_arg(args, char*);
            this->append_string(std::string(c));
            break;
        }
        
        default:
            break;
        }
        ++fmt;
    }
    va_end(args);
}

template<typename T>
bool Packet::read(T& t)
{
    if((this->read_pos+sizeof(t))>this->header->length) //ok object is too large we cannot read it
        return false;

    std::copy(this->data+this->read_pos+sizeof(PacketHeader), 
                this->data+this->read_pos+sizeof(PacketHeader)+sizeof(t),
            (unsigned char*)t);
    this->read_pos += sizeof(t);

    return true;
}

bool Packet::read_string(std::string& s)
{
    //loop though bytes to find terminating character
    std::size_t length = 0;
    for(std::size_t i=this->read_pos;i<this->header->length;i++)
    {
        if((char)this->data[i+sizeof(PacketHeader)]=='\0')
        {
            length = i-this->read_pos;
            break;
        }
    }

    if(length==0) //we did not find a string
        return false;

    s.insert(0, (char*)this->data+this->read_pos+sizeof(PacketHeader), length); //do not insert '\0'
    this->read_pos += length+1;

    return true;
}



/////////////////////////////////////////////

PacketBuffer::PacketBuffer()
{

}

PacketBuffer::~PacketBuffer()
{

}

//we take a reference and copy the packet such that we do not loose an object
Packet* PacketBuffer::pop_packet()
{
    if(this->packets.size()==0) //no packets left
        return nullptr;

    Packet* packet = this->packets.back();
    this->packets.pop_back();

    return packet;
}

void PacketBuffer::append(char* buffer, int buffer_length)
{
    for(int i=0;i<buffer_length;i++)
        this->buffer.push_front(((unsigned char*)buffer)[i]);
}

//extract packets from buffer
void PacketBuffer::parse_packets()
{
    //check if we can at least parse the packet header
    std::size_t header_size = sizeof(PacketHeader);
    while (this->buffer.size()>=header_size)
    {
        //get a peek at the packet header to see if we can parse the full packet
        std::vector<char> temp;
        for(auto it = this->buffer.rbegin();it!=buffer.rbegin()+header_size;it++)
            temp.push_back(*it);

        PacketHeader header = *((PacketHeader*)temp.data());
        if(this->buffer.size()<(header.length+header_size)) //packet size = header size + payload size
            return; //buffer to short -> packet is not fully received yet
        
        //read packet byte by byte
        Packet* packet = new Packet(header.type, header.length);
        for(std::size_t i=0;i<header.length+header_size;i++)
        {
            if(i>=header_size) //Packet header should not be read! because it is already read
            {
                packet->append_byte(this->buffer.back());
            }
            this->buffer.pop_back();
        }

        //put it into queue
        this->packets.push_front(packet);
    }
    
}

//write packet to buffer 
int PacketBuffer::write_packets(char*buffer, int buffer_length)
{
    //try to write as many packets fitting inside buffer_length
    //return the total amount of bytes written
    int length = 0;
    for(int i=0;i<this->packets.size();i++)
    {
        Packet* packet = this->packets.back();
        std::size_t packet_length = packet->get_total_length();
        if(buffer_length>length+packet_length) //ok we have enough space left to write packet
        {
            //put packet into buffer
            std::copy(packet->get_data(), packet->get_data()+packet_length, (unsigned char*)buffer+length);
            length = length + packet_length;
            delete packet; //clear packet
            this->packets.pop_back(); //remove from queue
        }
        else
            break;
    }

    return length;
}

//clear packets
void PacketBuffer::clear_packets()
{
    for(int i=0;i<this->packets.size();i++)
    {
        delete this->packets.back();
        this->packets.pop_back();
    }
}

void PacketBuffer::clear_buffer()
{
    this->buffer.clear();
}

