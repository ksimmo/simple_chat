#include <iostream>
#include "net/packet.h"

Packet::Packet(unsigned char type, std::size_t length)
{
    this->data = new unsigned char[length+sizeof(PacketHeader)];
    this->header = (struct PacketHeader*)this->data;
    this->header->type = type;
    this->header->length = length;

    this->write_pos = 0; //we read and write after header
    this->read_pos = 0;
}

Packet::~Packet()
{
    if(this->data!=nullptr)
        delete[] this->data;
}

void Packet::append_byte(unsigned char byte)
{
    if(this->write_pos<header->length)
    {
        this->data[this->write_pos+sizeof(PacketHeader)] = byte;
        this->write_pos++;
    }
}



/////////////////////////////////////////////

PacketBuffer::PacketBuffer()
{

}

PacketBuffer::~PacketBuffer()
{

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

