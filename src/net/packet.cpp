#include "net/packet.h"

Packet::Packet(std::size_t length)
{
    this->data.reserve(length);
    this->header = (struct PacketHeader*)this->data.data();
}

Packet::~Packet()
{
    this->data.clear();
}

void Packet::append_byte(char byte)
{
    if(this->write_pos<this->data.size())
    {
        this->data[this->write_pos] = byte;
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
        this->buffer.push_front(buffer[i]);
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
        if(this->buffer.size()<(header.length+header_size))
            return; //buffer to short -> packet is not fully received yet
        
        //read packet byte by byte
        Packet* packet = new Packet(header.length+header_size);
        for(unsigned int i=0;i<header.length+header_size;i++)
        {
            packet->append_byte(this->buffer.back());
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
        if(buffer_length>length+packet->get_length()) //ok we have enough space left to write packet
        {
            //put packet into buffer
            std::copy(packet->get_data(), packet->get_data()+packet->get_length(), buffer+length);
            length = length + packet->get_length();
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

