#include "net/packet.h"

PacketBuffer::PacketBuffer()
{

}

PacketBuffer::~PacketBuffer()
{

}

void PacketBuffer::append(char* buffer, int buffer_length)
{
    for(int i=0;i<buffer_length;i++)
        this->buffer.push(buffer[i]);
}

void PacketBuffer::parse_packets()
{

}

int PacketBuffer::write_packets(char*buffer, int buffer_length)
{
    //try to write as many packets fitting inside buffer_length
    //return the total amount of bytes written
    int length = 0;

    return length;
}

void PacketBuffer::clear_packets()
{
    
}

