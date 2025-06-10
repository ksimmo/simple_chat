#ifndef PACKET_H
#define PACKET_H

#include<queue>

struct PacketHeader
{
    short type;
    int length;
};

class Packet
{
public:
    
};


class PacketBuffer
{
private:
    std::queue<char> buffer;
    std::queue<Packet*> packets; //TODO: make this thread safe!
public:
    PacketBuffer();
    ~PacketBuffer();

    void append(char* buffer, int buffer_length);
    void parse_packets(); //create packets from buffer
    int write_packets(char* buffer, int buffer_length); //write packets to buffer
    void clear_packets(); //remove packets
};

#endif