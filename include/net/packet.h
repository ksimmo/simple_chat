#ifndef PACKET_H
#define PACKET_H

#include <queue>
#include <vector>

enum PacketType {PK_EMPTY, //Empty
                PK_AUTH_CHALLENGE,  //Authentification challenge
                PK_AUTH_STATUS,     //Authentification status 
                PK_AUTH_ADD,        //Authentification add new public key
                PK_ONLINE,          //Check if user is online
                PK_MSG              //A message packet between users
    };

struct PacketHeader
{
    unsigned char type;
    std::size_t length;
};

class Packet
{
private:
    std::vector<char> data; //the full packet data
    PacketHeader* header = nullptr; //pointer to packet header
    std::size_t write_pos = 0;  //the actual write position can only increase!
public:
    Packet(std::size_t length);
    ~Packet();

    void append_byte(char byte);
    std::size_t get_length() { return this->data.size(); }
    char* get_data() { return this->data.data(); }
};


class PacketBuffer
{
private:
    std::deque<char> buffer;
    std::deque<Packet*> packets; //TODO: make this thread safe!
public:
    PacketBuffer();
    ~PacketBuffer();

    void append(char* buffer, int buffer_length);
    void parse_packets(); //create packets from buffer
    int write_packets(char* buffer, int buffer_length); //write packets to buffer
    void clear_packets(); //remove packets
    void clear_buffer();
};

#endif