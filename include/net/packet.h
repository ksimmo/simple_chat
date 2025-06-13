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

#pragma pack(push, 1) //make sure that the header is the same on all architectures and no padding occurs
struct PacketHeader
{
    unsigned char type;
    std::size_t length;
};
#pragma pack(pop)

class Packet
{
private:
    unsigned char* data; //the full packet data
    PacketHeader* header = nullptr; //pointer to packet header
    std::size_t write_pos = 0;  //the actual write position can only increase!
    std::size_t read_pos = 0; //the actual position for reading
public:
    Packet(unsigned char type, std::size_t length);
    ~Packet();

    void append_byte(unsigned char byte);
    unsigned char get_type() { return this->header->type; }
    std::size_t get_length() { return this->header->length; }
    std::size_t get_total_length() { return this->header->length+sizeof(PacketHeader); }
    unsigned char* get_data() { return this->data; }
};


class PacketBuffer
{
private:
    std::deque<unsigned char> buffer;
    std::deque<Packet*> packets; //TODO: make this thread safe!
public:
    PacketBuffer();
    ~PacketBuffer();

    void append(char* buffer, int buffer_length);
    void add_packet(Packet* packet) { this->packets.push_front(packet); }
    void parse_packets(); //create packets from buffer
    int write_packets(char* buffer, int buffer_length); //write packets to buffer
    void clear_packets(); //remove packets
    void clear_buffer();
};

#endif