#ifndef PACKET_H
#define PACKET_H

#include <queue>
#include <vector>
#include <string>

#include <cstdarg>

enum PacketType {PK_EMPTY,          //Empty
                PK_LOGIN,           //Send by client initiates verification
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

    int fd = -1;
public:
    Packet(int fd=-1, unsigned char type=PK_EMPTY, std::size_t length=0);
    ~Packet();

    int get_fd() { return this->fd; }
    unsigned char get_type() { return this->header->type; }
    std::size_t get_length() { return this->header->length; }
    std::size_t get_total_length() { return this->header->length+sizeof(PacketHeader); }
    unsigned char* get_data() { return this->data; }

    void resize(std::size_t new_length); //resize packet to fit new length
    void resize_if_necessary(std::size_t write_length); //check if the following can be written - or resize

    void append_byte(unsigned char byte);
    template<typename T>
    void append(T t);
    void append_string(std::string s);
    void append_buffer(void* data, std::size_t length);
    void append_fmt(const char* fmt, ...); //inspired by ENet & Sauerbraten code ...

    bool read_string(std::string &s);
    bool read_raw(void* data, std::size_t length);
    template<typename T>
    bool read(T& t);
};

extern template bool Packet::read<std::size_t>(std::size_t&);

//a buffer holding unfinished packet bytes and not send packets
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
    Packet* pop_packet(); //remove packet (ingoing) for processing

    void parse_packets(int fd=-1); //create packets from inout buffer
    int write_packets(char* buffer, int buffer_length); //write packets to buffer (outgoing)
    void clear_packets(); //remove packets
    void clear_buffer();
};

#endif