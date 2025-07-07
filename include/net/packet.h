#ifndef PACKET_H
#define PACKET_H

#include <queue>
#include <vector>
#include <string>

#include <cstdarg>

enum PacketType {PK_EMPTY,                      //Empty
                PK_ERROR,                       //An error happened
                PK_LOGIN,                       //Send by client initiates verification
                PK_LOGIN_CHALLENGE,             //Authentification challenge
                PK_LOGIN_SUCCESSFULL,           //Authentification was succesfull
                PK_ONLINE_STATUS,               //Check if a user is online
                PK_USER_SEARCH,                 //provide a string and search for nearest user names
                PK_USER_KEYS,                   //get user keys to perform secret key exchange
                PK_UPLOAD_KEYS,                 //the current user sends keys to the server
                PK_KEY_EXPIRED,                 //if keys are too long on the server-> they will be deleted
                PK_MSG,                         //A message packet between users
                PK_MSG_DELIVERY_STATUS,         //is the message delivered or read?

    };

enum PacketErrors {PK_ERROR_NONE,
                    PK_ERROR_UNDEFINED,          //any other error
                    PK_ERROR_SERVER,              //error occured on server side
                    PK_ERROR_UNREGISTERED,       //User is not registered
                    PK_ERROR_AUTH,                  //Authentification failed
                    PK_ERROR_USER                   //User does not exists
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
    void append_string(const std::string& s);
    void append_buffer(void* data, std::size_t length, bool write_size=true);
    void append_buffer(const std::vector<unsigned char>& data, bool write_size=true);
    void append_fmt(const char* fmt, ...); //inspired by ENet & Sauerbraten code ...

    bool read_string(std::string &s);
    bool read_raw(void* data, std::size_t length);
    bool read_buffer(std::vector<unsigned char>& data);
    template<typename T>
    bool read(T& t)
    {
        if((this->read_pos+sizeof(t))>this->header->length) //ok object is too large we cannot read it
            return false;

        std::copy(this->data+this->read_pos+sizeof(PacketHeader), 
                    this->data+this->read_pos+sizeof(PacketHeader)+sizeof(t),
                (unsigned char*)&t);
        this->read_pos += sizeof(t);

        return true;
    }
    void read_remaining(std::vector<unsigned char>& data);
};

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
    std::size_t num_packets() { return this->packets.size(); }

    void parse_packets(int fd=-1); //create packets from inout buffer
    int write_packets(char* buffer, int buffer_length); //write packets to buffer (outgoing)
    void clear_packets(); //remove packets
    void clear_buffer();
};

#endif