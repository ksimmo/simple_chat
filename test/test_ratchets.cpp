#include <iostream>
#include <vector>

#include "crypto/crypto.h"

int main(int argc, char* argv[])
{
    std::vector<unsigned char> shared_secret = {120,248,42,4,116,93,46,114,59,71,236,72,51,118,50,207,44,96,169,175,49,194,14,25,19,61,10,2,215,214,215,165};
    
    //first of all check symmetric ratchet
    SymmetricRatchet alice(shared_secret);
    SymmetricRatchet bob(shared_secret, false);

    alice.send();
    bob.recv();
    bob.send();
    alice.recv();

    std::vector<unsigned char> key_s_alice = alice.get_send_key();
    std::vector<unsigned char> key_r_alice = alice.get_recv_key();
    std::vector<unsigned char> key_s_bob = bob.get_send_key();
    std::vector<unsigned char> key_r_bob = bob.get_recv_key();

    //check if the corresponding keys are equal
    bool send_equal = true;
    bool recv_equal = true;
    for(int i=0;i<key_s_alice.size();i++)
    {
        if(key_s_alice[i]!=key_r_bob[i])
            send_equal = false;
        if(key_r_alice[i]!=key_s_bob[i])
            recv_equal = false;
    }

    if(send_equal)
        std::cout << "Sending keys are equal!" << std::endl;
    else
        std::cout << "Sending keys are not equal!" << std::endl;

    if(recv_equal)
        std::cout << "Receiving keys are equal!" << std::endl;
    else
        std::cout << "Receiving keys are not equal!" << std::endl;

    //check diffie hellman ratchet

    return 0;
}