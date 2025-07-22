#include <iostream>

#include "crypto/crypto.h"

void print_key(const std::vector<unsigned char>& data, const std::string& prefix="")
{
    std::string s;
    for(auto i=0;i<data.size();i++)
        s += std::to_string((int)data[i])+",";
    std::cout << prefix << "(" << data.size() << ")" << ": " << s << std::endl;
}

int main(int argc, char* argv[])
{
    Key k = Key();
    bool test = k.create("ML-DSA-87");
    //print_key(k.get_private(), "Private");
    //print_key(k.get_public(), "Public");

    Key kk = Key();
    kk.create_from_private(k);

    bool similar = (kk.get_private()==k.get_private());
    if(similar)
        std::cout << "Private keys are similar!" << std::endl;
    else
        std::cout << "Private keys are not similar!" << std::endl; 

    Key kkk = Key();
    kkk.create_from_public(k);

    similar = (kkk.get_public()==k.get_public());
    if(similar)
        std::cout << "Public keys are similar!" << std::endl;
    else
        std::cout << "Public keys are not similar!" << std::endl; 


    //test signature
    std::vector<unsigned char> message = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<unsigned char> signed_message;
    bool test1 = kk.sign_data(message, signed_message);
    bool test2 = kkk.verify_signature(message, signed_message);
    std::cout << "Sign & Verify using ML-DSA-87: " << test1 << " " << test2 << std::endl;

    k.create("ML-KEM-768");
    //print_key(k.get_private(), "ML-KEM-768");

    std::cout << "Test" << std::endl;
    Key kkkk = Key();
    kkkk.create("X25519MLKEM768");
    print_key(kkkk.get_private(), "Hybrid-priv");
    print_key(kkkk.get_public(), "Hybrid-pub");

    //create x25519 keypair
    k.create("X25519");
    print_key(k.get_private(), "X25519-private");
    print_key(k.get_public(), "X25519-public");

    //create ed25519 keypair
    k.create("ED25519");
    print_key(k.get_private(), "ED25519-private");
    print_key(k.get_public(), "ED25519-public");

    //convert
    Key priv = Key();
    Key pub = Key();
    convert_ed25519_to_x25519_private(k, priv);
    convert_ed25519_to_x25519_public(k, pub);

    return 0;
}