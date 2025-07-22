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
    k.create("ML-KEM-768");

    Key pub = Key();
    k.derive_public(pub);

    std::vector<unsigned char> cipher;
    std::vector<unsigned char> secret;
    std::vector<unsigned char> secret2;
    pub.encapsulate(cipher, secret);
    k.decapsulate(cipher, secret2);
    std::cout << "Enc. dec. equal? " << (secret2==secret) << std::endl;



    return 0;
}