#include <iostream>
#include <vector>
#include <string>

#include <openssl/err.h>
#include <openssl/rand.h>
#include "crypto/crypto.h"

int main(int argc, char* argv[])
{
    std::vector<unsigned char> key = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                           0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                           0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                           0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31};

    std::string s = "This is a test sentence!";

    std::vector<unsigned char> plain;
    plain.resize(s.length());

    std::string s1;
    std::string s2;
    for(int i=0;i<s.length();i++)
    {
        plain[i] = (unsigned char)s[i];
        s1 += std::to_string((int)plain[i])+",";
    }
    s.clear();
    std::vector<unsigned char> cipher;

    //create iv
    std::vector<unsigned char> iv;
    iv.resize(12);
    if(!RAND_bytes(iv.data(), 12))
    {
        std::cerr << "[-] Cannot create iv: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return -1;
    }

    aead_encrypt(key, plain, cipher, iv);

    plain.clear();
    aead_decrypt(key, plain, cipher, iv);

    for(int i=0;i<plain.size();i++)
        s2 += std::to_string((int)plain[i])+",";

    std::cout << s1 << std::endl;
    std::cout << s2 << std::endl;
    return 0;
}

