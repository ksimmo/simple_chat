#ifndef KEY_H
#define KEY_H

#include<vector>

#include <openssl/evp.h>

//current default is Curve25519, maybe exchange with post quantum protocol later


//use the following names
//ML-DSA-{44, 65, 87}
//ML-KEM-{512,768, 1024} //768 recommended
//ED25519
class Key
{
private:
    std::string name;
    EVP_PKEY* key = nullptr;
    bool is_public = false;
public:
    Key();
    ~Key();

    std::string get_name() { return this->name; }
    bool is_public_only() { return this->is_public; }

    bool create(std::string& name);
    bool create_from_private(std::string& name, std::vector<unsigned char>& data);
    bool create_from_public(std::string& name, std::vector<unsigned char>& data);

    bool extract_private(std::vector<unsigned char>& data);
    bool extract_public(std::vector<unsigned char>& data);

    bool sign_data(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);
    bool verify_signature(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);
};

#endif