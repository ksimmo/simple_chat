#ifndef KEY_H
#define KEY_H

#include<vector>

#include <openssl/evp.h>

//current default is Curve25519, maybe exchange with post quantum protocol later
//void ed25519_to_x25519_public(std::vector<unsigned char>& ed, std::vector<unsigned char>& x);


//use the following names
//ML-DSA-{44, 65, 87}
//ML-KEM-{512,768, 1024} //768 recommended
//ED25519, or X25519
class Key
{
private:
    std::string name;
    EVP_PKEY* key = nullptr;
    bool is_public = false;
public:
    Key();
    Key(Key& other, bool only_public=false);
    ~Key();

    std::string get_name() { return this->name; }
    bool is_public_only() { return this->is_public; }

    operator EVP_PKEY*() { return this->key; }

    bool create(std::string& name);
    bool create_from_private(std::string& name, std::vector<unsigned char>& data);
    bool create_from_public(std::string& name, std::vector<unsigned char>& data);
    bool create_from_private(Key& other);
    bool create_from_public(Key& other);

    //get raw_key
    bool extract_private(std::vector<unsigned char>& data);
    bool extract_public(std::vector<unsigned char>& data);

    Key* get_public();

    bool sign_data(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);
    bool verify_signature(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);

    bool encapsulate(std::vector<unsigned char>& cipher, std::vector<unsigned char>& secret);
    bool decapsulate(std::vector<unsigned char>& cipher, std::vector<unsigned char>& secret);

    //encapsulate
    //decapsulate

    //diffie-hellmann
};

#endif