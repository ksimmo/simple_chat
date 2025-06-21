#ifndef KEY_H
#define KEY_H

#include<vector>

#include <openssl/evp.h>

//current default is Curve25519, maybe exchange with post quantum protocol later
class Key
{
private:
    int id = EVP_PKEY_ED25519;
    EVP_PKEY* key = nullptr;
    bool is_public = false;
public:
    Key();
    ~Key();

    int get_id() { return this->id; }
    bool is_public_only() { return this->is_public; }

    bool create(int id=EVP_PKEY_ED25519);
    bool create_from_private(int id, std::vector<unsigned char>& data);
    bool create_from_public(int id, std::vector<unsigned char>& data);

    bool extract_private(std::vector<unsigned char>& data);
    bool extract_public(std::vector<unsigned char>& data);

    bool sign_data(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);
    bool verify_signature(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);
};

#endif