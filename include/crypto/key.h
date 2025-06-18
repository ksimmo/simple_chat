#ifndef KEY_H
#define KEY_H

#include<vector>

#include <openssl/evp.h>

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
    bool create_from_private(int id, const unsigned char* bytes, std::size_t length);
    bool create_from_public(int id, const unsigned char* bytes, std::size_t length);

    std::vector<unsigned char> extract_private();
    std::vector<unsigned char> extract_public();
};

#endif