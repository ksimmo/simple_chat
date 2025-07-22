#ifndef KEY_H
#define KEY_H

#include<vector>

#include <openssl/evp.h>

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
    std::vector<unsigned char> private_key; //private key
    std::vector<unsigned char> public_key; //public key

    //get raw_key from EVP_PKEY
    bool extract_private();
    bool extract_public();
public:
    Key();
    Key(const std::vector<unsigned char>& data, const std::string& type, bool only_public=false);
    Key(const Key& other, bool only_public=false);
    ~Key();

    const std::string& get_name() { return this->name; }
    bool is_public_only() { return this->is_public; }
    bool is_initialized() { return this->key!=nullptr; }

    operator EVP_PKEY*() { return this->key; }

    bool create(const std::string& name);
    bool create_from_private(const std::string& name, const std::vector<unsigned char>& data);
    bool create_from_public(const std::string& name, const std::vector<unsigned char>& data);
    bool create_from_private(const Key& other);
    bool create_from_public(const Key& other);

    const std::vector<unsigned char>& get_private() { return this->private_key; }
    const std::vector<unsigned char>& get_public() { return this->public_key; }
    Key* derive_public();
    bool derive_public(Key& k);

    bool sign_data(const std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);
    bool verify_signature(const std::vector<unsigned char>& data, const std::vector<unsigned char>& signed_data);

    bool encapsulate(std::vector<unsigned char>& cipher, std::vector<unsigned char>& secret);
    bool decapsulate(const std::vector<unsigned char>& cipher, std::vector<unsigned char>& secret);
};

//convert ED25519 to X25519
bool convert_ed25519_to_x25519_private(Key& priv, Key& outkey);
bool convert_ed25519_to_x25519_public(Key& pub, Key& outkey);

#endif