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
    Key(const Key& other, bool only_public=false);
    ~Key();

    std::string get_name() { return this->name; }
    bool is_public_only() { return this->is_public; }

    operator EVP_PKEY*() { return this->key; }

    bool create(const std::string& name);
    bool create_from_private(const std::string& name, const std::vector<unsigned char>& data);
    bool create_from_public(const std::string& name, const std::vector<unsigned char>& data);
    bool create_from_private(const Key& other);
    bool create_from_public(const Key& other);

    const std::vector<unsigned char>& get_private() { return this->private_key; }
    const std::vector<unsigned char>& get_public() { return this->public_key; }
    Key* derive_public();

    bool sign_data(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);
    bool verify_signature(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data);

    bool encapsulate(std::vector<unsigned char>& cipher, std::vector<unsigned char>& secret);
    bool decapsulate(std::vector<unsigned char>& cipher, std::vector<unsigned char>& secret);

    //encapsulate
    //decapsulate

    //diffie-hellmann
};

//convert ED25519 to X25519
Key* convert_ed25519_to_x25519_private(Key* priv);
Key* convert_ed25519_to_x25519_public(Key* pub);

#endif