#ifndef CRYPTO_H
#define CRYPTO_H

#include "key.h"

bool dh(Key* priv, Key* pub, std::vector<unsigned char>& secret);
bool kdf(std::vector<unsigned char>& secret, std::vector<unsigned char>& output, std::size_t length);

bool create_iv(std::vector<unsigned char>& iv, std::size_t length=12);
bool aead_encrypt(std::vector<unsigned char>& key, std::vector<unsigned char>& data, std::vector<unsigned char>& cipher, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag);
bool aead_decrypt(std::vector<unsigned char>& key, std::vector<unsigned char>& data, std::vector<unsigned char>& cipher, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag);

bool x3dh_alice(std::vector<unsigned char> alice_priv_id, std::vector<unsigned char>& alice_pub_ep, 
                std::vector<unsigned char>& bob_pub_id, std::vector<unsigned char>& bob_pub_spk, std::vector<unsigned char>& bob_pub_ot,
                std::vector<unsigned char>& signature, std::string& id_type, std::string& other_type, std::vector<unsigned char>& final_secret);
bool x3dh_bob(std::vector<unsigned char> bob_priv_id, std::vector<unsigned char>& bob_priv_spk, 
                std::vector<unsigned char>& bob_priv_ot, std::vector<unsigned char>& alice_pub_id, std::vector<unsigned char>& alice_pub_ep,
                std::string& id_type, std::string& other_type, std::vector<unsigned char>& final_secret);
#endif