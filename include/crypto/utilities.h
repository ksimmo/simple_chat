#ifndef CRYPTO_UTILITIES_H
#define CRYPTO_UTILITIES_H

#include "key.h"

bool dh(Key* priv, Key* pub, std::vector<unsigned char>& secret);
bool kdf(const std::vector<unsigned char>& secret, std::vector<unsigned char>& output, std::size_t length);

bool create_iv(std::vector<unsigned char>& iv, std::size_t length=12);
bool aead_encrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data, std::vector<unsigned char>& cipher, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag);
bool aead_decrypt(const std::vector<unsigned char>& key, std::vector<unsigned char>& data, const std::vector<unsigned char>& cipher, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag);

bool x3dh_alice(const std::vector<unsigned char>& alice_priv_id, std::vector<unsigned char>& alice_pub_ep, 
                const std::vector<unsigned char>& bob_pub_id, const std::vector<unsigned char>& bob_pub_spk, const std::vector<unsigned char>& bob_pub_ot,
                const std::vector<unsigned char>& signature, const std::string& id_type, const std::string& other_type, std::vector<unsigned char>& final_secret);
bool x3dh_bob(const std::vector<unsigned char>& bob_priv_id, const std::vector<unsigned char>& bob_priv_spk, 
                const std::vector<unsigned char>& bob_priv_ot, const std::vector<unsigned char>& alice_pub_id, const std::vector<unsigned char>& alice_pub_ep,
                const std::string& id_type, const std::string& other_type, std::vector<unsigned char>& final_secret);

#endif