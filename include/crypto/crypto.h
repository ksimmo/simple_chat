#ifndef CRYPTO_H
#define CRYPTO_H

#include "key.h"

bool dh(Key* priv, Key* pub, std::vector<unsigned char>& secret);
bool kdf(std::vector<unsigned char>& secret, std::vector<unsigned char>& output, std::size_t length);

bool create_iv(std::vector<unsigned char>& iv);
bool aead_encrypt(std::vector<unsigned char>& key, std::vector<unsigned char>& data, std::vector<unsigned char>& cipher, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag);
bool aead_decrypt(std::vector<unsigned char>& key, std::vector<unsigned char>& data, std::vector<unsigned char>& cipher, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag);

#endif