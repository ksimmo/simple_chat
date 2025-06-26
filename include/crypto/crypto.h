#ifndef CRYPTO_H
#define CRYPTO_H

#include "key.h"

bool dh(Key* priv, Key* pub, std::vector<unsigned char>& secret);
bool kdf(std::vector<unsigned char>& secret, std::vector<unsigned char>& output, std::size_t length);

#endif