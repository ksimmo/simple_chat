#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

#include "crypto/crypto.h"

bool dh(Key* priv, Key* pub, std::vector<unsigned char>& secret)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(*priv, nullptr);
    if(!ctx)
    {
        std::cerr << "[-] Cannot create ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    if(EVP_PKEY_derive_init(ctx) <= 0)
    {
        std::cerr << "[-] Cannot initialize derive: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if(EVP_PKEY_derive_set_peer(ctx, *pub) <= 0)
    {
        std::cerr << "[-] Cannot set derive peer: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    std::size_t length;
    if(EVP_PKEY_derive(ctx, nullptr, &length) <= 0)
    {
        std::cerr << "[-] Cannot derive secret length: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    secret.resize(length);
    if(EVP_PKEY_derive(ctx, secret.data(), &length) <= 0)
    {
        std::cerr << "[-] Cannot derive secret: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool kdf(std::vector<unsigned char>& secret, std::vector<unsigned char>& output, std::size_t length)
{
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if(!kdf)
    {
        std::cerr << "[-] Cannot create kdf: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    if(!ctx)
    {
        std::cerr << "[-] Cannot create kdf ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_KDF_free(kdf);
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)"sha256", (std::size_t)6),
        OSSL_PARAM_construct_octet_string("key", secret.data(), (size_t)secret.size()),
        //OSSL_PARAM_construct_octet_string("salt", "salt", (size_t)4),
        //OSSL_PARAM_construct_octet_string("info", "label", (size_t)5),
        OSSL_PARAM_construct_end()
    };

    if(EVP_KDF_CTX_set_params(ctx, params) <= 0) {
        std::cerr << "[-] Failed setting ctx params: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(ctx);
        return false;
    }

    output.resize(length);
    if(EVP_KDF_derive(ctx, output.data(), length, nullptr)<=0)
    {
        std::cerr << "[-] Cannot derive kdf: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(ctx);
        return false;
    }

    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);

    return true;
}


//AEAD
bool create_iv(std::vector<unsigned char>& iv)
{
    iv.resize(12);
    if(!RAND_bytes(iv.data(), 12))
    {
        std::cerr << "[-] Cannot create iv: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    return true;
}

bool aead_encrypt(std::vector<unsigned char>& key, std::vector<unsigned char>& data, std::vector<unsigned char>& cipher, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(ctx==nullptr)
    {
        std::cerr << "[-] Cannot create cipher ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data())!=1)
    {
        std::cerr << "[-] Cannot initialize encrpytion: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    cipher.resize(data.size()+16); //reserve an additional extra block
    int cipher_length = cipher.size();
    if(EVP_EncryptUpdate(ctx, cipher.data(), &cipher_length, data.data(), data.size())!=1)
    {
        std::cerr << "[-] Cannot encrypt: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int length = 0;
    if(EVP_EncryptFinal_ex(ctx, cipher.data() + cipher_length, &length)!=1)
    {
        std::cerr << "[-] Cannot finalize encrypt: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    cipher_length += length;
    cipher.resize(cipher_length);

    tag.resize(16);
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()))
    {
        std::cerr << "[-] Cannot set tag: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool aead_decrypt(std::vector<unsigned char>& key, std::vector<unsigned char>& data, std::vector<unsigned char>& cipher, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(ctx==nullptr)
    {
        std::cerr << "[-] Cannot create cipher ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data())!=1)
    {
        std::cerr << "[-] Cannot initialize decrpytion: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data())!=1)
    {
        std::cerr << "[-] Cannot set tag: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    data.resize(cipher.size());
    int data_length = data.size();
    if(EVP_DecryptUpdate(ctx, data.data(), &data_length, cipher.data(), cipher.size())!=1)
    {
        std::cerr << "[-] Cannot decrypt: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int length = 0;
    if(EVP_DecryptFinal_ex(ctx, data.data() + data_length, &length)!=1)
    {
        std::cerr << "[-] Cannot finalize decrypt: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    data_length += length;
    data.resize(data_length);

    EVP_CIPHER_CTX_free(ctx);

    return true;
}