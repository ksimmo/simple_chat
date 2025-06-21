#include <iostream>
#include <openssl/err.h>

#include "crypto/key.h"

Key::Key()
{
}

Key::~Key()
{
    EVP_PKEY_free(this->key);
}

bool Key::create(int id)
{
    this->id = id;
    this->is_public = false;
    //initialize context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(this->id, nullptr);
    if(ctx==nullptr)
        return false;

    int result = EVP_PKEY_keygen_init(ctx);
    if(result<=0)
    {
        std::cerr << "[-] Cannot initialize key generator: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    result = EVP_PKEY_keygen(ctx, &this->key);
    if(result<=0)
    {
        std::cerr << "[-] Cannot create key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool Key::create_from_private(int id, std::vector<unsigned char>& data)
{
    if(this->key!=nullptr)
        EVP_PKEY_free(this->key);

    this->id = id;
    this->is_public = false;
    this->key = EVP_PKEY_new_raw_private_key(id, nullptr, data.data(), data.size());
    if(this->key==nullptr)
        std::cerr << "[-] Cannot create private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    return this->key==nullptr ? false : true;
}

bool Key::create_from_public(int id, std::vector<unsigned char>& data)
{
    if(this->key!=nullptr)
        EVP_PKEY_free(this->key);
    this->id = id;
    this->is_public = true;
    this->key = EVP_PKEY_new_raw_public_key(id, nullptr, data.data(), data.size());
    if(this->key==nullptr)
        std::cerr << "[-] Cannot create public key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    return this->key==nullptr ? false : true;
}

bool Key::extract_private(std::vector<unsigned char>& data)
{
    std::size_t length = 0;
    if(EVP_PKEY_get_raw_private_key(this->key, nullptr, &length)!=1)
    {
        std::cerr << "[-] Failed getting private key length: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    data.resize(length);
    if(EVP_PKEY_get_raw_private_key(this->key, data.data(), &length)!=1)
    {
        std::cerr << "[-] Failed getting private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    return true;
}

bool Key::extract_public(std::vector<unsigned char>& data)
{
    std::size_t length = 0;
    if(EVP_PKEY_get_raw_public_key(this->key, nullptr, &length)!=1)
    {
        std::cerr << "[-] Failed getting public key length: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    data.resize(length);
    if(EVP_PKEY_get_raw_public_key(this->key, data.data(), &length)!=1)
    {
        std::cerr << "[-] Failed getting public key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    return true;
}

///////////////////////////////////
bool Key::sign_data(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(ctx==nullptr)
    {
        std::cerr << "[-] Failed create ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    if((EVP_DigestSignInit(ctx, NULL, NULL, NULL, this->key) <= 0))
    {
        std::cerr << "[-] Failed create sign ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    //get length of signed data
    std::size_t length;
    if(EVP_DigestSign(ctx, NULL, &length, data.data(), data.size()) <= 0)
    {
        std::cerr << "[-] Failed get sign length: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    //sign
    signed_data.resize(length);
    if(EVP_DigestSign(ctx, signed_data.data(), &length, data.data(), data.size()) <= 0)
    {
        std::cerr << "[-] Failed sign: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;

}

bool Key::verify_signature(std::vector<unsigned char>& data, std::vector<unsigned char>& signed_data)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(ctx==nullptr)
    {
        std::cerr << "[-] Failed create ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    if((EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, this->key) <= 0))
    {
        std::cerr << "[-] Failed create verify ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    //verify
    int result = EVP_DigestVerify(ctx, signed_data.data(), signed_data.size(), data.data(), data.size());
    if(result<0)
        std::cerr << "[-] Failed verify: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;

    EVP_MD_CTX_free(ctx);
    return (result==1);
}