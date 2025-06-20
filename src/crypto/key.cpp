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

bool Key::create_from_private(int id, const unsigned char* bytes, std::size_t length)
{
    if(this->key!=nullptr)
        EVP_PKEY_free(this->key);
    this->id = id;
    this->is_public = false;
    this->key = EVP_PKEY_new_raw_private_key(id, nullptr, bytes, length);
    if(this->key==nullptr)
        std::cerr << "[-] Cannot create private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    return this->key==nullptr ? false : true;
}

bool Key::create_from_public(int id, const unsigned char* bytes, std::size_t length)
{
    if(this->key!=nullptr)
        EVP_PKEY_free(this->key);
    this->id = id;
    this->is_public = true;
    this->key = EVP_PKEY_new_raw_public_key(id, nullptr, bytes, length);
    return this->key==nullptr ? false : true;
}

std::vector<unsigned char> Key::extract_private()
{
    unsigned char* buffer = new unsigned char[512];
    std::size_t length = 512;
    if(EVP_PKEY_get_raw_private_key(this->key, buffer, &length)<=0)
    {
        std::cerr << "[-] Failed getting private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return std::vector<unsigned char>();
    } 
    std::vector<unsigned char> bytes(buffer, buffer+length);
    delete[] buffer;

    return bytes;
}

std::vector<unsigned char> Key::extract_public()
{
    unsigned char* buffer = new unsigned char[512];
    std::size_t length = 512;
    if(EVP_PKEY_get_raw_public_key(this->key, buffer, &length)<=0)
    {
        std::cerr << "[-] Failed getting public key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return std::vector<unsigned char>();
    } 
    std::vector<unsigned char> bytes(buffer, buffer+length);
    delete[] buffer;

    return bytes;
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
    unsigned char* buffer = new unsigned char[length];
    if(EVP_DigestSign(ctx, buffer, &length, data.data(), data.size()) <= 0)
    {
        std::cerr << "[-] Failed sign: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        delete[] buffer;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    for(int i=0;i<length;i++)
        signed_data.push_back(buffer[i]);
    
    delete[] buffer;

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

    EVP_MD_CTX_free(ctx);
    return (result==1);
}