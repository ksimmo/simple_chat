#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

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

/*
// HKDF with SHA-256
std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                 const std::vector<uint8_t>& salt = {},
                                 const std::vector<uint8_t>& info = {},
                                 size_t outLen = 32) {
    std::vector<uint8_t> okm(outLen);
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, const_cast<char*>("extract-and-expand"), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt.data(), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm.data(), ikm.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size()),
        OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_OUTLEN, &outLen),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_OUT, okm.data(), okm.size()),
        OSSL_PARAM_END
    };
    EVP_KDF_derive(ctx, params);
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
    return okm;
}
*/