#include <iostream>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include "crypto/key.h"

Key::Key()
{
}

Key::Key(const Key& other, bool public_only)
{
    if(public_only)
        this->create_from_public(other);
    else if(!other.is_public && !public_only)
        this->create_from_private(other);
}

Key::~Key()
{
    EVP_PKEY_free(this->key);
}

bool Key::extract_private()
{
    std::size_t length = 0;
    if(!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PRIV_KEY, nullptr, 0, &length))
    {
        std::cerr << "[-] Failed getting private key length: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    this->private_key.resize(length);
    if(!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PRIV_KEY, this->private_key.data(), this->private_key.size(), nullptr))
    {
        std::cerr << "[-] Failed getting private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        this->private_key.clear();
        return false;
    } 

    return true;
}

bool Key::extract_public()
{
    std::size_t length = 0;
    if(!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &length))
    {
        std::cerr << "[-] Failed getting private key length: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    this->public_key.resize(length);
    if(!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PUB_KEY, this->public_key.data(), this->public_key.size(), nullptr))
    {
        std::cerr << "[-] Failed getting private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        this->public_key.clear();
        return false;
    } 

    return true;
}

bool Key::create(const std::string& name) //add seed
{
    this->name = name;
    this->is_public = false;
    this->private_key.clear();
    this->public_key.clear();

    //initialize context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, name.c_str(), nullptr);
    if(ctx==nullptr)
        return false;

    int result = EVP_PKEY_keygen_init(ctx);
    if(result<=0)
    {
        std::cerr << "[-] Cannot initialize key generator: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    //only for ml-dsa in case of deterministic seed
    /*
    std::size_t pos = name.find("ML-DSA");
    if(pos!=std::string::npos)
    {
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                  const_cast<unsigned char*>(seed), seed_len),
                OSSL_PARAM_END
            };
        if(EVP_PKEY_CTX_set_params(ctx, params) <= 0) 
        {
            std::cerr << "[-] Cannot create key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
    }
    */

    /*
    //I don*t think I would need this
    std::size_t pos = name.find("ML-KEM");
    if(pos!=std::string::npos)
    {
        //set kyber variant
        if(EVP_PKEY_CTX_ctrl_str(ctx, "parameter_set", "Kyber_768_r2") <= 0) 
        {
            std::cerr << "[-] Cannot set kyber parameters: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
    }
    */

    result = EVP_PKEY_keygen(ctx, &this->key);
    if(result<=0)
    {
        std::cerr << "[-] Cannot create key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);


    //extract private and public key
    if(!this->extract_private())
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
        return false;
    }

    if(!this->extract_public())
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
        return false;
    }

    return true;
}

bool Key::create_from_private(const std::string& name, const std::vector<unsigned char>& data)
{
    if(this->key!=nullptr)
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
    }

    this->name = name;
    this->is_public = false;
    this->private_key.clear();
    this->public_key.clear();

    //initialize context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, name.c_str(), nullptr);
    if(ctx==nullptr)
        return false;

    if(EVP_PKEY_fromdata_init(ctx) <= 0) 
    {
        std::cerr << "[-] Cannot initialize ctx from data: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void*)data.data(), data.size()),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_fromdata(ctx, &this->key, EVP_PKEY_PRIVATE_KEY, params) <= 0) {
        std::cerr << "[-] Cannot create key from data: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    //extract private key ->we could theoretically also just copy the input here
    if(!this->extract_private())
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
        return false;
    }

    //extract public key
    if(!this->extract_public())
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
        return false;
    }

    return true;
}

bool Key::create_from_public(const std::string& name, const std::vector<unsigned char>& data)
{
    if(this->key!=nullptr)
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
    }

    this->name = name;
    this->is_public = false;
    this->private_key.clear();
    this->public_key.clear();

    //initialize context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, name.c_str(), nullptr);
    if(ctx==nullptr)
        return false;

    if(EVP_PKEY_fromdata_init(ctx) <= 0) 
    {
        std::cerr << "[-] Cannot initialize ctx from data: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)data.data(), data.size()),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_fromdata(ctx, &this->key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        std::cerr << "[-] Cannot create key from data: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    //extract public key ->we could theoretically also just copy the input here
    if(!this->extract_public())
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
        return false;
    }
    return true;
}

bool Key::create_from_public(const Key& other)
{
    if(!this->create_from_public(other.name, other.public_key))
        return false;

    return true;
}

bool Key::create_from_private(const Key& other)
{
    if(other.is_public)
        return false;
    if(!this->create_from_private(other.name, other.private_key))
        return false;

    return true;
}


Key* Key::derive_public()
{
    if(this->key==nullptr)
        return nullptr;

    Key* k = new Key();
    if(!k->create_from_public(this->name, this->public_key))
    {
        delete k;
        return nullptr;
    }
    return k;
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

bool Key::encapsulate(std::vector<unsigned char>& cipher, std::vector<unsigned char>& secret)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(this->key, nullptr);
    if(ctx==nullptr)
        return false;

    if(EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0)
    {
        std::cerr << "[-] Failed create ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    std::size_t length_c = 0, length_s = 0;
    if(EVP_PKEY_encapsulate(ctx, nullptr, &length_c, nullptr, &length_s) <= 0)
    {
        std::cerr << "[-] Failed getting lengths: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    cipher.resize(length_c);
    secret.resize(length_s);
    if(EVP_PKEY_encapsulate(ctx, cipher.data(), &length_c, secret.data(), &length_s) <= 0)
    {
        std::cerr << "[-] Failed encapsulate: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool Key::decapsulate(std::vector<unsigned char>& cipher, std::vector<unsigned char>& secret)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(this->key, nullptr);
    if(ctx==nullptr)
        return false;

    if(EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0)
    {
        std::cerr << "[-] Failed create ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    std::size_t length_c = 0;
    if(EVP_PKEY_decapsulate(ctx, nullptr, &length_c, secret.data(), secret.size()) <= 0)
    {
        std::cerr << "[-] Failed getting lengths: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    cipher.resize(length_c);
    if(EVP_PKEY_decapsulate(ctx, cipher.data(), &length_c, secret.data(), secret.size()) <= 0)
    {
        std::cerr << "[-] Failed decapsulate: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}



Key* convert_ed25519_to_x25519_private(Key* priv)
{
    std::vector<unsigned char> data = priv->get_private();
    std::vector<unsigned char> out;
    out.resize(SHA512_DIGEST_LENGTH);

    //hash
    if(SHA512(data.data(), data.size(), out.data())==0)
    {
        std::cerr << "[-] SHA512 failed: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return nullptr;
    }

    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;

    out.resize(data.size());

    Key* k = new Key();
    std::string s("X25519");
    if(!k->create_from_private(s, out))
    {
        delete k;
        return nullptr;
    }

    return k;
}


Key* convert_ed25519_to_x25519_public(Key* pub)
{
    std::vector<unsigned char> data = pub->get_public();

    std::vector<unsigned char> out;
    out.resize(data.size());

    BN_CTX* ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM* y = BN_CTX_get(ctx);
    BIGNUM* one = BN_CTX_get(ctx);
    BIGNUM* num = BN_CTX_get(ctx);
    BIGNUM* den = BN_CTX_get(ctx);
    BIGNUM* inv_den = BN_CTX_get(ctx);
    BIGNUM* u = BN_CTX_get(ctx);
    BIGNUM* p = BN_CTX_get(ctx);

    //set modulus for the X25519 curve (p = 2^255 - 19)
    BN_hex2bn(&p, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED");

    data[31] &= 0x7F; //clear sign bit
    BN_lebin2bn(data.data(), data.size(), y);
    BN_one(one);

    BN_add(num, one, y); //1+y
    BN_sub(den, one, y); //1-y

    if(BN_mod_inverse(inv_den, den, p, ctx)==nullptr)
    {
        std::cerr << "[-] Inverse failed: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return nullptr;
    }

    //final result
    BN_mod_mul(u, num, inv_den, p, ctx); //make sure modulo fits
    BN_bn2lebinpad(u, out.data(), out.size());

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    Key* k = new Key();
    std::string s("X25519");
    if(!k->create_from_public(s, out))
    {
        std::cout << "Key creation failed" << std::endl;
        delete k;
        return nullptr;
    }

    return k;
}