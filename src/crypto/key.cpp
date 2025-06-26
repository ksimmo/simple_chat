#include <iostream>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>

#include "crypto/key.h"

Key* create_x25519_from_ed25519_private(Key* priv)
{
    std::vector<unsigned char> data;
    if(!priv->extract_private(data))
        return nullptr;

    data[0] &= 248;
    data[31] &= 127;
    data[31] |= 64;

    Key* k = new Key();
    std::string s("X25519");
    if(!k->create_from_private(s, data))
    {
        delete k;
        return nullptr;
    }

    return k;
}

Key* create_x25519_from_ed25519_public(Key* priv)
{
    std::vector<unsigned char> data;
    if(!priv->extract_public(data))
        return nullptr;

    BN_CTX* ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM* y = BN_CTX_get(ctx);
    BIGNUM* one = BN_CTX_get(ctx);
    BIGNUM* num = BN_CTX_get(ctx);
    BIGNUM* den = BN_CTX_get(ctx);
    BIGNUM* inv_den = BN_CTX_get(ctx);
    BIGNUM* u = BN_CTX_get(ctx);
    BIGNUM* p = BN_CTX_get(ctx);

    BN_hex2bn(&p, "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED");

    std::vector<unsigned char> y_bytes(data);
    data[31] &= 0x7F; //clear sign bit
    BN_lebin2bn(y_bytes.data(), y_bytes.size(), y);

    BN_one(one);

    BN_mod_add(num, one, y, p, ctx);
    BN_mod_sub(den, one ,y, p, ctx);
    BN_mod_inverse(inv_den, den, p, ctx);
    BN_mod_mul(u, num, inv_den, p, ctx);

    std::vector<unsigned char> pub;
    pub.resize(data.size());
    BN_bn2lebinpad(u, pub.data(), pub.size());

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    Key* k = new Key();
    std::string s("X25519");
    if(!k->create_from_public(s, pub))
    {
        delete k;
        return nullptr;
    }

    return k;
}


//--------------------------------------------

Key::Key()
{
}

Key::Key(Key& other, bool public_only)
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

bool Key::create(std::string& name) //add seed
{
    this->name = name;
    this->is_public = false;
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
    return true;
}

bool Key::create_from_private(std::string& name, std::vector<unsigned char>& data)
{
    if(this->key!=nullptr)
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
    }

    this->name = name;
    this->is_public = false;
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
    return true;
}

bool Key::create_from_public(Key& other)
{
    std::vector<unsigned char> data;
    if(!other.extract_public(data))
        return false;
    if(!this->create_from_public(other.name, data))
        return false;

    return true;
}

bool Key::create_from_private(Key& other)
{
    if(other.is_public_only())
        return false;
    std::vector<unsigned char> data;
    if(!other.extract_private(data))
        return false;
    if(!this->create_from_private(other.name, data))
        return false;

    return true;
}

bool Key::create_from_public(std::string& name, std::vector<unsigned char>& data)
{
    if(this->key!=nullptr)
    {
        EVP_PKEY_free(this->key);
        this->key = nullptr;
    }

    this->name = name;
    this->is_public = false;
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
    return true;
}

bool Key::extract_private(std::vector<unsigned char>& data)
{
    std::size_t length = 0;
    if(!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PRIV_KEY, nullptr, 0, &length))
    {
        std::cerr << "[-] Failed getting private key length: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    data.resize(length);
    if(!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PRIV_KEY, data.data(), data.size(), nullptr))
    {
        std::cerr << "[-] Failed getting private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    return true;
}

bool Key::extract_public(std::vector<unsigned char>& data)
{
    std::size_t length = 0;
    if(!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &length))
    {
        std::cerr << "[-] Failed getting private key length: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    data.resize(length);
    if(!EVP_PKEY_get_octet_string_param(this->key, OSSL_PKEY_PARAM_PUB_KEY, data.data(), data.size(), nullptr))
    {
        std::cerr << "[-] Failed getting private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    } 

    return true;
}

Key* Key::get_public()
{
    if(this->key==nullptr)
        return nullptr;

    std::vector<unsigned char> data;
    if(!this->extract_public(data))
        return nullptr;

    Key* k = new Key();
    if(!k->create_from_public(this->name, data))
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




///////////////////////////
/*
//old code (keep for safety)
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
*/