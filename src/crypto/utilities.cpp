#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

#include "logger.h"
#include "crypto/utilities.h"

bool dh(Key& priv, Key& pub, std::vector<unsigned char>& secret)
{
    Logger& logger = Logger::instance();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
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

    if(EVP_PKEY_derive_set_peer(ctx, pub) <= 0)
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

    secret.clear();
    secret.resize(length);
    if(EVP_PKEY_derive(ctx, secret.data(), &length) <= 0)
    {
        std::cerr << "[-] Cannot derive secret: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_PKEY_CTX_free(ctx);
        secret.clear();
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool kdf(const std::vector<unsigned char>& secret, std::vector<unsigned char>& output, std::size_t length, const std::vector<unsigned char>& salt, const std::vector<unsigned char>& info)
{
    Logger& logger = Logger::instance();
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

    std::vector<OSSL_PARAM> params;
    params.push_back(OSSL_PARAM_construct_utf8_string("digest", (char*)"sha256", (std::size_t)6));
    params.push_back(OSSL_PARAM_construct_octet_string("key", (void*)secret.data(), secret.size()));
    if(salt.size()>0)
        params.push_back(OSSL_PARAM_construct_octet_string("salt", (void*)salt.data(), salt.size()));
    if(info.size()>0)
        params.push_back(OSSL_PARAM_construct_octet_string("info", (void*)info.data(), info.size()));
    params.push_back(OSSL_PARAM_construct_end());
    /*
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)"sha256", (std::size_t)6),
        OSSL_PARAM_construct_octet_string("key", (void*)secret.data(), secret.size()),
        //OSSL_PARAM_construct_octet_string("salt", (void*)salt.data(), salt.size()),
        //OSSL_PARAM_construct_octet_string("info", (void*)info.data(), info.size()),
        OSSL_PARAM_construct_end()
    };
    */

    if(EVP_KDF_CTX_set_params(ctx, params.data()) <= 0) {
        std::cerr << "[-] Failed setting ctx params: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(ctx);
        return false;
    }

    output.clear();
    output.resize(length);
    if(EVP_KDF_derive(ctx, output.data(), length, nullptr)<=0)
    {
        std::cerr << "[-] Cannot derive kdf: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(ctx);
        output.clear();
        return false;
    }

    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);

    return true;
}


//AEAD
bool create_iv(std::vector<unsigned char>& iv, std::size_t length)
{
    Logger& logger = Logger::instance();
    iv.resize(length); //12 or 16 depending on mode (gcm vs cbc)
    if(!RAND_bytes(iv.data(), length))
    {
        std::cerr << "[-] Cannot create iv: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        iv.clear();
        return false;
    }

    return true;
}

bool aead_encrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data, std::vector<unsigned char>& cipher, const std::vector<unsigned char>& iv) //, std::vector<unsigned char>& tag)
{
    Logger& logger = Logger::instance();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(ctx==nullptr)
    {
        std::cerr << "[-] Cannot create cipher ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())!=1) //EVP_aes_256_gcm()
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

    /*
    tag.resize(16);
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()))
    {
        std::cerr << "[-] Cannot set tag: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }*/

    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool aead_decrypt(const std::vector<unsigned char>& key, std::vector<unsigned char>& data, const std::vector<unsigned char>& cipher, const std::vector<unsigned char>& iv) //, std::vector<unsigned char>& tag)
{
    Logger& logger = Logger::instance();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(ctx==nullptr)
    {
        std::cerr << "[-] Cannot create cipher ctx: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return false;
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())!=1) //EVP_aes_256_gcm()
    {
        std::cerr << "[-] Cannot initialize decrpytion: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /*
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data())!=1)
    {
        std::cerr << "[-] Cannot set tag: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }*/

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


//x3dh according to signal protocol
bool x3dh_alice(const std::vector<unsigned char>& alice_priv_id, std::vector<unsigned char>& alice_pub_ep, 
                const std::vector<unsigned char>& bob_pub_id, const std::vector<unsigned char>& bob_pub_spk, const std::vector<unsigned char>& bob_pub_ot,
                const std::vector<unsigned char>& signature, const std::string& id_type, const std::string& other_type, std::vector<unsigned char>& final_secret)
{
    Logger& logger = Logger::instance();
    //create keys (ALICE)
    Key alice_id = Key(); //identity key (ed25519)
    if(!alice_id.create_from_private(id_type, alice_priv_id))
        return false;

    Key alice_ep = Key(); //create new ephemeral key (X25519)
    if(!alice_ep.create(other_type))
        return false;

    std::vector<unsigned char> temp = alice_ep.get_public();
    alice_pub_ep.clear();
    alice_pub_ep.insert(alice_pub_ep.end(), temp.begin(), temp.end());

    Key alice_id_conv = Key();
    if(!convert_ed25519_to_x25519_private(alice_id, alice_id_conv))
        return false;

    //create keys (BOB)
    Key bob_id = Key(); //identity key
    if(!bob_id.create_from_public(id_type, bob_pub_id))
        return false;

    Key bob_id_conv = Key(); //convert id key to X25519
    if(!convert_ed25519_to_x25519_public(bob_id, bob_id_conv))
        return false;

    Key bob_spk = Key(); //signed prekey (X25519)
    if(!bob_spk.create_from_public(other_type, bob_pub_spk))
        return false;

    Key bob_ot = Key();
    if(bob_pub_ot.size()>0) //only use onetime prekey if available
    {
        if(!bob_ot.create_from_public(other_type, bob_pub_ot))
            return false;
    }


    //first of all verify signature
    if(!bob_id.verify_signature(bob_pub_spk, signature))
    {
        std::cerr << "Prekey signature could not be verified!" << std::endl;
        return false;
    }

    //perform dh
    std::vector<unsigned char> secret1;
    std::vector<unsigned char> secret2;
    std::vector<unsigned char> secret3;
    std::vector<unsigned char> secret4;
    if(!dh(alice_id_conv, bob_spk, secret1))
        return false;
    if(!dh(alice_ep, bob_id_conv, secret2))
        return false;
    if(!dh(alice_ep, bob_spk, secret3))
        return false;
    if(bob_pub_ot.size()>0) //only if onetime prekey is available
    {
        if(!dh(alice_ep, bob_ot, secret4))
            return false;
    }

    //concatenate secrets
    std::vector<unsigned char> secret_combined;    
    secret_combined.insert(secret_combined.end(), secret1.begin(), secret1.end());
    secret_combined.insert(secret_combined.end(), secret2.begin(), secret2.end());
    secret_combined.insert(secret_combined.end(), secret3.begin(), secret3.end());
    secret_combined.insert(secret_combined.end(), secret4.begin(), secret4.end());

    //get final secret
    if(!kdf(secret_combined, final_secret, 32))
        return false;

    return true;
}

bool x3dh_bob(const std::vector<unsigned char>& bob_priv_id, const std::vector<unsigned char>& bob_priv_spk, 
                const std::vector<unsigned char>& bob_priv_ot, const std::vector<unsigned char>& alice_pub_id, const std::vector<unsigned char>& alice_pub_ep,
                const std::string& id_type, const std::string& other_type, std::vector<unsigned char>& final_secret)
{
    //create keys (BOB)
    Key bob_id = Key(); //identity key (ED25519)
    if(!bob_id.create_from_private(id_type, bob_priv_id))
        return false;

    Key bob_id_conv = Key(); //convert id key to X25519
    if(!convert_ed25519_to_x25519_private(bob_id, bob_id_conv))
        return false;

    Key bob_spk = Key(); //signed prekey (X25519)
    if(!bob_spk.create_from_private(other_type, bob_priv_spk))
        return false;

    Key bob_ot = Key();
    if(bob_priv_ot.size()>0)
    {
        if(!bob_ot.create_from_private(other_type, bob_priv_ot)) //onetime prekey (X25519)
            return false;
    }

    //create keys (ALICE)
    Key alice_id = Key(); //identity key (ED25519)
    if(!alice_id.create_from_public(id_type, alice_pub_id))
        return false;

    Key alice_id_conv = Key(); //convert id key to X25519
    if(!convert_ed25519_to_x25519_public(alice_id, alice_id_conv))
        return false;

    Key alice_ep = Key(); //ephemeral key (X25519)
    if(!alice_ep.create_from_public(other_type, alice_pub_ep))
        return false;

    //perform dh
    std::vector<unsigned char> secret1;
    std::vector<unsigned char> secret2;
    std::vector<unsigned char> secret3;
    std::vector<unsigned char> secret4;
    if(!dh(bob_spk, alice_id_conv, secret1))
        return false;
    if(!dh(bob_id_conv, alice_ep, secret2))
        return false;
    if(!dh(bob_spk, alice_ep, secret3))
        return false;
    if(bob_priv_ot.size()>0)
    {
        if(!dh(bob_ot, alice_ep, secret4))
            return false;
    }

    //concatenate single secrects
    std::vector<unsigned char> secret_combined;
    secret_combined.insert(secret_combined.end(), secret1.begin(), secret1.end());
    secret_combined.insert(secret_combined.end(), secret2.begin(), secret2.end());
    secret_combined.insert(secret_combined.end(), secret3.begin(), secret3.end());
    secret_combined.insert(secret_combined.end(), secret4.begin(), secret4.end());

    //get final secret
    if(!kdf(secret_combined, final_secret, 32))
        return false;

    return true;
}