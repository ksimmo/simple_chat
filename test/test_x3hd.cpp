#include <iostream>

#include "crypto/crypto.h"

int main(int argc, char* argv[])
{
    //lets run a few tests here
    std::string name_ed = "ED25519";
    std::string name_x = "X25519";

    //create keys bob
    Key* identity_bob_priv = new Key();
    identity_bob_priv->create(name_ed);
    Key* identity_bob_pub = identity_bob_priv->get_public();

    //convert ed25519 to x25519 TODO: this does not work as intended
    Key* identity_bob_priv_conv = convert_ed25519_to_x25519_private(identity_bob_priv);
    if(identity_bob_priv_conv==nullptr)
    {
        std::cout << "Private key conversion failed!" << std::endl;
        delete identity_bob_priv;
        delete identity_bob_pub;
        return 0;
    }
    
    Key* identity_bob_pub_conv = convert_ed25519_to_x25519_public(identity_bob_pub);
    if(identity_bob_pub_conv==nullptr)
    {
        std::cout << "Public key conversion failed!" << std::endl;
        delete identity_bob_priv;
        delete identity_bob_pub;
        delete identity_bob_priv_conv;
        return 0;
    }

    //signed prekey
    Key* signed_prekey_bob_priv = new Key();
    signed_prekey_bob_priv->create(name_x);
    Key* signed_prekey_bob_pub = signed_prekey_bob_priv->get_public();

    //sign signed_prekey
    std::vector<unsigned char> prekey_pub;
    signed_prekey_bob_priv->extract_public(prekey_pub);
    std::vector<unsigned char> prekey_signature_bob;
    identity_bob_priv->sign_data(prekey_pub, prekey_signature_bob);

    //one-time prekey
    Key* onetime_prekey_bob_priv = new Key();
    onetime_prekey_bob_priv->create(name_x);
    Key* onetime_prekey_bob_pub = onetime_prekey_bob_priv->get_public();

    ///////////////////////
    //Alice

    //check bobs signed prekey signature
    bool status = identity_bob_pub->verify_signature(prekey_pub, prekey_signature_bob);
    if(status)
        std::cout << "Pre-Key signature is valid!" << std::endl;
    else
    {
        std::cout << "Pre-Key signature is not valid!" << std::endl;
    }

    //create keys
    Key* identity_alice_priv = new Key();
    identity_alice_priv->create(name_ed);
    Key* identity_alice_pub = identity_alice_priv->get_public();

    Key* identity_alice_priv_conv = convert_ed25519_to_x25519_private(identity_alice_priv);
    Key* identity_alice_pub_conv = convert_ed25519_to_x25519_public(identity_alice_pub);

    //generate ephemeral key
    Key* ephemeral_alice_priv = new Key();
    ephemeral_alice_priv->create(name_x);
    Key* ephemeral_alice_pub = ephemeral_alice_priv->get_public();

    //derive secrects - Alice
    std::vector<unsigned char> secret1, secret2, secret3, secret4;
    dh(identity_alice_priv_conv, signed_prekey_bob_pub, secret1);
    dh(ephemeral_alice_priv, identity_bob_pub_conv, secret2); //mh this is problematic
    dh(ephemeral_alice_priv, signed_prekey_bob_pub, secret3);
    dh(ephemeral_alice_priv, onetime_prekey_bob_pub, secret4);

    //concatenate secrets
    std::vector<unsigned char> secret_combined;
    secret_combined.insert(secret_combined.end(), secret1.begin(), secret1.end());
    secret_combined.insert(secret_combined.end(), secret2.begin(), secret2.end());
    secret_combined.insert(secret_combined.end(), secret3.begin(), secret3.end());
    secret_combined.insert(secret_combined.end(), secret4.begin(), secret4.end());

    std::vector<unsigned char> out_alice;
    kdf(secret_combined, out_alice, 32);

    std::cout << "Alice finished" << std::endl;

    //do key exchange Bob
    secret1.clear();
    secret2.clear();
    secret3.clear();
    secret4.clear();
    dh(signed_prekey_bob_priv, identity_alice_pub_conv, secret1); //this seems problematic
    dh(identity_bob_priv_conv, ephemeral_alice_pub, secret2);
    dh(signed_prekey_bob_priv, ephemeral_alice_pub, secret3);
    dh(onetime_prekey_bob_priv, ephemeral_alice_pub, secret4);

    //combine secrets
    secret_combined.clear();
    secret_combined.insert(secret_combined.end(), secret1.begin(), secret1.end());
    secret_combined.insert(secret_combined.end(), secret2.begin(), secret2.end());
    secret_combined.insert(secret_combined.end(), secret3.begin(), secret3.end());
    secret_combined.insert(secret_combined.end(), secret4.begin(), secret4.end());

    std::vector<unsigned char> out_bob;
    kdf(secret_combined, out_bob, 32);

    bool equal = true;
    for(int i=0;i<32;i++)
    {
        if(out_alice[i]!=out_bob[i])
        {
            equal = false;
            break;
        }
    }
    std::cout << "Shared secret is equal: " << equal << std::endl;

    //delete keys
    delete identity_bob_priv;
    delete identity_bob_pub;
    delete identity_bob_priv_conv;
    delete identity_bob_pub_conv;
    delete signed_prekey_bob_priv;
    delete signed_prekey_bob_pub;
    delete onetime_prekey_bob_priv;
    delete onetime_prekey_bob_pub;

    delete identity_alice_priv;
    delete identity_alice_pub;
    delete identity_alice_priv_conv;
    delete identity_alice_pub_conv;
    delete ephemeral_alice_priv;
    delete ephemeral_alice_pub;

    return 0;
}