#include <iostream>

#include "crypto/crypto.h"

int main(int argc, char* argv[])
{
    //lets run a few tests here
    std::string a = "ML-DSA-87";

    //if not exists -> create private/public key pair (long term identity key)
    Key* k = new Key();
    k->create(a);
    std::vector<unsigned char> priv = k->get_private();
    std::vector<unsigned char> pub = k->get_public();
    std::cout << "test" << std::endl;
    std::cout << "test2 " << priv.size() << std::endl;
    std::cout << "test3 " << pub.size() << std::endl;
    std::string s1 = "";
    std::string s2 = "";
    for (std::size_t i = 0; i < priv.size(); i++)
    {
        //printf("%02x", priv[i]);
        s1 += std::to_string((int)priv[i]) + ",";
    }
    for (std::size_t i = 0; i < pub.size(); i++)
    {
        //printf("%02x", priv[i]);
        s1 += std::to_string((int)pub[i]) + ",";
    }
    std::cout << "Private: " << s1 << std::endl;
    std::cout<< "Public: " << s2 << std::endl;

    Key* kk = new Key();
    bool test1 = kk->create_from_private(a, priv);
    std::vector<unsigned char> priv2 = kk->get_private();

    Key* kkk = new Key();
    bool test2 = kkk->create_from_public(a, pub);
    std::vector<unsigned char> pub2 = kkk->get_public();

    std::cout << "create " << test1 << " " << test2 << std::endl;

    test1 = true;
    for(int i=0;i<priv.size();i++)
    {
        if(priv[i]!=priv2[i])
        {
            test1 = false;
            break;
        }
    }

    test2 = true;
    for(int i=0;i<pub.size();i++)
    {
        if(pub[i]!=pub2[i])
        {
            test1 = false;
            break;
        }
    }
    std::cout << "extract " << test1 << " " << test2 << std::endl;

    //test signature
    std::vector<unsigned char> message = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<unsigned char> signed_message;
    test1 = kk->sign_data(message, signed_message);
    test2 = kk->verify_signature(message, signed_message);
    std::cout << "sign " << test1 << " " << test2 << std::endl;

    Key* k3 = new Key();
    k3->create(a);
    test2 = k3->verify_signature(message, signed_message);
    std::cout << "sign " << test1 << " " << test2 << std::endl;


    delete kk;
    delete kkk;
    delete k3;

    a = "ML-KEM-768";
    k3 = new Key();
    k3->create(a);
    delete k3;



    //create ed25519 keypair
    kk = new Key();
    a = "ED25519";
    kk->create(a);

    priv = kk->get_private();
    pub = kk->get_public();

    s1 = "";
    s2 = "";
    for(int i=0;i<priv.size();i++)
    {
        s1 += std::to_string((int)priv[i]) + ",";
        s2 += std::to_string((int)pub[i]) + ",";
    }
    delete kk;

    std::cout << s1 << std::endl;
    std::cout << s2 << std::endl;

    //create x25519 keypair
    kk = new Key();
    a = "X25519";
    kk->create(a);

    priv = kk->get_private();
    pub = kk->get_public();

    s1 = "";
    s2 = "";
    for(int i=0;i<priv.size();i++)
    {
        s1 += std::to_string((int)priv[i]) + ",";
        s2 += std::to_string((int)pub[i]) + ",";
    }
    delete kk;

    std::cout << s1 << std::endl;
    std::cout << s2 << std::endl;

    return 0;
}