// adapted from https://botan.randombit.net/handbook/api_ref/cipher_modes.html#cipher-modes

#include <botan/rng.h>
#include <botan/pk_keys.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <iostream>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>
#include <botan/data_src.h>
#include <botan/pubkey.h>
#include <botan/mac.h>


int main(int argc, char **argv)
{
    std::string ukey = (const char *)argv[1];
    std::string mode;
    std::string hmacmode = "HMAC";

    char *umode = argv[2];
    std::string botan_cipher_id;
    int opmode = 0;
    Botan::AutoSeeded_RNG rng;
    if (!strcmp(umode, "aes-cbc"))
    {   
        mode = "PKCS7";
        botan_cipher_id = "AES-128/";
        mode.insert(0, "CBC/");
        mode.insert(0, botan_cipher_id);
        opmode = 1;
    }
    else if (!strcmp(umode, "aes-ctr"))
    {   
        botan_cipher_id = "AES-128/";
        mode.insert(0, "CTR");
        mode.insert(0, botan_cipher_id);
        opmode = 1;
    }
    else if (!strcmp(umode, "aes-gcm"))
    {
        botan_cipher_id = "AES-128/";
        mode.insert(0, "GCM");
        mode.insert(0, botan_cipher_id);
        opmode = 1;
        botan_cipher_id = "AES-128";
        opmode = 1;
    }
    else if (!strcmp(umode, "aria-cbc"))
    {
        mode = "PKCS7";
        botan_cipher_id = "ARIA-128/";
        mode.insert(0, "CBC/");
        mode.insert(0, botan_cipher_id);
        opmode = 1;
    }
    else if (!strcmp(umode, "cast-cbc"))
    {
        mode = "PKCS7";
        botan_cipher_id = "CAST-128/";
        mode.insert(0, "CBC/");
        mode.insert(0, botan_cipher_id);
        opmode = 1;
    }
    else if (!strcmp(umode, "camellia-cbc"))
    {
        mode = "PKCS7";
        botan_cipher_id = "Camellia-128/";
        mode.insert(0, "CBC/");
        mode.insert(0, botan_cipher_id);
        opmode = 1;
    }
    else if (!strcmp(umode, "des-cbc"))
    {
        mode = "PKCS7";
        botan_cipher_id = "3DES/";
        mode.insert(0, "CBC/");
        mode.insert(0, botan_cipher_id);
        opmode = 1;
    }
    else if (!strcmp(umode, "sm4-cbc"))
    {
        mode = "PKCS7";
        botan_cipher_id = "SM4/";
        mode.insert(0, "CBC/");
        mode.insert(0, botan_cipher_id);
        opmode = 1;
    }
    else if (!strcmp(umode, "hmac-sha256"))
    {
        std::string id = "(SHA-256)";
        hmacmode.insert(4, id);
        opmode = 2;
    }
    else if (!strcmp(umode, "hmac-sha512"))
    {
        std::string id = "(SHA-512)";
        hmacmode.insert(4, id);
        opmode = 2;
    }
    else if (!strcmp(umode, "ecdsa") or !strcmp(umode, "rsa"))
    {
        const std::string path = argv[1];
        printf("loading key\n");
        Botan::DataSource_Stream in(path, true);
        printf("loaded key\n");
        std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(in));
        printf("decoded key\n");
        std::string text("This is a tasty burger!");
        std::vector<uint8_t> data(text.data(),text.data()+text.length());
        // sign data
        Botan::PK_Signer signer(*key, rng, "EMSA1(SHA-256)");
        signer.update(data);
        std::vector<uint8_t> signature = signer.signature(rng);
        std::cout << "Signature:" << std::endl << Botan::hex_encode(signature) << std::flush;

    }
    if (opmode == 1){
        const std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
        const std::vector<uint8_t> key = Botan::hex_decode(ukey);
        std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create(mode, Botan::ENCRYPTION);
        enc->set_key(key);

        // generate fresh nonce (IV)
        Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

        // Copy input data to a buffer that will be encrypted
        Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());

        enc->start(iv);
        enc->finish(pt);
    }
    else if (opmode == 2){
        //hmac
        const std::vector<uint8_t> key = Botan::hex_decode(ukey);
        const std::vector<uint8_t> data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");
        std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create(hmacmode));
        if(!mac)
            return 1;
        mac->set_key(key);
        mac->start();
        mac->update(data);
        Botan::secure_vector<uint8_t> tag = mac->final();
    }
    

    return 0;
}
