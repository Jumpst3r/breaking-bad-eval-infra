// adapted from https://botan.randombit.net/handbook/api_ref/cipher_modes.html#cipher-modes

#include <botan/rng.h>
#include <botan/pk_keys.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/curve25519.h>
#include <botan/hex.h>
#include <iostream>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/ecdh.h>
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
#include <botan/pk_keys.h>

#include <fstream>
#include <iostream>

std::vector<std::unique_ptr<Botan::Private_Key>> load_keys(std::string filename)
{
    std::ifstream file(filename, std::fstream::binary);

    Botan::DataSource_Stream ds(file, "<std::ifstream>");

    std::vector<std::unique_ptr<Botan::Private_Key>> res;
    while (!ds.end_of_data() && res.size() < 2)
    {
        try
        {
            res.push_back(Botan::PKCS8::load_key(ds));
        }
        catch (Botan::Decoding_Error)
        {
        }

        std::cout << "Bytes read: " << ds.get_bytes_read()
                  << " End: " << ds.end_of_data() << "\n";
    }
    // res.push_back(Botan::PKCS8::load_key(ds));
    return res;
}

int main(int argc, char **argv)
{
    std::string ukey = (const char *)argv[1];
    std::string mode;
    std::string hmacmode = "HMAC";

    char *umode = argv[2];
    std::string umode_str(umode);
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
    else if (!strcmp(umode, "chacha-poly1305"))
    {
        botan_cipher_id = "ChaCha20Poly1305";
        mode.insert(0, botan_cipher_id);
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
    else if (!strcmp(umode, "hmac-sha1"))
    {
        std::string id = "(SHA-160)";
        hmacmode.insert(4, id);
        opmode = 2;
    }
    else if (!strcmp(umode, "hmac-blake2"))
    {
        std::string id = "(Blake2b(512))";
        hmacmode.insert(4, id);
        opmode = 2;
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
    else if (umode_str.find("ecdsa") != std::string::npos)
    {
        // from https://github.com/randombit/botan/blob/master/src/examples/ecdsa.cpp
        // const std::vector<uint8_t> rnd_seed = Botan::hex_decode(ukey);
        Botan::AutoSeeded_RNG rng;
        // rng.add_entropy(rnd_seed.data(), rnd_seed.size());

        auto keys = load_keys(ukey);
        if (keys.size() < 1)
        {
            std::cerr << "could not load key from file\n";
            return -4;
        }
        Botan::ECDSA_PrivateKey key = Botan::ECDSA_PrivateKey(
            keys[0]->algorithm_identifier(),
            keys[0]->private_key_bits());
        std::string text("This is a tasty burger!");
        std::vector<uint8_t> data(text.data(), text.data() + text.length());
        // sign data
        Botan::PK_Signer signer(key, rng, "EMSA1(SHA-256)");
        signer.update(data);
        std::vector<uint8_t> signature = signer.signature(rng);
        std::cout << "Signature:" << std::endl
                  << Botan::hex_encode(signature);
        // verify signature
        Botan::PK_Verifier verifier(key, "EMSA1(SHA-256)");
        verifier.update(data);
        std::cout << std::endl
                  << "is " << (verifier.check_signature(signature) ? "valid" : "invalid");
        return 0;
    }
    else if (!strcmp(umode, "rsa"))
    {
        // const std::vector<uint8_t> rnd_seed = Botan::hex_decode(ukey);
        Botan::AutoSeeded_RNG rng;
        // rng.add_entropy(rnd_seed.data(), rnd_seed.size());

        auto keys = load_keys(ukey);
        if (keys.size() < 1)
        {
            std::cerr << "could not load key from file\n";
            return -4;
        }
        Botan::RSA_PrivateKey key = Botan::RSA_PrivateKey(
            keys[0]->algorithm_identifier(),
            keys[0]->private_key_bits());

        std::string text("This is a tasty burger!");
        std::vector<uint8_t> data(text.data(), text.data() + text.length());
        // sign data
        Botan::PK_Signer signer(key, rng, "EMSA1(SHA-256)");
        signer.update(data);
        std::vector<uint8_t> signature = signer.signature(rng);
        std::cout << "Signature:" << std::endl
                  << Botan::hex_encode(signature);
        // verify signature
        Botan::PK_Verifier verifier(key, "EMSA1(SHA-256)");
        verifier.update(data);
        std::cout << std::endl
                  << "is " << (verifier.check_signature(signature) ? "valid" : "invalid");
        return 0;
    }
    else if (umode_str.find("curve25519") != std::string::npos)
    {
        Botan::AutoSeeded_RNG rng;

        std::string kdf = "KDF2(SHA-256)";

        auto keys = load_keys(ukey);

        if (keys.size() < 2)
        {
            std::cerr << "Could not load two keys from file\n";
            return -1;
        }

        Botan::Curve25519_PrivateKey keyA = Botan::Curve25519_PrivateKey(
            keys[0]->algorithm_identifier(),
            keys[0]->private_key_bits());
        Botan::Curve25519_PrivateKey keyB = Botan::Curve25519_PrivateKey(
            keys[1]->algorithm_identifier(),
            keys[1]->private_key_bits());

        Botan::PK_Key_Agreement ecdhA(keyA, rng, kdf);
        Botan::PK_Key_Agreement ecdhB(keyB, rng, kdf);
        // Agree on shared secret and derive symmetric key of 256 bit length
        Botan::secure_vector<uint8_t> sA = ecdhA.derive_key(32, keyB.public_value()).bits_of();
        Botan::secure_vector<uint8_t> sB = ecdhB.derive_key(32, keyA.public_value()).bits_of();

        if (sA != sB)
            return 1;

        std::cout << "agreed key: " << std::endl
                  << Botan::hex_encode(sA);
        return 0;
    }
    else if (umode_str.find("ecdh") != std::string::npos)
    {
        // from https://github.com/randombit/botan/blob/master/src/examples/ecdh.cpp
        Botan::AutoSeeded_RNG rng;

        std::string kdf = "KDF2(SHA-256)";

        auto keys = load_keys(ukey);

        if (keys.size() < 2)
        {
            std::cerr << "Could not load two keys from file\n";
            return -1;
        }

        Botan::ECDH_PrivateKey keyA = Botan::ECDH_PrivateKey(
            keys[0]->algorithm_identifier(),
            keys[0]->private_key_bits());
        Botan::ECDH_PrivateKey keyB = Botan::ECDH_PrivateKey(
            keys[1]->algorithm_identifier(),
            keys[1]->private_key_bits());
        // generate ECDH keys
        // Botan::ECDH_PrivateKey keyA(rng, domain);
        // Botan::ECDH_PrivateKey keyB(rng, domain);
        // Construct key agreements
        Botan::PK_Key_Agreement ecdhA(keyA, rng, kdf);
        Botan::PK_Key_Agreement ecdhB(keyB, rng, kdf);
        // Agree on shared secret and derive symmetric key of 256 bit length
        Botan::secure_vector<uint8_t> sA = ecdhA.derive_key(32, keyB.public_value()).bits_of();
        Botan::secure_vector<uint8_t> sB = ecdhB.derive_key(32, keyA.public_value()).bits_of();

        if (sA != sB)
            return 1;

        std::cout << "agreed key: " << std::endl
                  << Botan::hex_encode(sA);
        return 0;
    }
    else
    {
        std::cout << "unsupported algorithm\n";
        return -1;
    }
    // const std::string path = argv[1];
    // printf("loading key\n");
    // Botan::DataSource_Stream in(path, true);
    // printf("loaded key\n");
    // std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(in));
    // printf("decoded key\n");
    // std::string text("This is a tasty burger!");
    // std::vector<uint8_t> data(text.data(),text.data()+text.length());
    // // sign data
    // Botan::PK_Signer signer(*key, rng, "EMSA1(SHA-256)");
    // signer.update(data);
    // std::vector<uint8_t> signature = signer.signature(rng);
    // std::cout << "Signature:" << std::endl << Botan::hex_encode(signature) << std::flush;

    if (opmode == 1)
    {
        const std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
        std::vector<uint8_t> key = Botan::hex_decode(ukey);
        std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create(mode, Botan::ENCRYPTION);
        if (!enc->valid_keylength(key.size()))
        {
            key.resize(enc->minimum_keylength(), 0);
        }
        enc->set_key(key);

        // generate fresh nonce (IV)
        Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

        // Copy input data to a buffer that will be encrypted
        Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());

        enc->start(iv);
        enc->finish(pt);

        std::cout << "successful";
    }
    else if (opmode == 2)
    {
        // hmac
        const std::vector<uint8_t> key = Botan::hex_decode(ukey);
        const std::vector<uint8_t> data = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");
        std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create(hmacmode));
        if (!mac)
            return 1;
        mac->set_key(key);
        mac->start();
        mac->update(data);
        Botan::secure_vector<uint8_t> tag = mac->final();
        std::cout << "successful";
    }
    else
    {
        std::cout << "unsuccessful";
        return -1;
    }

    return 0;
}
