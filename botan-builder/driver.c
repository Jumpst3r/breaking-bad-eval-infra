// adapted from https://botan.randombit.net/handbook/api_ref/cipher_modes.html#cipher-modes

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>
int main(int argc, char **argv)
{
    std::string ukey = (const char *)argv[1];

    char *umode = argv[2];
    std::string botan_cipher_id;
    if (!strcmp(umode, "aes-cbc"))
    {
        botan_cipher_id = "AES-128";
    }
    else if (!strcmp(umode, "aria-cbc"))
    {
        botan_cipher_id = "ARIA-128";
    }
    else if (!strcmp(umode, "cast-cbc"))
    {
        botan_cipher_id = "CAST-128";
    }
    else if (!strcmp(umode, "camellia-cbc"))
    {
        botan_cipher_id = "Camellia-128";
    }
    else if (!strcmp(umode, "des-cbc"))
    {
        botan_cipher_id = "3DES";
    }
    else if (!strcmp(umode, "sm4-cbc"))
    {
        botan_cipher_id = "SM4";
    }
    else if (!strcmp(umode, "chacha_poly1305"))
    {
        botan_cipher_id = "ChaCha20Poly1305-256";
    }

    Botan::AutoSeeded_RNG rng;

    const std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
    const std::vector<uint8_t> key = Botan::hex_decode(ukey);
    std::string mode = "/CBC/PKCS7";
    mode.insert(0, botan_cipher_id);
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create(mode, Botan::ENCRYPTION);
    enc->set_key(key);

    // generate fresh nonce (IV)
    Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

    // Copy input data to a buffer that will be encrypted
    Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());

    enc->start(iv);
    enc->finish(pt);

    std::cout << enc->name() << " with iv " << Botan::hex_encode(iv) << " " << Botan::hex_encode(pt) << "\n";
    return 0;
}
