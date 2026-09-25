/*
 * Phase 0 – Ed25519 keygen + XChaCha20-Poly1305 encrypt/decrypt + tamper detection
 * Pure libsodium (C++)
 */

#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <string>

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    std::cout << std::dec << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialization failed\n";
        return 1;
    }

    std::cout << "=== Phase 0: libsodium C++ demo ===\n\n";

    // 1. Generate Ed25519 keypair
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    std::cout << "Ed25519 private key (hex): ";
    print_hex(sk, crypto_sign_SECRETKEYBYTES);
    std::cout << "Ed25519 public  key (hex): ";
    print_hex(pk, crypto_sign_PUBLICKEYBYTES);
    std::cout << std::endl;

    // 2. Generate random key for XChaCha20-Poly1305
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    randombytes_buf(key, sizeof key);

    const char *message = "Hello from Nest - Phase 0. This message is authentic.";
    size_t message_len = std::strlen(message);

    std::cout << "Original message: " << message << std::endl;

    // 3. Encrypt
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> ciphertext(message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        reinterpret_cast<const unsigned char*>(message), message_len,
        nullptr, 0,          // no additional data
        nullptr,             // nsec (not used)
        nonce, key
    );

    std::cout << "Ciphertext (hex): ";
    print_hex(ciphertext.data(), ciphertext_len);
    std::cout << std::endl;

    // 4. Decrypt + verify
    std::vector<unsigned char> decrypted(message_len);
    unsigned long long decrypted_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,
            ciphertext.data(), ciphertext_len,
            nullptr, 0,
            nonce, key) != 0)
    {
        std::cerr << "ERROR: authentication failed\n";
        return 1;
    }

    std::cout << "Decrypted OK: " << std::string(reinterpret_cast<char*>(decrypted.data()), decrypted_len) << std::endl;

    // 5. Tamper detection
    std::cout << "\n--- Tampering test ---\n";
    ciphertext[20] ^= 0x01;   // flip one bit

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,
            ciphertext.data(), ciphertext_len,
            nullptr, 0,
            nonce, key) != 0)
    {
        std::cout << "Tampering correctly detected – decryption failed as expected.\n";
    } else {
        std::cout << "ERROR: tampered message was accepted!\n";
        return 1;
    }

    std::cout << "\nPhase 0 complete.\n";
    return 0;
}
