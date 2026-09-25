/*
 * Phase 1 – Local Secure Channel (Final for this phase)
 * C++ / libsodium
 *
 * Features:
 *  - Persistent Ed25519 identity keys
 *  - X25519 key exchange
 *  - Dual-chain symmetric ratchet (forward secrecy)
 *  - XChaCha20-Poly1305
 *  - Message counters + basic replay protection
 *  - Cleaner disconnect handling
 */

#include <sodium.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

constexpr int PORT = 9876;
constexpr size_t MAX_MSG = 4096;

volatile bool running = true;

void signal_handler(int) {
    running = false;
}

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

bool save_identity(const char* filename, const unsigned char* pk, const unsigned char* sk) {
    FILE* f = fopen(filename, "wb");
    if (!f) return false;
    if (fwrite(pk, 1, crypto_sign_PUBLICKEYBYTES, f) != crypto_sign_PUBLICKEYBYTES) { fclose(f); return false; }
    if (fwrite(sk, 1, crypto_sign_SECRETKEYBYTES, f) != crypto_sign_SECRETKEYBYTES) { fclose(f); return false; }
    fclose(f);
    return true;
}

bool load_identity(const char* filename, unsigned char* pk, unsigned char* sk) {
    FILE* f = fopen(filename, "rb");
    if (!f) return false;
    if (fread(pk, 1, crypto_sign_PUBLICKEYBYTES, f) != crypto_sign_PUBLICKEYBYTES) { fclose(f); return false; }
    if (fread(sk, 1, crypto_sign_SECRETKEYBYTES, f) != crypto_sign_SECRETKEYBYTES) { fclose(f); return false; }
    fclose(f);
    return true;
}

void load_or_create_identity(const char* filename, unsigned char* pk, unsigned char* sk) {
    if (load_identity(filename, pk, sk)) {
        std::cout << "Loaded existing identity from " << filename << "\n";
    } else {
        crypto_sign_keypair(pk, sk);
        if (!save_identity(filename, pk, sk)) {
            std::cerr << "Failed to save identity key\n";
            exit(1);
        }
        std::cout << "Generated and saved new identity to " << filename << "\n";
    }
    std::cout << "Public key: ";
    print_hex(pk, crypto_sign_PUBLICKEYBYTES);
}

bool send_all(int sock, const unsigned char* data, size_t len) {
    uint32_t net_len = htonl(static_cast<uint32_t>(len));
    if (send(sock, &net_len, 4, 0) != 4) return false;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool recv_all(int sock, std::vector<unsigned char>& out) {
    uint32_t net_len = 0;
    if (recv(sock, &net_len, 4, MSG_WAITALL) != 4) return false;
    uint32_t len = ntohl(net_len);
    if (len == 0 || len > MAX_MSG) return false;
    out.resize(len);
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(sock, out.data() + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

struct Ratchet {
    unsigned char send_chain[32];
    unsigned char recv_chain[32];
    uint64_t send_count = 0;
    uint64_t recv_count = 0;

    void init(const unsigned char* root_key) {
        unsigned char info_send[] = "send";
        unsigned char info_recv[] = "recv";
        crypto_generichash(send_chain, 32, root_key, 32, info_send, 4);
        crypto_generichash(recv_chain, 32, root_key, 32, info_recv, 4);
        send_count = 0;
        recv_count = 0;
    }

    void next_send_key(unsigned char* msg_key) {
        unsigned char input[32 + 8];
        memcpy(input, send_chain, 32);
        for (int i = 0; i < 8; i++)
            input[32 + i] = (send_count >> (i * 8)) & 0xff;

        crypto_generichash(msg_key, 32, input, sizeof(input), nullptr, 0);

        unsigned char adv[33];
        memcpy(adv, send_chain, 32);
        adv[32] = 0x01;
        crypto_generichash(send_chain, 32, adv, sizeof(adv), nullptr, 0);

        send_count++;
    }

    void next_recv_key(unsigned char* msg_key) {
        unsigned char input[32 + 8];
        memcpy(input, recv_chain, 32);
        for (int i = 0; i < 8; i++)
            input[32 + i] = (recv_count >> (i * 8)) & 0xff;

        crypto_generichash(msg_key, 32, input, sizeof(input), nullptr, 0);

        unsigned char adv[33];
        memcpy(adv, recv_chain, 32);
        adv[32] = 0x01;
        crypto_generichash(recv_chain, 32, adv, sizeof(adv), nullptr, 0);

        recv_count++;
    }
};

int run_server(const unsigned char* my_pk, const unsigned char* my_sk) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(server_fd, 1) < 0) {
        perror("listen"); return 1;
    }

    std::cout << "Server listening on port " << PORT << "...\n";

    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) { perror("accept"); return 1; }
    std::cout << "Client connected.\n";

    if (!send_all(client_fd, my_pk, crypto_sign_PUBLICKEYBYTES)) {
        std::cerr << "Failed to send public key\n"; return 1;
    }

    std::vector<unsigned char> peer_pk(crypto_sign_PUBLICKEYBYTES);
    if (!recv_all(client_fd, peer_pk)) {
        std::cerr << "Failed to receive peer public key\n"; return 1;
    }
    std::cout << "Peer public key: ";
    print_hex(peer_pk.data(), peer_pk.size());

    unsigned char my_x25519_sk[crypto_scalarmult_SCALARBYTES];
    unsigned char peer_x25519_pk[crypto_scalarmult_BYTES];

    crypto_sign_ed25519_sk_to_curve25519(my_x25519_sk, my_sk);
    if (crypto_sign_ed25519_pk_to_curve25519(peer_x25519_pk, peer_pk.data()) != 0) {
        std::cerr << "Failed to convert peer public key\n";
        return 1;
    }

    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared, my_x25519_sk, peer_x25519_pk) != 0) {
        std::cerr << "Key exchange failed\n"; return 1;
    }

    unsigned char root_key[32];
    crypto_generichash(root_key, 32, shared, sizeof shared, nullptr, 0);

    Ratchet ratchet;
    ratchet.init(root_key);

    // Swap chains on server so send/recv match the client
    {
        unsigned char tmp[32];
        memcpy(tmp, ratchet.send_chain, 32);
        memcpy(ratchet.send_chain, ratchet.recv_chain, 32);
        memcpy(ratchet.recv_chain, tmp, 32);
    }

    std::cout << "Session + dual-chain ratchet established.\n";
    std::cout << "Type messages (Ctrl+C to quit)\n\n";

    std::string line;
    while (running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(STDIN_FILENO, &fds);

        timeval tv{1, 0}; // 1 second timeout so we can react to Ctrl+C
        int maxfd = std::max(client_fd, STDIN_FILENO);
        int ready = select(maxfd + 1, &fds, nullptr, nullptr, &tv);
        if (ready < 0) break;
        if (ready == 0) continue;

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            if (!std::getline(std::cin, line)) break;
            if (line.empty()) continue;

            unsigned char msg_key[32];
            ratchet.next_send_key(msg_key);

            unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            randombytes_buf(nonce, sizeof nonce);

            // Packet format: nonce (24) + counter (8) + ciphertext
            uint64_t counter = ratchet.send_count - 1; // already incremented
            unsigned char counter_bytes[8];
            for (int i = 0; i < 8; i++)
                counter_bytes[i] = (counter >> (i * 8)) & 0xff;

            std::vector<unsigned char> ciphertext(line.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
            unsigned long long clen;

            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.data(), &clen,
                reinterpret_cast<const unsigned char*>(line.data()), line.size(),
                counter_bytes, 8,   // additional data = counter
                nullptr, nonce, msg_key);

            std::vector<unsigned char> packet;
            packet.insert(packet.end(), nonce, nonce + sizeof nonce);
            packet.insert(packet.end(), counter_bytes, counter_bytes + 8);
            packet.insert(packet.end(), ciphertext.begin(), ciphertext.begin() + clen);

            if (!send_all(client_fd, packet.data(), packet.size())) {
                std::cerr << "Send failed\n"; break;
            }
        }

        if (FD_ISSET(client_fd, &fds)) {
            std::vector<unsigned char> packet;
            if (!recv_all(client_fd, packet)) {
                std::cout << "\nPeer disconnected.\n"; break;
            }
            if (packet.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 8) continue;

            const unsigned char* nonce = packet.data();
            const unsigned char* counter_bytes = packet.data() + 24;
            const unsigned char* ct = packet.data() + 32;
            size_t ct_len = packet.size() - 32;

            uint64_t received_counter = 0;
            for (int i = 0; i < 8; i++)
                received_counter |= (uint64_t)counter_bytes[i] << (i * 8);

            // Basic replay protection
            if (received_counter < ratchet.recv_count) {
                std::cout << "[!] Replay detected (counter too old) – ignored\n";
                continue;
            }

            // Advance ratchet until we reach the expected counter
            while (ratchet.recv_count < received_counter) {
                unsigned char dummy[32];
                ratchet.next_recv_key(dummy);
            }

            unsigned char msg_key[32];
            ratchet.next_recv_key(msg_key);

            std::vector<unsigned char> plaintext(ct_len);
            unsigned long long plen;

            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext.data(), &plen, nullptr,
                    ct, ct_len,
                    counter_bytes, 8,
                    nonce, msg_key) != 0)
            {
                std::cout << "[!] Tampered or invalid message received\n";
                continue;
            }

            std::cout << "Peer: " << std::string(reinterpret_cast<char*>(plaintext.data()), plen) << std::endl;
        }
    }

    close(client_fd);
    close(server_fd);
    std::cout << "Server shut down cleanly.\n";
    return 0;
}

int run_client(const unsigned char* my_pk, const unsigned char* my_sk) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    std::cout << "Connecting to 127.0.0.1:" << PORT << "...\n";
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }
    std::cout << "Connected.\n";

    std::vector<unsigned char> peer_pk(crypto_sign_PUBLICKEYBYTES);
    if (!recv_all(sock, peer_pk)) {
        std::cerr << "Failed to receive peer public key\n"; return 1;
    }
    std::cout << "Peer public key: ";
    print_hex(peer_pk.data(), peer_pk.size());

    if (!send_all(sock, my_pk, crypto_sign_PUBLICKEYBYTES)) {
        std::cerr << "Failed to send public key\n"; return 1;
    }

    unsigned char my_x25519_sk[crypto_scalarmult_SCALARBYTES];
    unsigned char peer_x25519_pk[crypto_scalarmult_BYTES];

    crypto_sign_ed25519_sk_to_curve25519(my_x25519_sk, my_sk);
    if (crypto_sign_ed25519_pk_to_curve25519(peer_x25519_pk, peer_pk.data()) != 0) {
        std::cerr << "Failed to convert peer public key\n";
        return 1;
    }

    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared, my_x25519_sk, peer_x25519_pk) != 0) {
        std::cerr << "Key exchange failed\n"; return 1;
    }

    unsigned char root_key[32];
    crypto_generichash(root_key, 32, shared, sizeof shared, nullptr, 0);

    Ratchet ratchet;
    ratchet.init(root_key);

    std::cout << "Session + dual-chain ratchet established.\n";
    std::cout << "Type messages (Ctrl+C to quit)\n\n";

    std::string line;
    while (running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        FD_SET(STDIN_FILENO, &fds);

        timeval tv{1, 0};
        int maxfd = std::max(sock, STDIN_FILENO);
        int ready = select(maxfd + 1, &fds, nullptr, nullptr, &tv);
        if (ready < 0) break;
        if (ready == 0) continue;

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            if (!std::getline(std::cin, line)) break;
            if (line.empty()) continue;

            unsigned char msg_key[32];
            ratchet.next_send_key(msg_key);

            unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            randombytes_buf(nonce, sizeof nonce);

            uint64_t counter = ratchet.send_count - 1;
            unsigned char counter_bytes[8];
            for (int i = 0; i < 8; i++)
                counter_bytes[i] = (counter >> (i * 8)) & 0xff;

            std::vector<unsigned char> ciphertext(line.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
            unsigned long long clen;

            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.data(), &clen,
                reinterpret_cast<const unsigned char*>(line.data()), line.size(),
                counter_bytes, 8,
                nullptr, nonce, msg_key);

            std::vector<unsigned char> packet;
            packet.insert(packet.end(), nonce, nonce + sizeof nonce);
            packet.insert(packet.end(), counter_bytes, counter_bytes + 8);
            packet.insert(packet.end(), ciphertext.begin(), ciphertext.begin() + clen);

            if (!send_all(sock, packet.data(), packet.size())) {
                std::cerr << "Send failed\n"; break;
            }
        }

        if (FD_ISSET(sock, &fds)) {
            std::vector<unsigned char> packet;
            if (!recv_all(sock, packet)) {
                std::cout << "\nPeer disconnected.\n"; break;
            }
            if (packet.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 8) continue;

            const unsigned char* nonce = packet.data();
            const unsigned char* counter_bytes = packet.data() + 24;
            const unsigned char* ct = packet.data() + 32;
            size_t ct_len = packet.size() - 32;

            uint64_t received_counter = 0;
            for (int i = 0; i < 8; i++)
                received_counter |= (uint64_t)counter_bytes[i] << (i * 8);

            if (received_counter < ratchet.recv_count) {
                std::cout << "[!] Replay detected (counter too old) – ignored\n";
                continue;
            }

            while (ratchet.recv_count < received_counter) {
                unsigned char dummy[32];
                ratchet.next_recv_key(dummy);
            }

            unsigned char msg_key[32];
            ratchet.next_recv_key(msg_key);

            std::vector<unsigned char> plaintext(ct_len);
            unsigned long long plen;

            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext.data(), &plen, nullptr,
                    ct, ct_len,
                    counter_bytes, 8,
                    nonce, msg_key) != 0)
            {
                std::cout << "[!] Tampered or invalid message received\n";
                continue;
            }

            std::cout << "Peer: " << std::string(reinterpret_cast<char*>(plaintext.data()), plen) << std::endl;
        }
    }

    close(sock);
    std::cout << "Client shut down cleanly.\n";
    return 0;
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    signal(SIGINT, signal_handler);

    if (argc != 2 || (std::string(argv[1]) != "server" && std::string(argv[1]) != "client")) {
        std::cerr << "Usage: " << argv[0] << " [server|client]\n";
        return 1;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    if (std::string(argv[1]) == "server") {
        load_or_create_identity("server_identity.key", pk, sk);
        return run_server(pk, sk);
    } else {
        load_or_create_identity("client_identity.key", pk, sk);
        return run_client(pk, sk);
    }
}
