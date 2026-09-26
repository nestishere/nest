/*
 * Phase 2/3 – Nest Client
 * Supports connecting to a Tor onion relay
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
#include <netdb.h>
#include <sstream>
#include <iomanip>

constexpr int RELAY_PORT = 9900;

// Change this to your onion address
const char* RELAY_HOST = "i7tweaeafgtkyxjwsqxg4s67n2xbgqo4n3k6yr64lzd73iwuuuefmuid.onion";

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
}

std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

std::vector<unsigned char> from_hex(const std::string& hex) {
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int byte;
        sscanf(hex.c_str() + i, "%02x", &byte);
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

bool load_identity(const char* filename, unsigned char* pk, unsigned char* sk) {
    FILE* f = fopen(filename, "rb");
    if (!f) return false;
    if (fread(pk, 1, crypto_sign_PUBLICKEYBYTES, f) != crypto_sign_PUBLICKEYBYTES) { fclose(f); return false; }
    if (fread(sk, 1, crypto_sign_SECRETKEYBYTES, f) != crypto_sign_SECRETKEYBYTES) { fclose(f); return false; }
    fclose(f);
    return true;
}

bool send_all(int sock, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = send(sock, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool recv_line(int sock, std::string& out) {
    out.clear();
    char c;
    while (true) {
        ssize_t n = recv(sock, &c, 1, 0);
        if (n <= 0) return false;
        if (c == '\n') break;
        out.push_back(c);
        if (out.size() > 65536) return false;
    }
    return true;
}

int connect_to_relay() {
    // When using torsocks, getaddrinfo will resolve .onion via Tor
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(RELAY_PORT);
    int err = getaddrinfo(RELAY_HOST, port_str.c_str(), &hints, &res);
    if (err != 0) {
        std::cerr << "getaddrinfo failed: " << gai_strerror(err) << "\n";
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return sock;
}

std::string encrypt_for(const unsigned char* recipient_curve_pk, const std::string& plaintext) {
    std::vector<unsigned char> ciphertext(crypto_box_SEALBYTES + plaintext.size());
    if (crypto_box_seal(ciphertext.data(),
                        reinterpret_cast<const unsigned char*>(plaintext.data()),
                        plaintext.size(),
                        recipient_curve_pk) != 0) {
        return "";
    }
    return to_hex(ciphertext.data(), ciphertext.size());
}

std::string decrypt_from(const unsigned char* my_curve_pk, const unsigned char* my_curve_sk,
                         const std::string& ciphertext_hex) {
    auto ct = from_hex(ciphertext_hex);
    if (ct.size() < crypto_box_SEALBYTES) return "";

    std::vector<unsigned char> plaintext(ct.size() - crypto_box_SEALBYTES);
    if (crypto_box_seal_open(plaintext.data(),
                             ct.data(), ct.size(),
                             my_curve_pk, my_curve_sk) != 0) {
        return "";
    }
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
}

int cmd_send(const unsigned char* my_pk, const unsigned char* my_sk,
             const std::string& recipient_hex, const std::string& message) {
    auto recipient_pk_vec = from_hex(recipient_hex);
    if (recipient_pk_vec.size() != crypto_sign_PUBLICKEYBYTES) {
        std::cerr << "Invalid recipient public key length\n";
        return 1;
    }

    unsigned char recipient_curve[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(recipient_curve, recipient_pk_vec.data()) != 0) {
        std::cerr << "Failed to convert recipient key\n";
        return 1;
    }

    std::string blob = encrypt_for(recipient_curve, message);
    if (blob.empty()) {
        std::cerr << "Encryption failed\n";
        return 1;
    }

    int sock = connect_to_relay();
    if (sock < 0) {
        std::cerr << "Cannot connect to relay\n";
        return 1;
    }

    std::string request = "SEND " + recipient_hex + " " + blob + "\n";
    if (!send_all(sock, request)) {
        std::cerr << "Send failed\n";
        close(sock);
        return 1;
    }

    std::string response;
    if (!recv_line(sock, response)) {
        std::cerr << "No response from relay\n";
        close(sock);
        return 1;
    }
    close(sock);

    if (response == "OK") {
        std::cout << "Message sent successfully (via Tor)\n";
        return 0;
    } else {
        std::cout << "Relay error: " << response << "\n";
        return 1;
    }
}

int cmd_fetch(const unsigned char* my_pk, const unsigned char* my_sk) {
    std::string my_hex = to_hex(my_pk, crypto_sign_PUBLICKEYBYTES);

    int sock = connect_to_relay();
    if (sock < 0) {
        std::cerr << "Cannot connect to relay\n";
        return 1;
    }

    std::string request = "FETCH " + my_hex + "\n";
    if (!send_all(sock, request)) {
        std::cerr << "Send failed\n";
        close(sock);
        return 1;
    }

    unsigned char my_curve_sk[crypto_box_SECRETKEYBYTES];
    unsigned char my_curve_pk[crypto_box_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_curve25519(my_curve_sk, my_sk);
    crypto_scalarmult_base(my_curve_pk, my_curve_sk);

    int count = 0;
    while (true) {
        std::string line;
        if (!recv_line(sock, line)) break;

        if (line == "END") break;
        if (line.rfind("MSG ", 0) == 0) {
            std::string blob = line.substr(4);
            std::string plaintext = decrypt_from(my_curve_pk, my_curve_sk, blob);
            if (plaintext.empty()) {
                std::cout << "[!] Failed to decrypt a message\n";
            } else {
                std::cout << "New message: " << plaintext << "\n";
                count++;
            }
        } else if (line.rfind("ERROR", 0) == 0) {
            std::cout << line << "\n";
        }
    }
    close(sock);

    if (count == 0)
        std::cout << "No new messages\n";
    return 0;
}

void print_usage(const char* prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " [--identity client|server] mykey\n"
              << "  " << prog << " [--identity client|server] send <recipient_pubkey_hex> <message>\n"
              << "  " << prog << " [--identity client|server] fetch\n";
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string identity = "client";
    int arg_offset = 1;

    if (argc >= 3 && std::string(argv[1]) == "--identity") {
        identity = argv[2];
        arg_offset = 3;
        if (identity != "client" && identity != "server") {
            std::cerr << "Identity must be 'client' or 'server'\n";
            return 1;
        }
    }

    if (argc < arg_offset + 1) {
        print_usage(argv[0]);
        return 1;
    }

    std::string id_path = "../phase1/" + identity + "_identity.key";
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    if (!load_identity(id_path.c_str(), pk, sk)) {
        id_path = identity + "_identity.key";
        if (!load_identity(id_path.c_str(), pk, sk)) {
            std::cerr << "Cannot load identity key: " << id_path << "\n";
            return 1;
        }
    }

    std::string cmd = argv[arg_offset];

    if (cmd == "mykey") {
        std::cout << "Identity: " << identity << "\n";
        std::cout << "Public key: ";
        print_hex(pk, crypto_sign_PUBLICKEYBYTES);
        std::cout << "\n";
        return 0;
    }
    else if (cmd == "send") {
        if (argc < arg_offset + 3) {
            print_usage(argv[0]);
            return 1;
        }
        std::string recipient = argv[arg_offset + 1];
        std::string message = argv[arg_offset + 2];
        for (int i = arg_offset + 3; i < argc; i++) {
            message += " ";
            message += argv[i];
        }
        return cmd_send(pk, sk, recipient, message);
    }
    else if (cmd == "fetch") {
        return cmd_fetch(pk, sk);
    }
    else {
        print_usage(argv[0]);
        return 1;
    }
}
