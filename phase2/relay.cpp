/*
 * Phase 2 – Simple Store-and-Forward Relay
 * C++ / pure sockets
 *
 * Protocol (very simple, text-based for clarity):
 *
 *   SEND <recipient_hex_pubkey> <hex_blob>\n
 *   FETCH <my_hex_pubkey>\n
 *
 * Responses:
 *   OK\n
 *   MSG <hex_blob>\n
 *   END\n
 *   ERROR <message>\n
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <algorithm>

constexpr int PORT = 9900;
constexpr size_t MAX_LINE = 65536;

// In-memory store: recipient_pubkey_hex → list of encrypted blobs (as hex strings)
std::map<std::string, std::vector<std::string>> mailbox;

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool send_line(int sock, const std::string& line) {
    std::string data = line + "\n";
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
        if (out.size() > MAX_LINE) return false;
    }
    return true;
}

void handle_client(int client_fd) {
    std::string line;
    if (!recv_line(client_fd, line)) {
        close(client_fd);
        return;
    }
    line = trim(line);
    std::cout << "Received: " << line.substr(0, 80) << (line.size() > 80 ? "..." : "") << "\n";

    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;

    if (cmd == "SEND") {
        std::string recipient, blob;
        iss >> recipient >> blob;
        if (recipient.empty() || blob.empty()) {
            send_line(client_fd, "ERROR missing recipient or blob");
        } else {
            mailbox[recipient].push_back(blob);
            std::cout << "Stored message for " << recipient.substr(0, 16) << "... (total: "
                      << mailbox[recipient].size() << ")\n";
            send_line(client_fd, "OK");
        }
    }
    else if (cmd == "FETCH") {
        std::string me;
        iss >> me;
        if (me.empty()) {
            send_line(client_fd, "ERROR missing pubkey");
        } else {
            auto& messages = mailbox[me];
            for (const auto& msg : messages) {
                send_line(client_fd, "MSG " + msg);
            }
            messages.clear(); // delivered → remove
            send_line(client_fd, "END");
            std::cout << "Delivered messages to " << me.substr(0, 16) << "...\n";
        }
    }
    else {
        send_line(client_fd, "ERROR unknown command");
    }

    close(client_fd);
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 16) < 0) {
        perror("listen");
        return 1;
    }

    std::cout << "Nest Relay listening on port " << PORT << "\n";
    std::cout << "Commands: SEND <recipient_hex> <blob_hex>   or   FETCH <my_hex>\n\n";

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        handle_client(client_fd);
    }

    close(server_fd);
    return 0;
}
