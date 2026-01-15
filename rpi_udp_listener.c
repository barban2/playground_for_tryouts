
// udp_listener.c
// Cross-platform UDP listener that mimics the Python sample behavior.
//
// Listens on 0.0.0.0:5005 and prints sender address and received data.
// Build instructions below.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  #define CLOSESOCK closesocket
  static void sock_perror(const char* msg) {
      fprintf(stderr, "%s: WSA error %ld\n", msg, WSAGetLastError());
  }
#else
  #include <unistd.h>
  #include <errno.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #define CLOSESOCK close
  static void sock_perror(const char* msg) { perror(msg); }
#endif

#define DEFAULT_IP   "0.0.0.0"   // Listen on all interfaces
#define DEFAULT_PORT 5005
#define MAX_UDP      65535

// Uncomment to print hex dump instead of raw text
// #define PRINT_HEX

#ifdef PRINT_HEX
static void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 2 == 0) printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}
#endif

int main(int argc, char* argv[]) {
    const char* ip_str = DEFAULT_IP;
    uint16_t port = DEFAULT_PORT;

    // Optional: allow overriding IP and PORT via arguments
    // Usage: udp_listener [ip] [port]
    if (argc >= 2) ip_str = argv[1];
    if (argc >= 3) port = (uint16_t)atoi(argv[2]);

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        sock_perror("WSAStartup failed");
        return EXIT_FAILURE;
    }
#endif

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        sock_perror("socket");
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    // Allow quick rebinding after restart
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes)) < 0) {
        sock_perror("setsockopt(SO_REUSEADDR)");
        // Not fatal; continue
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // If ip_str is "0.0.0.0", bind to INADDR_ANY; otherwise parse.
    if (strcmp(ip_str, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, ip_str, &addr.sin_addr) != 1) {
            fprintf(stderr, "Invalid IP address: %s\n", ip_str);
            CLOSESOCK(sockfd);
#ifdef _WIN32
            WSACleanup();
#endif
            return EXIT_FAILURE;
        }
    }

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        sock_perror("bind");
        CLOSESOCK(sockfd);
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    printf("Listening UDP on %s:%u ...\n", ip_str, (unsigned)port);

    // Receive buffer: +1 to allow null-termination for readable printing
    unsigned char buf[MAX_UDP + 1];

    while (1) {
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
#ifdef _WIN32
        int n = recvfrom(sockfd, (char*)buf, MAX_UDP, 0, (struct sockaddr*)&src, &srclen);
#else
        ssize_t n = recvfrom(sockfd, buf, MAX_UDP, 0, (struct sockaddr*)&src, &srclen);
#endif
        if (n < 0) {
            sock_perror("recvfrom");
            // continue receiving
            continue;
        }

        // Prepare printable address
        char src_ip[INET_ADDRSTRLEN] = {0};
        if (!inet_ntop(AF_INET, &src.sin_addr, src_ip, sizeof(src_ip))) {
            strncpy(src_ip, "(unknown)", sizeof(src_ip) - 1);
        }
        unsigned src_port = ntohs(src.sin_port);

        // Null-terminate for safe string print (does NOT mean data is text)
        size_t len = (size_t)n;
        if (len > MAX_UDP) len = MAX_UDP;
        buf[len] = '\0';

        printf("From %s:%u — %zu bytes\n", src_ip, src_port, len);

#ifdef PRINT_HEX
        print_hex(buf, len);
#else
        // Print similar to Python's bytes: this will emit raw data; may include non-printables.
        // If your data is binary, prefer enabling PRINT_HEX above.
        fwrite(buf, 1, len, stdout);
        printf("\n");
#endif
        fflush(stdout);
    }

    // Unreachable in normal use
    CLOSESOCK(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return EXIT_SUCCESS;
}
