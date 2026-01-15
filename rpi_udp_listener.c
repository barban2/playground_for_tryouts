
// udp_latency_ts_prefix.c
// Listens on 0.0.0.0:5005, parses "ts=<ISO8601>" at payload start,
// computes Δt = (local_receive_UTC - remote_send_UTC) and prints it.
//
// Example payload:
//   ts=2026-01-15T08:55:21.611+00:00 X=0.381 Y=-0.654 Z=9.310
//
// Build:
//   Linux/macOS: cc -O2 -Wall -Wextra -o udp_latency udp_latency_ts_prefix.c
//   Windows (MSVC): cl /W4 /O2 udp_latency_ts_prefix.c ws2_32.lib
//   Windows (MinGW): gcc -O2 -Wall -Wextra -o udp_latency.exe udp_latency_ts_prefix.c -lws2_32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #pragma comment(lib, "Ws2_32.lib")
  #define CLOSESOCK closesocket
  static void sock_perror(const char* msg) {
      fprintf(stderr, "%s: WSA error %ld\n", msg, WSAGetLastError());
  }
  // Define timespec for older MSVC if needed
  #ifndef _TIMESPEC_DEFINED
  #define _TIMESPEC_DEFINED
  struct timespec { time_t tv_sec; long tv_nsec; };
  #endif
#else
  #include <unistd.h>
  #include <errno.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #define CLOSESOCK close
  static void sock_perror(const char* msg) { perror(msg); }
#endif

#define DEFAULT_IP   "0.0.0.0"
#define DEFAULT_PORT 5005
#define MAX_UDP      65535

// -------- Time utilities --------

#ifdef _WIN32
static void now_utc_timespec(struct timespec* ts) {
    // Prefer high-precision; available on Windows 8+.
    static BOOL has_precise = TRUE;
    FILETIME ft;
    ULARGE_INTEGER uli;

    if (has_precise) {
        // Dynamically resolve to be safe on older systems.
        static BOOL resolved = FALSE;
        static void (WINAPI *pGetSystemTimePreciseAsFileTime)(LPFILETIME) = NULL;
        if (!resolved) {
            HMODULE h = GetModuleHandleA("kernel32.dll");
            pGetSystemTimePreciseAsFileTime =
                (void (WINAPI *)(LPFILETIME))GetProcAddress(h, "GetSystemTimePreciseAsFileTime");
            resolved = TRUE;
            if (!pGetSystemTimePreciseAsFileTime) has_precise = FALSE;
        }
        if (pGetSystemTimePreciseAsFileTime) {
            pGetSystemTimePreciseAsFileTime(&ft);
        } else {
            GetSystemTimeAsFileTime(&ft); // fallback
        }
    } else {
        GetSystemTimeAsFileTime(&ft);
    }

    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    const uint64_t EPOCH_DIFF_100NS = 11644473600ULL * 10000000ULL; // 1601->1970
    uint64_t t100 = uli.QuadPart - EPOCH_DIFF_100NS;
    ts->tv_sec  = (time_t)(t100 / 10000000ULL);
    ts->tv_nsec = (long)((t100 % 10000000ULL) * 100);
}
#else
static void now_utc_timespec(struct timespec* ts) {
    clock_gettime(CLOCK_REALTIME, ts); // UTC
}
#endif

// Portable UTC 'timegm'
static time_t timegm_portable(struct tm* tm_utc) {
#ifdef _WIN32
    return _mkgmtime(tm_utc);
#else
    return timegm(tm_utc);
#endif
}

// Parse "ts=<ISO8601>" at the beginning of 'payload'.
// Supports: YYYY-MM-DDThh:mm:ss[.frac](Z|±HH[:MM]|±HHMM|±HH)
// Returns 0 on success and fills 'out' (UTC), else -1.
static int parse_ts_field_to_timespec(const char* payload, struct timespec* out) {
    if (!payload || !out) return -1;

    // Expect "ts=" prefix (case-sensitive as per sample)
    const char* p = payload;
    while (*p && isspace((unsigned char)*p)) ++p;
    if (strncmp(p, "ts=", 3) != 0) return -1;
    p += 3;

    // Now p should point to ISO8601 datetime
    // Parse date and time: YYYY-MM-DDThh:mm:ss
    int year, mon, day, hour, min, sec;
    if (sscanf(p, "%4d-%2d-%2dT%2d:%2d:%2d", &year, &mon, &day, &hour, &min, &sec) != 6) {
        return -1;
    }

    // Move p to the end of "YYYY-MM-DDThh:mm:ss"
    const char* tptr = strchr(p, 'T');
    if (!tptr) return -1;
    const char* q = tptr + 1; // points at hh
    // Ensure expected layout hh:mm:ss (8 chars)
    if (!isdigit((unsigned char)q[0]) || !isdigit((unsigned char)q[1]) ||
        q[2] != ':' ||
        !isdigit((unsigned char)q[3]) || !isdigit((unsigned char)q[4]) ||
        q[5] != ':' ||
        !isdigit((unsigned char)q[6]) || !isdigit((unsigned char)q[7])) {
        return -1;
    }
    const char* after_sec = q + 8; // after seconds

    // Fractional seconds (optional)
    long nanos = 0;
    p = after_sec;
    if (*p == '.') {
        ++p;
        int digits = 0;
        long long frac_val = 0;
        while (isdigit((unsigned char)*p) && digits < 9) {
            frac_val = frac_val * 10 + (*p - '0');
            ++p; ++digits;
        }
        // Scale to nanoseconds (pad remaining)
        for (int i = digits; i < 9; ++i) frac_val *= 10;
        nanos = (long)frac_val;
        // Skip any extra fractional digits (ignored)
        while (isdigit((unsigned char)*p)) ++p;
    }

    // Timezone: 'Z' or ±HH[:MM] or ±HHMM or ±HH
    int tz_sign = 0;
    int tz_h = 0, tz_m = 0;
    if (*p == 'Z' || *p == 'z') {
        tz_sign = 0; // UTC
        ++p;
    } else if (*p == '+' || *p == '-') {
        tz_sign = (*p == '-') ? -1 : 1; // NOTE: - means WEST of UTC
        ++p;
        // Expect at least two digits for hours
        if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1])) return -1;
        tz_h = (p[0] - '0') * 10 + (p[1] - '0');
        p += 2;

        if (*p == ':') {
            // ±HH:MM
            ++p;
            if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1])) return -1;
            tz_m = (p[0] - '0') * 10 + (p[1] - '0');
            p += 2;
        } else if (isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1])) {
            // ±HHMM
            tz_m = (p[0] - '0') * 10 + (p[1] - '0');
            p += 2;
        } else {
            // ±HH
            tz_m = 0;
        }
    } else {
        // Not a recognized timezone suffix
        return -1;
    }

    // Build UTC epoch
    struct tm tm_utc;
    memset(&tm_utc, 0, sizeof(tm_utc));
    tm_utc.tm_year = year - 1900;
    tm_utc.tm_mon  = mon - 1;
    tm_utc.tm_mday = day;
    tm_utc.tm_hour = hour;
    tm_utc.tm_min  = min;
    tm_utc.tm_sec  = sec;
    tm_utc.tm_isdst = 0;

    time_t naive = timegm_portable(&tm_utc); // interpret as if UTC initially
    if (naive == (time_t)-1) return -1;

    // Convert from local-with-offset to UTC:
    // ISO string denotes local time with offset. UTC = local - offset.
    long tz_offset_sec = (long)(tz_h * 3600 + tz_m * 60);
    if (tz_sign != 0) naive -= (tz_sign * tz_offset_sec);

    out->tv_sec  = naive;
    out->tv_nsec = nanos;
    return 0;
}

// Compute (a - b) normalized.
static void timespec_diff(const struct timespec* a, const struct timespec* b, struct timespec* d) {
    d->tv_sec  = a->tv_sec  - b->tv_sec;
    d->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (d->tv_nsec < 0) {
        d->tv_sec -= 1;
        d->tv_nsec += 1000000000L;
    }
}

static void print_diff_ms_us_ns(const struct timespec* d) {
    double ms = (double)d->tv_sec * 1000.0 + (double)d->tv_nsec / 1e6;
    long long us = (long long)d->tv_sec * 1000000LL + (d->tv_nsec / 1000);
    printf("Δt = %.3f ms  (%lld µs, %ld ns remainder)\n",
           ms, us, d->tv_nsec % 1000);
}

// -------- UDP listener --------

int main(int argc, char* argv[]) {
    const char* ip_str = DEFAULT_IP;
    uint16_t port = DEFAULT_PORT;
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

    int yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (strcmp(ip_str, "0.0.0.0") == 0) addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else if (inet_pton(AF_INET, ip_str, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        CLOSESOCK(sockfd);
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
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
            continue;
        }

        // Capture receive time immediately after recv
        struct timespec local_ts;
        now_utc_timespec(&local_ts);

        size_t len = (size_t)n;
        if (len > MAX_UDP) len = MAX_UDP;
        buf[len] = '\0';

        char src_ip[INET_ADDRSTRLEN] = {0};
        if (!inet_ntop(AF_INET, &src.sin_addr, src_ip, sizeof(src_ip))) {
            strncpy(src_ip, "(unknown)", sizeof(src_ip) - 1);
        }
        unsigned src_port = ntohs(src.sin_port);

        printf("From %s:%u — %zu bytes\n", src_ip, src_port, len);

        // Parse ts=<...> from the start of payload
        struct timespec remote_ts;
        if (parse_ts_field_to_timespec((const char*)buf, &remote_ts) == 0) {
            struct timespec diff;
            timespec_diff(&local_ts, &remote_ts, &diff);
            print_diff_ms_us_ns(&diff);
        } else {
            printf("Warning: Could not parse 'ts=' ISO8601 timestamp from payload start.\n");
        }

        // Optional: also parse/print sensor values X, Y, Z (simple scan)
        // Uncomment if you want to see them.
        /*
        double X, Y, Z;
        if (sscanf((const char*)buf, "ts=%*s X=%lf Y=%lf Z=%lf", &X, &Y, &Z) == 3) {
            printf("X=%.3f Y=%.3f Z=%.3f\n", X, Y, Z);
        }
        */

        fflush(stdout);
    }

    CLOSESOCK(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
    return EXIT_SUCCESS;
}
