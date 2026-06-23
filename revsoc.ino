#include "config.h"

#include <WiFi.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <errno.h>

// ── tunables ─────────────────────────────────────────────────────────
#define RELAY_BUF_SIZE       4096   // per-direction relay buffer (bytes)
#define TUNNEL_TASK_STACK    6144   // stack for the main tunnel task
#define RELAY_TASK_STACK     6144   // stack for each relay direction task
#define RECONNECT_DELAY_MS   5000   // delay between reconnect attempts
#define HEADER_BUF_SIZE       512   // max "host:port" header size

// ── relay state (one active tunnel at a time) ─────────────────────────
static volatile int  g_serverSock   = -1;  // socket to relay server
static volatile int  g_localSock    = -1;  // socket to local LAN target
static volatile bool g_relayRunning = false;
static TaskHandle_t  g_s2lTask      = NULL;  // server → local task
static TaskHandle_t  g_l2sTask      = NULL;  // local  → server task

// ── TCP helpers ───────────────────────────────────────────────────────

// Returns a connected TCP socket fd, or -1 on failure.
static int tcp_connect(const char *host, int port) {
    struct addrinfo hints{}, *res = nullptr;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == nullptr) {
        Serial.printf("[revsoc] DNS failed: %s\n", host);
        return -1;
    }

    int sock = -1;
    for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0)
        Serial.printf("[revsoc] connect failed: %s:%d\n", host, port);
    return sock;
}

// Gracefully close a socket fd (safe to call with fd == -1).
static void close_sock(volatile int &fd) {
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);  // unblocks any blocked recv/send
        close(fd);
        fd = -1;
    }
}

// ── relay tasks ───────────────────────────────────────────────────────

// Stop relay: close both sockets (which unblocks recv() in relay tasks),
// wait briefly for natural exit, then force-delete any survivors.
static void stop_relay() {
    g_relayRunning = false;

    close_sock(g_localSock);   // unblocks recv() in l2s task
    close_sock(g_serverSock);  // unblocks recv() in s2l task

    // Give tasks time to detect the error and self-delete
    vTaskDelay(pdMS_TO_TICKS(400));

    if (g_s2lTask) { vTaskDelete(g_s2lTask); g_s2lTask = NULL; }
    if (g_l2sTask) { vTaskDelete(g_l2sTask); g_l2sTask = NULL; }

    Serial.println("[revsoc] relay stopped");
}

// Relay bytes from one socket to the other.
// Uses global g_serverSock / g_localSock so no malloc'd arg struct needed.
static void task_s2l(void *) {
    uint8_t *buf = (uint8_t *)malloc(RELAY_BUF_SIZE);
    bool ok = (buf != nullptr);
    if (!ok) Serial.println("[revsoc] s→l: malloc failed");

    while (ok && g_relayRunning) {
        int n = recv(g_serverSock, buf, RELAY_BUF_SIZE, 0);
        if (n <= 0) break;
        for (int sent = 0; sent < n; ) {
            int w = send(g_localSock, buf + sent, n - sent, 0);
            if (w <= 0) { ok = false; break; }
            sent += w;
        }
    }

    free(buf);
    Serial.println("[revsoc] s→l ended");
    g_relayRunning = false;
    g_s2lTask = NULL;
    vTaskDelete(NULL);
}

static void task_l2s(void *) {
    uint8_t *buf = (uint8_t *)malloc(RELAY_BUF_SIZE);
    bool ok = (buf != nullptr);
    if (!ok) Serial.println("[revsoc] l→s: malloc failed");

    while (ok && g_relayRunning) {
        int n = recv(g_localSock, buf, RELAY_BUF_SIZE, 0);
        if (n <= 0) break;
        for (int sent = 0; sent < n; ) {
            int w = send(g_serverSock, buf + sent, n - sent, 0);
            if (w <= 0) { ok = false; break; }
            sent += w;
        }
    }

    free(buf);
    Serial.println("[revsoc] l→s ended");
    g_relayRunning = false;
    g_l2sTask = NULL;
    vTaskDelete(NULL);
}

// ── header parsing ────────────────────────────────────────────────────

// The relay server sends "host:port" immediately followed by any data
// from the SOCKS5 client (no explicit delimiter between header and data).
//
// Strategy: read a chunk, find the last ':' to split host and port,
// use strtol to consume only the decimal digits of the port number.
// Any bytes after the port digits are initial relay data already received.
//
// Returns the number of initial-data bytes placed in init_buf, or -1.
static int parse_tunnel_header(char *out_host, int host_size,
                                int  *out_port,
                                uint8_t *init_buf, int init_buf_size) {
    char hdr[HEADER_BUF_SIZE];
    int  hdr_len = recv(g_serverSock, hdr, sizeof(hdr) - 1, 0);
    if (hdr_len <= 0) return -1;
    hdr[hdr_len] = '\0';

    // Find the ':' separator (use last occurrence to handle IPv6 literals)
    char *sep = (char *)memrchr(hdr, ':', hdr_len);
    if (!sep) {
        Serial.printf("[revsoc] malformed header (no ':'): %.*s\n", hdr_len, hdr);
        return -1;
    }

    // Copy host
    int host_len = sep - hdr;
    if (host_len <= 0 || host_len >= host_size) {
        Serial.println("[revsoc] host too long or empty");
        return -1;
    }
    memcpy(out_host, hdr, host_len);
    out_host[host_len] = '\0';

    // Parse port (strtol stops at first non-digit)
    char *port_end;
    long port = strtol(sep + 1, &port_end, 10);
    if (port_end == sep + 1 || port <= 0 || port > 65535) {
        Serial.printf("[revsoc] invalid port in header: %s\n", sep + 1);
        return -1;
    }
    *out_port = (int)port;

    // Bytes after port digits = initial relay data already in the buffer
    int init_len = (int)((hdr + hdr_len) - port_end);
    if (init_len > 0) {
        if (init_len > init_buf_size) init_len = init_buf_size;
        memcpy(init_buf, port_end, init_len);
    }
    return init_len;
}

// ── main tunnel task ──────────────────────────────────────────────────

static void tunnel_task(void *) {
    char    target_host[256];
    int     target_port = 0;
    uint8_t init_buf[HEADER_BUF_SIZE];

    for (;;) {
        // ── wait for WiFi ──
        while (WiFi.status() != WL_CONNECTED) {
            Serial.println("[revsoc] waiting for WiFi...");
            vTaskDelay(pdMS_TO_TICKS(2000));
        }

        // ── connect to relay server ──
        Serial.printf("[revsoc] connecting to relay server %s:%d\n",
                      SERVER_HOST, SERVER_PORT);
        g_serverSock = tcp_connect(SERVER_HOST, SERVER_PORT);
        if (g_serverSock < 0) {
            Serial.println("[revsoc] relay server unreachable, retrying...");
            vTaskDelay(pdMS_TO_TICKS(RECONNECT_DELAY_MS));
            continue;
        }
        Serial.println("[revsoc] connected to relay server — waiting for tunnel request");

        // ── parse "host:port[data]" from server ──
        int init_len = parse_tunnel_header(target_host, sizeof(target_host),
                                           &target_port, init_buf, sizeof(init_buf));
        if (init_len < 0) {
            Serial.println("[revsoc] bad tunnel header or server disconnected");
            close_sock(g_serverSock);
            vTaskDelay(pdMS_TO_TICKS(RECONNECT_DELAY_MS));
            continue;
        }
        Serial.printf("[revsoc] tunnel request → %s:%d  (init=%d B)\n",
                      target_host, target_port, init_len);

        // ── connect to local LAN target ──
        g_localSock = tcp_connect(target_host, target_port);
        if (g_localSock < 0) {
            Serial.printf("[revsoc] cannot reach local target %s:%d\n",
                          target_host, target_port);
            close_sock(g_serverSock);
            vTaskDelay(pdMS_TO_TICKS(RECONNECT_DELAY_MS));
            continue;
        }

        // ── forward any initial data that arrived with the header ──
        if (init_len > 0) {
            bool fwd_ok = true;
            for (int sent = 0; sent < init_len; ) {
                int w = send(g_localSock, init_buf + sent, init_len - sent, 0);
                if (w <= 0) { fwd_ok = false; break; }
                sent += w;
            }
            if (!fwd_ok) {
                Serial.println("[revsoc] failed to forward initial data");
                close_sock(g_serverSock);
                close_sock(g_localSock);
                vTaskDelay(pdMS_TO_TICKS(RECONNECT_DELAY_MS));
                continue;
            }
        }

        // ── start bidirectional relay ──
        g_relayRunning = true;
        bool tasks_ok =
            xTaskCreate(task_s2l, "s2l", RELAY_TASK_STACK, NULL, 5, &g_s2lTask) == pdPASS &&
            xTaskCreate(task_l2s, "l2s", RELAY_TASK_STACK, NULL, 5, &g_l2sTask) == pdPASS;

        if (!tasks_ok) {
            Serial.println("[revsoc] failed to create relay tasks");
            stop_relay();
            vTaskDelay(pdMS_TO_TICKS(RECONNECT_DELAY_MS));
            continue;
        }

        Serial.println("[revsoc] relay running...");

        // Wait for relay to finish (relay tasks set g_relayRunning = false on error/close)
        while (g_relayRunning) {
            vTaskDelay(pdMS_TO_TICKS(200));
        }

        stop_relay();
        Serial.println("[revsoc] session ended — reconnecting");
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ── Arduino entry points ───────────────────────────────────────────────

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n[revsoc] ESP32-S3 Reverse SOCKS5 Proxy — starting");

    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(true);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.printf("[revsoc] connecting to WiFi: %s\n", WIFI_SSID);

    for (int i = 0; i < 30 && WiFi.status() != WL_CONNECTED; i++) {
        delay(500);
        Serial.print('.');
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("[revsoc] WiFi OK — IP %s\n", WiFi.localIP().toString().c_str());
    } else {
        Serial.println("[revsoc] WiFi not ready yet (tunnel task will keep retrying)");
    }

    xTaskCreate(tunnel_task, "tunnel", TUNNEL_TASK_STACK, NULL, 5, NULL);
}

void loop() {
    // Arduino loop only handles WiFi watchdog.
    // The tunnel lives in its own FreeRTOS task.
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[revsoc] WiFi lost — reconnecting");
        WiFi.reconnect();
    }
    delay(15000);
}
