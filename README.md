The wifi the ESP32 will connect to.

```
#define WIFI_SSID     "wifi"
#define WIFI_PASSWORD "wifi_password_123"
```

Address and port of the Python relay server. The server must be reachable from both target network (for the ESP to connect out) and from the operator network (for SOCKS5 clients).

```
#define SERVER_HOST "192.168.16.13"
#define SERVER_PORT 6668
```