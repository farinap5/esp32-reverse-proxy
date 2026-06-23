The ESP32-S3 keeps a persistent outbound TCP connection to the relay server. No inbound ports need to be opened on router.

This project may be loaded to the Arduino IDE.

Before flashing its necessary to set four variables:

The credentials the ESP32 will use to connect to a WiFi network.

```
#define WIFI_SSID     "wifi"
#define WIFI_PASSWORD "wifi_password_123"
```

Address and port of the Python relay server. The server must be reachable from both target network (for the ESP to connect out) and from the operator network (for SOCKS5 clients).

```
#define SERVER_HOST "192.168.16.13"
#define SERVER_PORT 6668
```

Start SOCKS5 and HTTP proxy
```
python3 main.py -s -H 8080

Output:
ESP listener    0.0.0.0:6668
SOCKS5 proxy    0.0.0.0:6669
HTTP proxy listening on 0.0.0.0:8080
```

Start HTTP proxy only
```
python3 main.py -H 8080

```

Example on the use of TCP forwarding for SSH forward. Use the command `ssh -p 2222 user@relay`.

```
python3 main.py -t 192.168.1.10:22 -l 2222
```

Perform tests.

```
# Socks5
curl -x socks5://127.0.0.1:6670 https://example.com

# HTTPS (via CONNECT tunnel)
curl -x http://127.0.0.1:8080 https://example.com

# Plain HTTP
curl -x http://127.0.0.1:8080 http://example.com
```


This project is based on [esp8266-reverse-socks5](https://github.com/mehdilauters/esp8266-reverse-socks5).