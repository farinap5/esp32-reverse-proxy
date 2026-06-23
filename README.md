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

Run the relay server.

```
python main.py -r 6668 -l 6669 -s
```


This project is based on [esp8266-reverse-socks5](https://github.com/mehdilauters/esp8266-reverse-socks5).