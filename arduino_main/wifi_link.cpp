// Secrets must be included BEFORE config.hpp so they can override the defaults.
// __has_include asks the compiler whether the file exists (GCC 5+).
#if __has_include("arduino_secrets.h")
#include "arduino_secrets.h"
#endif
#include "wifi_link.hpp"

// ---------------------------------------------------------------------------
// Constructor. On the Rev2 we also build an IPAddress from the four octets in
// config.hpp. On the R3 those members do not exist, so we only set _active.
// ---------------------------------------------------------------------------
WifiLink::WifiLink()
#if BOARD_HAS_WIFI
    : _active(false), _bound(false),
      _peer(CFG_WIFI_PEER_IP[0], CFG_WIFI_PEER_IP[1],
            CFG_WIFI_PEER_IP[2], CFG_WIFI_PEER_IP[3])
#else
    : _active(false)
#endif
{
}

void WifiLink::begin() {
    _active = false;
#if BOARD_HAS_WIFI
    _bound = false;
#endif
    // No WiFi.begin() here: switching medium needs user approval.
}

bool WifiLink::connected() const {
#if BOARD_HAS_WIFI
    return _active && (WiFi.status() == WL_CONNECTED);
#else
    return false;   // R3 has no radio
#endif
}

bool WifiLink::connect() {
#if BOARD_HAS_WIFI
    if (connected()) return true;

    WiFi.disconnect();
    WiFi.begin(CFG_WIFI_SSID, CFG_WIFI_PASS);

    // Wait up to 10 s for association. A time-based loop works the same on a
    // fast or slow board; delay(100) avoids hammering the radio with queries.
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED &&
           (millis() - start) < CFG_WIFI_CONNECT_TIMEOUT_MS) {
        delay(100);
    }
    if (WiFi.status() != WL_CONNECTED) {
        _active = false;
        return false;
    }

    if (!_bound) {
        _udp.begin(CFG_WIFI_UDP_PORT);   // listen on port 4210
        _bound = true;
    }
    _active = true;
    return true;
#else
    return false;   // R3: Wi-Fi unavailable
#endif
}

void WifiLink::disconnect() {
#if BOARD_HAS_WIFI
    if (_bound) {
        _udp.stop();
        _bound = false;
    }
    WiFi.disconnect();
#endif
    _active = false;
}

void WifiLink::send(const uint8_t *buf, uint8_t len) {
#if BOARD_HAS_WIFI
    if (!connected()) return;
    _udp.beginPacket(_peer, CFG_WIFI_UDP_PORT);
    _udp.write(buf, len);
    _udp.endPacket();
#else
    (void)buf;   // silence "unused parameter" warnings on the R3
    (void)len;
#endif
}

uint8_t WifiLink::recv(uint8_t *buf, uint8_t maxLen) {
#if BOARD_HAS_WIFI
    if (!connected()) return 0;

    int available = _udp.parsePacket();
    if (available <= 0) return 0;

    int take = (available < (int)maxLen) ? available : (int)maxLen;
    int got = _udp.read(buf, (size_t)take);

    // Discard bytes beyond maxLen so the next call starts on a fresh datagram.
    for (int i = got; i < available; i++) (void)_udp.read();

    return (got > 0) ? (uint8_t)got : 0;
#else
    (void)buf;
    (void)maxLen;
    return 0;
#endif
}

uint32_t WifiLink::airtimeMs(uint8_t bytes) const {
#if BOARD_HAS_WIFI
    // ~60 B of UDP/IP/MAC overhead at ~1 Mbit/s plus 2 ms turnaround.
    const uint32_t overheadBytes = 60;
    return (((uint32_t)bytes + overheadBytes) * 8UL * 1000UL) / 1000000UL + 2UL;
#else
    (void)bytes;
    return 1;   // never used; Wi-Fi is unavailable
#endif
}
