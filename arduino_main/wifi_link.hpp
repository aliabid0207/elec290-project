#ifndef WIFI_LINK_HPP
#define WIFI_LINK_HPP

#include "board_config.hpp"  // brings in WiFiNINA.h on Rev2, nothing on R3
#include "link.hpp"          // ILink, the interface we must satisfy
#include "config.hpp"        // SSID, password, port, peer IP, timeouts

// ============================================================================
// WifiLink — the OPTIONAL fallback medium (portfolio 3.1.1).
//
// Only the Uno WiFi Rev2 has a radio. The Uno R3 has no Wi-Fi hardware, so on
// that board this class still exists (so the rest of the code compiles) but
// every method is a no-op: connect() returns false, send() does nothing, etc.
// The host sees "WIFI NOT AVAILABLE" instead of a connection failure.
//
// On the Rev2 the library is WiFiNINA, whose API is very similar to other
// Arduino Wi-Fi libraries (beginPacket/write/endPacket, parsePacket/read).
//
// "Inactive by default" is deliberate: the portfolio says Wi-Fi is only used
// when the user approves or explicitly requests it. The host must send "WIFI ON".
//
// CREDENTIALS: copy arduino_secrets.example.h to arduino_secrets.h and edit it.
// That file is gitignored. Without it, the CHANGE_ME defaults in config.hpp apply.
// ============================================================================
class WifiLink : public ILink {
public:
    WifiLink();

    // ILink requirement: reset flags. Does NOT associate with an access point.
    void begin() override;

    // Extra Wi-Fi-specific methods:
    bool connect();         // blocking, bounded wait; false if unavailable/failed
    void disconnect();
    bool connected() const;

    void send(const uint8_t *buf, uint8_t len) override;
    uint8_t recv(uint8_t *buf, uint8_t maxLen) override;

    // Wi-Fi has no IR-style listen-before-talk; radio handles medium access.
    bool channelClear() override { return true; }
    bool isActive() const override { return _active; }
    void setActive(bool on) override { if (on) connect(); else disconnect(); }

    uint32_t airtimeMs(uint8_t bytes) const override;
    uint32_t latencyMs() const override { return CFG_WIFI_LATENCY_MS; }
    const char *name() const override { return "WIFI"; }

private:
    bool _active;   // on the R3 this is always false

#if BOARD_HAS_WIFI
    bool _bound;
    IPAddress _peer;   // the OTHER board's IP
    WiFiUDP _udp;      // the library object that sends/receives UDP datagrams
#endif
};

#endif // WIFI_LINK_HPP
