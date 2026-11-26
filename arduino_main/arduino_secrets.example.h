#ifndef ARDUINO_SECRETS_H
#define ARDUINO_SECRETS_H

// ---------------------------------------------------------------------------
// HOW TO USE THIS FILE
// ---------------------------------------------------------------------------
// 1. Make a COPY named arduino_secrets.h in this same folder.
// 2. Edit the copy with your real Wi-Fi details.
// 3. Do NOT commit it: .gitignore already lists arduino_main/arduino_secrets.h,
//    so Git will never add your password to the repository.
//
// This .example.h file IS committed on purpose: it documents the format.
//
// wifi_link.cpp includes arduino_secrets.h BEFORE config.hpp, and config.hpp
// only supplies its CHANGE_ME defaults if these names are not defined yet.
// That is how the real values "win" without editing any other source file.
//
// Each board needs its own copy. PEER IP must be the OTHER board's address:
//   Device A: peer = Device B's IP
//   Device B: peer = Device A's IP
// ---------------------------------------------------------------------------

#define CFG_WIFI_SSID      "YOUR_WIFI_SSID"
#define CFG_WIFI_PASS      "YOUR_WIFI_PASSWORD"

// Uncomment and edit if 192.168.1.50 (the default in config.hpp) is not the
// address of the other board. The four numbers are the octets of an IPv4 IP.
// constexpr uint8_t CFG_WIFI_PEER_IP[4] = {192, 168, 1, 50};

#endif // ARDUINO_SECRETS_H
