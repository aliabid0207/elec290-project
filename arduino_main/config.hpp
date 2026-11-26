#ifndef CONFIG_HPP
#define CONFIG_HPP

// Header guard: if another file includes this header twice, the second copy is
// skipped. Otherwise the compiler would see duplicate definitions and fail.

#include <Arduino.h>        // we use Arduino types such as uint8_t / uint32_t
#include "board_config.hpp" // detects Rev2 vs R3 and pulls in the right Wi-Fi library
#include "phy.hpp"          // reuse the PHY_* timing constants from the IR layer
                            // (one source of truth: change a number in ONE place)

// ============================================================================
// config.hpp — IDENTITY + EVERY TUNABLE NUMBER IN THE PROJECT.
//
// Why a separate file? Imagine a timeout is mentioned in five different files.
// If you change it in four of them, the behaviour becomes mysterious. Here all
// the "magic numbers" live together, with comments explaining the units.
//
// Two C++ ideas used below:
//   * `#define NAME value` is a PREPROCESSOR macro: the compiler literally
//     replaces NAME with value before compiling. Useful for conditional code.
//   * `constexpr uint8_t X = 4;` is a real typed constant. The compiler checks
//     its type, and it takes no RAM because it is folded into the code.
//
// RULES FOR THIS FILE:
//   1. Header-only: constants and macros only, no functions with storage.
//   2. If you need a new tunable elsewhere, add it HERE with its unit and why.
//   3. Do not rename existing symbols; other files depend on these names.
// ============================================================================

// ---------------------------------------------------------------------------
// 1. DEVICE IDENTITY — set automatically from the board detection above.
// ---------------------------------------------------------------------------
// The Uno WiFi Rev2 is Device A and the Uno R3 is Device B (as requested).
// If you ever need to override it, define one of these BEFORE including this
// header (e.g. with a compiler flag). Otherwise the code below chooses for you.
#if !defined(DEVICE_ROLE_A) && !defined(DEVICE_ROLE_B)
  #if defined(BOARD_UNO_WIFI_REV2)
    #define DEVICE_ROLE_A
  #else
    #define DEVICE_ROLE_B
  #endif
#endif

// The #if/#error block is a compile-time safety net: if someone forgets, or
// enables both by mistake, compilation stops with a clear message instead of
// producing a device that silently uses the wrong ID.
#if defined(DEVICE_ROLE_A) && defined(DEVICE_ROLE_B)
#error "Define exactly one of DEVICE_ROLE_A / DEVICE_ROLE_B"
#elif !defined(DEVICE_ROLE_A) && !defined(DEVICE_ROLE_B)
#error "Define exactly one of DEVICE_ROLE_A / DEVICE_ROLE_B"
#endif

// SELF_ID is put in every packet we send; PEER_ID is the ID we accept from the
// other board. They also go into the AEAD nonce, which is why A and B can share
// one secret key without ever generating the same nonce.
#if defined(DEVICE_ROLE_A)
  constexpr uint8_t SELF_ID = 0x0A;   // 0x means hexadecimal (base 16)
  constexpr uint8_t PEER_ID = 0x0B;
#else
  constexpr uint8_t SELF_ID = 0x0B;
  constexpr uint8_t PEER_ID = 0x0A;
#endif

// ---------------------------------------------------------------------------
// 2. PC <-> ARDUINO (USB serial)
// ---------------------------------------------------------------------------
constexpr uint32_t CFG_SERIAL_BAUD   = 115200;  // bits per second; PC must match
constexpr uint8_t  CFG_HOST_LINE_MAX = 48;      // longest accepted host line, bytes

// ---------------------------------------------------------------------------
// 3. STATUS RGB LED
// ---------------------------------------------------------------------------
// Common-cathode LED with ONE shared 220 Ω resistor means only one colour can
// be lit at a time (portfolio section 3.3.2). HIGH = colour on.
constexpr uint8_t CFG_LED_R = 4;
constexpr uint8_t CFG_LED_G = 5;
constexpr uint8_t CFG_LED_B = 6;

// ---------------------------------------------------------------------------
// 4. PROTOCOL BEHAVIOUR (reliability rules)
// ---------------------------------------------------------------------------
// Retries AFTER the first attempt (portfolio 3.1.4 step 6: "up to three
// retries"). Total transmissions per message = 1 + CFG_MAX_RETRIES = 4.
constexpr uint8_t  CFG_MAX_RETRIES = 3;

// Random wait in milliseconds before a retry or after finding the channel busy.
// While a device transmits it is deaf: a frame lasts roughly 0.3-0.5 s. If both
// boards start at the same instant, neither hears the other. A random delay
// breaks that tie. 50-400 ms is deliberately wider than one frame time.
constexpr uint32_t CFG_BACKOFF_MIN_MS = 50;
constexpr uint32_t CFG_BACKOFF_MAX_MS = 400;

// How many consecutive "channel busy" results before giving up on a message.
constexpr uint8_t  CFG_MAX_CHANNEL_BUSY = 8;

// Listen-before-talk window in MICROSECONDS (1 ms = 1000 µs). It must be longer
// than the longest continuous HIGH inside a Manchester frame (2 half-bits =
// 1000 µs), otherwise a frame already in progress could look like silence.
constexpr uint32_t CFG_LBT_IDLE_US = 2000UL;

// ---------------------------------------------------------------------------
// 5. ACK TIMEOUT BUDGET (all milliseconds)
// ---------------------------------------------------------------------------
// Communication computes:
//     timeout = airtime(ACK) + 2 x link latency + CFG_ACK_MARGIN_MS
// so it adapts automatically to IR (slow) or Wi-Fi (fast). Do not hard-code it.
//
// CFG_IR_PROC_MS is our estimate of receiver-side work: Manchester decoding
// over a few hundred edges plus ChaCha20-Poly1305 on at most 47 bytes. It should
// be MEASURED on real hardware with micros() around the receive handler.
constexpr uint32_t CFG_IR_PROC_MS    = 20;
constexpr uint32_t CFG_ACK_MARGIN_MS = 60;

// ---------------------------------------------------------------------------
// 6. WI-FI FALLBACK (Uno WiFi Rev2 ONLY, WiFiNINA library)
// ---------------------------------------------------------------------------
// The Uno R3 has no Wi-Fi hardware, so these values are ignored there and the
// WIFI ON command reports "not available". On the Rev2, copy
// arduino_secrets.example.h to arduino_secrets.h and edit it. That file is
// gitignored (never committed). wifi_link.cpp includes it BEFORE this header,
// so its #defines replace these defaults. The #ifndef checks mean "only define
// the default if nobody has defined this name already".
#ifndef CFG_WIFI_SSID
#define CFG_WIFI_SSID      "CHANGE_ME"
#endif
#ifndef CFG_WIFI_PASS
#define CFG_WIFI_PASS      "CHANGE_ME"
#endif

// UDP port both boards listen on. It just needs to be the same on each side.
constexpr uint16_t CFG_WIFI_UDP_PORT  = 4210;

// The OTHER board's IP. Both boards should be on the same router/hotspot with
// reserved addresses. wifi_link.cpp turns these four octets into an IPAddress.
#ifndef CFG_WIFI_PEER_IP
constexpr uint8_t  CFG_WIFI_PEER_IP[4] = {192, 168, 1, 50};
#endif

// Give up connecting after 10 s rather than hanging the whole program.
constexpr uint32_t CFG_WIFI_CONNECT_TIMEOUT_MS = 10000;

// Rough one-way processing estimate for the Wi-Fi path, used in ACK timeouts.
constexpr uint32_t CFG_WIFI_LATENCY_MS = 30;

#endif // CONFIG_HPP
