// ELEC 290 Fall 2026 — secure bidirectional communication node.
// Target: Arduino Uno WiFi Rev2 (Device A) or Arduino Uno R3 (Device B).
// The host PC talks to this sketch over USB serial.
//
// This is the "main" file Arduino looks for (a .ino file with setup()/loop()).
// Its job is to wire the lower-level modules together and provide the user
// interface. It does NOT implement the protocol or the radio itself.
//
// Host commands (115200 baud, one command per line, press Enter to send):
//   HELP                 list commands
//   STATUS               device role, epoch/counter, active link, state
//   SEND <text>          encrypt and transmit (max 24 bytes)
//   WIFI ON|OFF|STATUS   approve/leave the UDP fallback link
//   SELFTEST             run the ChaCha20-Poly1305 self-test
//
// Unsolicited lines printed by this node:
//   RECV <text>          an authenticated message from the peer
//   TX OK / TX FAIL      delivery result for the last SEND
//   RX REJECT <reason>   an invalid/tampered/replayed frame was dropped
// ============================================================================

#include <Arduino.h>       // core Arduino functions: millis(), pinMode(), Serial...
#include <ctype.h>         // toupper(), for case-insensitive commands
#include <string.h>        // strtok(), strcmp_P(), strlen(), memcpy(), memcmp()

// Our own project modules. Each header describes one piece of the system.
#include "config.hpp"         // roles, pins, timeouts, Wi-Fi settings
#include "encryption.hpp"     // ChaCha20-Poly1305 wrapper
#include "protocol.hpp"       // packet format constants and helper functions
#include "link.hpp"           // ILink interface
#include "ir_link.hpp"        // IR implementation of ILink
#include "wifi_link.hpp"      // Wi-Fi implementation of ILink
#include "communication.hpp"  // the protocol engine that ties it all together

// ---------------------------------------------------------------------------
// Hardware / protocol objects (created once, live for the whole program)
// ---------------------------------------------------------------------------
// Think of these as four "workers":
//   crypto  knows how to lock and unlock messages.
//   phy     knows how to wiggle the IR LED at 38 kHz and decode the receiver.
//   ir      wraps `phy` so it matches the generic ILink shape.
//   wifi    is a second ILink, initially switched off.
//   comm    is the traffic controller; it starts out using the IR link.
Encryption crypto;
PHY phy;
IrLink ir(phy);
WifiLink wifi;
Communication comm(crypto, ir);   // WIFI ON will switch the link to `wifi`

// ---------------------------------------------------------------------------
// Status RGB LED
// ---------------------------------------------------------------------------
// The board has a common-cathode RGB LED: all three cathodes share one 220 Ω
// resistor, so we only light ONE colour at a time. HIGH means "colour on".
// An enum gives readable names to the four possibilities.
enum LedColor { LED_OFF, LED_RED, LED_GREEN, LED_BLUE };

// static = these variables are private to this .ino file. They remember the
// current LED state between calls to loop().
static LedColor currentLed = LED_OFF;
static LedColor heldLed = LED_OFF;
static uint32_t heldUntil = 0;   // millis() value when a temporary flash ends

// Actually write the pins. The ternary `? :` operator chooses HIGH for the
// matching colour and LOW for the other two, guaranteeing only one is lit.
static void applyLed(LedColor c) {
    if (c == currentLed) return;  // avoid unnecessary pin writes
    digitalWrite(CFG_LED_R, (c == LED_RED)   ? HIGH : LOW);
    digitalWrite(CFG_LED_G, (c == LED_GREEN) ? HIGH : LOW);
    digitalWrite(CFG_LED_B, (c == LED_BLUE)  ? HIGH : LOW);
    currentLed = c;
}

// Ask for a temporary colour (e.g. blue for 250 ms when a message arrives).
// refreshLed() below decides when the flash is over.
static void flashLed(LedColor c, uint32_t ms) {
    heldLed = c;
    heldUntil = millis() + ms;
}

// Called every loop. Normal state: red while transmitting, green when idle.
// A recent flash overrides that until its timer expires.
static void refreshLed() {
    LedColor want = comm.busy() ? LED_RED : LED_GREEN;
    if (heldUntil != 0 && (int32_t)(millis() - heldUntil) < 0) want = heldLed;
    else heldUntil = 0;
    applyLed(want);
}

// ---------------------------------------------------------------------------
// Communication callbacks
// ---------------------------------------------------------------------------
// Communication does not know Serial exists. Instead, we give it the ADDRESS
// of these two functions. It calls them when something happens. The (void)
// casts mean "we received these arguments but don't need them here"; they
// silence compiler warnings.
static void onMessage(const uint8_t *payload, uint8_t len,
                      uint8_t src, uint16_t epoch, uint16_t ctr) {
    (void)src; (void)epoch; (void)ctr;
    Serial.print(F("RECV "));
    // The payload is raw bytes, not guaranteed to end in '\0', so we print
    // exactly `len` bytes with write() rather than using print() on a string.
    for (uint8_t i = 0; i < len; i++) Serial.write(payload[i]);
    Serial.println();
    flashLed(LED_BLUE, 250);
}

// Communication reports events (TX started, TX succeeded, frame rejected...)
// through this function. We turn them into host messages and LED flashes.
static void onEvent(CommEvent event, uint16_t code) {
    switch (event) {              // switch = multi-way branch on one value
        case COMM_TX_START:
            flashLed(LED_RED, 120);
            break;
        case COMM_TX_OK:
            Serial.print(F("TX OK ("));
            Serial.print((unsigned int)(code + 1));  // code is 0-based
            Serial.println(F(" attempt(s))"));
            flashLed(LED_GREEN, 300);
            break;
        case COMM_TX_FAIL:
            Serial.println(F("TX FAIL"));
            flashLed(LED_RED, 600);
            break;
        case COMM_RX_OK:
            flashLed(LED_BLUE, 250);   // the text is printed by onMessage()
            break;
        case COMM_RX_REJECT:
            Serial.print(F("RX REJECT "));
            Serial.println((unsigned int)code);  // 1=malformed 2=wrong src
            flashLed(LED_RED, 200);              // 3=replay 4=bad tag
            break;
        case COMM_WIFI_UP:
            Serial.println(F("WIFI UP"));
            break;
        case COMM_WIFI_DOWN:
            Serial.println(F("WIFI DOWN"));
            break;
    }
}

// ---------------------------------------------------------------------------
// Crypto self-test (also covers the zero-length ACK payload)
// ---------------------------------------------------------------------------
// A self-test is a small program inside the program that checks the crypto is
// behaving correctly. It returns true only if EVERY check passes.
static bool selfTestCrypto() {
    // Reuse the GLOBAL cipher object instead of creating a local one. A local
    // Encryption holds a ChaChaPoly state (~250 bytes) on the stack, which is
    // dangerous when the R3 only has ~400 bytes of stack left. Sharing is safe:
    // every seal()/open() call installs a fresh IV, so no state carries over.
    crypto.init();        // reload the key before testing

    // A made-up nonce and 7-byte header. The actual values do not matter as
    // long as they are the same for seal() and open().
    uint8_t nonce[PROTO_NONCE_LEN] = { 0x01, 0x0A, 0x00, 0x01,
                                       0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    uint8_t aad[PROTO_HDR_LEN]     = { 0x01, 0x0A, 0x00, 0x01,
                                       0x00, 0x01, 0x05 };
    const uint8_t message[5] = { 'H', 'E', 'L', 'L', 'O' };
    uint8_t cipher[5], tag[PROTO_TAG_LEN], plain[5];

    // Test 1: encrypt, then decrypt, and compare with the original.
    if (!crypto.seal(nonce, aad, sizeof(aad), message, sizeof(message),
                   cipher, tag, sizeof(tag))) return false;
    if (!crypto.open(nonce, aad, sizeof(aad), cipher, sizeof(cipher),
                   tag, sizeof(tag), plain)) return false;
    if (memcmp(plain, message, sizeof(message)) != 0) return false;

    // Test 2: tamper with ONE bit of the tag. open() must refuse the data AND
    // zero the output buffer, so unauthenticated bytes can never be delivered.
    uint8_t badTag[PROTO_TAG_LEN];
    uint8_t wiped[5] = { 1, 2, 3, 4, 5 };
    memcpy(badTag, tag, sizeof(tag));
    badTag[0] ^= 0x01;              // XOR with 1 flips the lowest bit
    if (crypto.open(nonce, aad, sizeof(aad), cipher, sizeof(cipher),
                  badTag, sizeof(badTag), wiped)) return false;
    for (uint8_t i = 0; i < sizeof(wiped); i++) if (wiped[i] != 0) return false;

    // Test 3: ACKs have no payload. Check seal/open still work with len = 0.
    uint8_t emptyTag[PROTO_TAG_LEN];
    const uint8_t emptyPayload = 0;  // a real address, but we pass length 0
    if (!crypto.seal(nonce, aad, sizeof(aad), &emptyPayload, 0,
                   cipher, emptyTag, sizeof(emptyTag))) return false;
    if (!crypto.open(nonce, aad, sizeof(aad), cipher, 0,
                   emptyTag, sizeof(emptyTag), plain)) return false;

    return true;    // reached the end => all tests passed
}

// ---------------------------------------------------------------------------
// Host serial interface
// ---------------------------------------------------------------------------
// We read incoming bytes into a fixed-size character array. A "C string" is
// just characters followed by a '\0' (null) terminator, which is why the array
// is CFG_HOST_LINE_MAX + 1 bytes long: one extra slot for the '\0'.
//
// IMPORTANT FOR THE UNO R3: plain "..." text in Serial.print() would normally
// be copied into SRAM at startup. Wrapping it in F("...") keeps it in flash
// memory instead, where there is plenty of room. Every message below uses F()
// for this reason — it saved several hundred bytes of precious RAM.
static char hostLine[CFG_HOST_LINE_MAX + 1];
static uint8_t hostLen = 0;
static bool hostOverflow = false;   // true if a line was longer than the buffer

// Convert a string to upper case in place, so "send" and "SEND" both work.
// The unsigned char cast is needed because toupper() expects 0..255.
static void upper(char *s) {
    for (; *s; s++) *s = (char)toupper((unsigned char)*s);
}

// Return a pointer to the first non-space character (skip leading blanks).
static char *trimLeft(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

static void printHelp() {
    Serial.println(F("COMMANDS:"));
    Serial.println(F("  HELP"));
    Serial.println(F("  STATUS"));
    Serial.println(F("  SEND <text>"));
    Serial.println(F("  WIFI ON|OFF|STATUS"));
    Serial.println(F("  SELFTEST"));
}

static void printStatus() {
    // #if is evaluated at COMPILE time. Only one of these println lines ends
    // up in the firmware, depending on which role is defined in config.hpp.
#if defined(DEVICE_ROLE_A)
    Serial.println(F("ROLE A"));
#else
    Serial.println(F("ROLE B"));
#endif
    Serial.print(F("SELF 0x")); Serial.println((unsigned int)SELF_ID, HEX);
    Serial.print(F("PEER 0x")); Serial.println((unsigned int)PEER_ID, HEX);
    Serial.print(F("EPOCH ")); Serial.println((unsigned int)comm.epoch());
    Serial.print(F("COUNTER ")); Serial.println((unsigned int)comm.counter());
    Serial.print(F("LINK ")); Serial.println(comm.link()->name());
    Serial.print(F("BUSY ")); Serial.println(comm.busy() ? F("YES") : F("NO"));
    Serial.print(F("BOARD ")); Serial.println(F(BOARD_NAME));
    Serial.print(F("WIFI "));
#if BOARD_HAS_WIFI
    Serial.println(wifi.connected() ? F("UP") : F("DOWN"));
#else
    Serial.println(F("NOT AVAILABLE"));
#endif
}

// Parse and execute one completed line of text from the PC.
static void processLine(char *line) {
    // strtok() splits a string into "tokens". Passing the string the first
    // time starts the split; passing nullptr continues where it left off.
    // Here the first token is the command, and the rest is its argument.
    char *cmd = strtok(line, " \t");
    if (!cmd) return;             // empty line
    upper(cmd);
    char *arg = trimLeft(strtok(nullptr, ""));

    // strcmp_P() compares a normal string with one stored in FLASH via PSTR().
    // Like F() for Serial output, this keeps the command words out of SRAM.
    // It returns 0 when the two strings are identical.
    if (strcmp_P(cmd, PSTR("HELP")) == 0) {
        printHelp();
    } else if (strcmp_P(cmd, PSTR("STATUS")) == 0) {
        printStatus();
    } else if (strcmp_P(cmd, PSTR("SEND")) == 0) {
        if (!arg || *arg == '\0') {
            Serial.println(F("USAGE: SEND <text>"));
        } else if (strlen(arg) > PROTO_MAX_PAYLOAD) {
            // Print the limit from the constant so this message can never get
            // out of sync if the payload size is tuned later.
            Serial.print(F("TOO LONG (max "));
            Serial.print((unsigned int)PROTO_MAX_PAYLOAD);
            Serial.println(F(" bytes)"));
        } else if (comm.busy()) {
            Serial.println(F("BUSY"));       // finish current transfer first
        } else if (comm.sendText(arg)) {
            Serial.println(F("TX QUEUED"));  // real result arrives later as TX OK
        } else {
            Serial.println(F("TX ERROR"));
        }
    } else if (strcmp_P(cmd, PSTR("WIFI")) == 0) {
        if (!arg || *arg == '\0' || strcmp_P(arg, PSTR("STATUS")) == 0) {
            Serial.print(F("WIFI "));
#if BOARD_HAS_WIFI
            Serial.println(wifi.connected() ? F("UP") : F("DOWN"));
#else
            Serial.println(F("NOT AVAILABLE"));   // R3 has no radio
#endif
        } else {
            upper(arg);
#if !BOARD_HAS_WIFI
            // The R3 has no Wi-Fi hardware, so reject ON/OFF before compiling
            // any of the connection code below (it is compiled out anyway).
            Serial.println(F("WIFI NOT AVAILABLE"));
#else
            if (strcmp_P(arg, PSTR("ON")) == 0) {
                if (comm.busy()) {
                    Serial.println(F("BUSY"));
                } else if (wifi.connect()) {
                    // Only change the active link AFTER the connection works.
                    comm.setLink(&wifi);
                    onEvent(COMM_WIFI_UP, 0);
                } else {
                    Serial.println(F("WIFI FAIL"));
                }
            } else if (strcmp_P(arg, PSTR("OFF")) == 0) {
                if (comm.busy()) {
                    Serial.println(F("BUSY"));
                } else {
                    // Switch back to IR BEFORE shutting Wi-Fi down.
                    if (comm.link() == &wifi) comm.setLink(&ir);
                    wifi.disconnect();
                    onEvent(COMM_WIFI_DOWN, 0);
                }
            } else {
                Serial.println(F("USAGE: WIFI ON|OFF|STATUS"));
            }
#endif
        }
    } else if (strcmp_P(cmd, PSTR("SELFTEST")) == 0 || strcmp_P(cmd, PSTR("TEST")) == 0) {
        Serial.println(selfTestCrypto() ? F("SELFTEST PASS") : F("SELFTEST FAIL"));
    } else {
        Serial.println(F("UNKNOWN COMMAND - type HELP"));
    }
}

// Read bytes from the PC one at a time. We act only when Enter (newline)
// arrives, so a partially typed command is never executed.
static void readHost() {
    while (Serial.available() > 0) {
        char c = (char)Serial.read();
        if (c == '\r') continue;          // ignore carriage return (Windows)
        if (c == '\n') {                  // newline ends the line
            hostLine[hostLen] = '\0';     // terminate the C string
            if (hostOverflow) Serial.println(F("LINE TOO LONG"));
            else processLine(hostLine);
            hostLen = 0;                  // ready for the next line
            hostOverflow = false;
        } else if (hostLen < CFG_HOST_LINE_MAX) {
            hostLine[hostLen++] = c;
        } else {
            hostOverflow = true;          // remember, complain at newline
        }
    }
}

// ---------------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------------
// setup() runs once after power-on or reset.
void setup() {
    Serial.begin(CFG_SERIAL_BAUD);
    // On a board connected over USB, Serial may not be ready immediately.
    // Wait up to 2 s for the PC's serial monitor, but don't hang forever if
    // nobody is watching (e.g. the device is powered by a battery).
    uint32_t waitStart = millis();
    while (!Serial && (millis() - waitStart) < 2000) { /* wait for monitor */ }

    // Configure the three LED pins as outputs and start with all colours off.
    pinMode(CFG_LED_R, OUTPUT);
    pinMode(CFG_LED_G, OUTPUT);
    pinMode(CFG_LED_B, OUTPUT);
    digitalWrite(CFG_LED_R, LOW);
    digitalWrite(CFG_LED_G, LOW);
    digitalWrite(CFG_LED_B, LOW);

    // Seed the random-number generator from two floating analog pins and the
    // microsecond clock. Without this, random() would produce the same backoff
    // sequence on every boot.
    randomSeed(analogRead(A0) ^ analogRead(A1) ^ (uint32_t)micros());

    // Load the shared key into the MAIN cipher object. Without this, seal()
    // and open() would run with an empty key and nothing could be decrypted.
    // (SELFTEST uses its own separate Encryption object, so it can pass even
    // if this line is missing — which is why this deserves a clear comment.)
    crypto.init();

    phy.begin();     // IR pins, 38 kHz carrier, receiver interrupt
    wifi.begin();    // no access-point association until user says WIFI ON
    comm.setLink(&ir);
    comm.begin(onMessage, onEvent);  // registers callbacks + loads epoch

    Serial.print(F("ELEC290 SECURE LINK READY ("));
    Serial.print(F(BOARD_NAME));
#if defined(DEVICE_ROLE_A)
    Serial.println(F(", DEVICE A)"));
#else
    Serial.println(F(", DEVICE B)"));
#endif
    printHelp();
}

// loop() runs over and over, forever. Each pass must be short so the device
// stays responsive to both the PC and the other board.
void loop() {
    readHost();       // 1) any new command from the PC?
    comm.tick();      // 2) advance the protocol state machine by one small step

#if BOARD_HAS_WIFI
    // If the access point disappears while Wi-Fi is selected, go back to IR
    // automatically so the link is not left pointing at a dead medium.
    // Compiled out on the R3, which has no radio.
    if (wifi.isActive() && !wifi.connected()) {
        if (comm.link() == &wifi) comm.setLink(&ir);
        wifi.disconnect();
        onEvent(COMM_WIFI_DOWN, 0);
        Serial.println(F("WIFI LOST - USING IR"));
    }
#endif

    refreshLed();     // 3) update the indicator LEDs
}
