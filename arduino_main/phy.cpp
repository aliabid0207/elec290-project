// phy.cpp
// ELEC 290 — IR Physical Layer for Uno WiFi Rev2 / Uno R3
// Manchester encoding/decoding at 1 kbit/s over a 38 kHz carrier.
// See phy.hpp for the hardware description and timing rationale.

#include "phy.hpp"

// ============================================================================
// ISR = "Interrupt Service Routine": a tiny function the hardware calls
// automatically when the RX pin changes state. It must be very fast.
//
// MEMORY-SAVING DESIGN (critical on the Uno R3's 2 KB of SRAM):
// Each edge is stored in ONE BYTE, not a 16-bit word:
//   bits 0..6 = time since previous edge in units of 100 µs (0..12700 µs)
//   bit 7     = pin level AFTER the edge (1 = HIGH, 0 = LOW)
//
// A half-bit is 500 µs = 5 units; a full bit is 1000 µs = 10 units. These
// small numbers give plenty of tolerance for clock jitter. The 100 µs scale
// is fine because our decoder only distinguishes ~500 µs from ~1000 µs.
//
// MAX_EDGES = 512. A full 47-byte packet is 24+8+47*8 = 408 Manchester bits.
// Every bit has a mid-bit edge, and a second edge appears at the boundary when
// two adjacent bits are equal. With random ciphertext that averages ~1.5 edges
// per bit, i.e. ~600 edges for a FULL packet. So 512 is comfortable for short
// messages but a maximum-length payload can overflow the buffer. Do NOT shrink
// this further: the real fix for full-length messages is a streaming decoder
// that decodes inside the ISR instead of storing edges. The exact frame gap is
// still tracked by a separate 32-bit timestamp.
//
// `static` = private to this .cpp. `volatile` = "may change inside an interrupt;
// never cache in a register". The buffers are global because an ISR cannot
// easily receive a `this` pointer, and there is only one receiver.
// ============================================================================
#define MAX_EDGES          512
#define EDGE_LEVEL_BIT     0x80
#define EDGE_INTERVAL_MASK 0x7F
#define EDGE_SCALE_US      100UL

static volatile uint8_t _edges[MAX_EDGES];
static volatile uint16_t _edgeCount  = 0;
static volatile uint32_t _lastEdgeUs = 0;

// The ISR cannot capture `this`, so keep the RX pin number in a global too.
static uint8_t _rxPinISR = PHY_RX_PIN;

// Called by hardware on every CHANGE of the TSOP output pin.
static void TSOP_ISR() {
    uint32_t now      = micros();
    uint32_t interval = now - _lastEdgeUs;
    uint16_t idx      = _edgeCount;
    if (idx < MAX_EDGES) {
        // Convert µs to 100 µs units, clamped to 7 bits so the level bit is
        // never overwritten. Long gaps (noise) simply store as 127.
        uint16_t units = (uint16_t)(interval / EDGE_SCALE_US);
        if (units > EDGE_INTERVAL_MASK) units = EDGE_INTERVAL_MASK;
        uint8_t packed = (uint8_t)units;
        if (digitalRead(_rxPinISR) == HIGH) packed |= EDGE_LEVEL_BIT;
        _edges[idx] = packed;
        _edgeCount  = idx + 1;
    }
    _lastEdgeUs = now;
}

// ============================================================================
// Constructor & begin
// ============================================================================
PHY::PHY(uint8_t txPin, uint8_t rxPin) : _txPin(txPin), _rxPin(rxPin) {}

void PHY::begin() {
    pinMode(_txPin, OUTPUT);
    pinMode(_rxPin, INPUT);  // TSOP has an open-collector output with pull-up

    // No analogWriteFrequency() here: that function is R4-only and is not
    // available on the AVR boards. tone()/noTone() below produce the 38 kHz
    // carrier on both the Rev2 and the R3.
    _carrierOff();

    _rxPinISR = _rxPin;

    // Seed the pseudo-random generator from two floating analog inputs plus
    // the microsecond clock, so backoff delays differ between the two boards.
    randomSeed(analogRead(A0) ^ analogRead(A1) ^ (uint32_t)micros());

    enableRx();
}

void PHY::enableRx() {
    noInterrupts();          // critical section: update shared variables safely
    _edgeCount  = 0;
    _lastEdgeUs = micros();
    interrupts();
    attachInterrupt(digitalPinToInterrupt(_rxPin), TSOP_ISR, CHANGE);
}

void PHY::disableRx() {
    detachInterrupt(digitalPinToInterrupt(_rxPin));
}

// ============================================================================
// Carrier helpers
// ============================================================================
// tone() starts a 50%-duty square wave on the pin using a hardware timer.
// noTone() stops it and leaves the pin LOW, which switches the LED off.
// Calling these every 500 µs is cheap enough for our 1 kbit/s bit rate.
void PHY::_carrierOn()  { tone(_txPin, PHY_CARRIER_HZ); }
void PHY::_carrierOff() { noTone(_txPin); }

// ============================================================================
// Manchester transmit
//
// Bit 1: carrier ON first half, OFF second half -> TSOP LOW then HIGH.
// Bit 0: carrier OFF first half, ON second half -> TSOP HIGH then LOW.
//
// delayMicroseconds() handles the 500 µs half-cells. A few µs of timer jitter
// is negligible compared with the decoder's ±250 µs tolerance.
// ============================================================================
void PHY::_sendBit(bool one) {
    if (one) {
        _carrierOn();  delayMicroseconds(PHY_HALF_BIT_US);
        _carrierOff(); delayMicroseconds(PHY_HALF_BIT_US);
    } else {
        _carrierOff(); delayMicroseconds(PHY_HALF_BIT_US);
        _carrierOn();  delayMicroseconds(PHY_HALF_BIT_US);
    }
}

// Send the most-significant BIT first (i = 7 down to 0). Shifting right by i
// moves the wanted bit into position 0; `& 1` keeps only that bit.
void PHY::_sendByte(uint8_t b) {
    for (int8_t i = 7; i >= 0; --i)
        _sendBit((b >> i) & 1);
}

void PHY::send(const uint8_t *buf, uint8_t len) {
    disableRx();             // half-duplex: don't listen to our own LED
    noInterrupts();          // keep timing precise during the whole frame

    // Preamble 0,1,0,1... lets the TSOP AGC settle (`i & 1` gives 0,1,0,1...).
    for (uint8_t i = 0; i < PHY_PREAMBLE_BITS; i++)
        _sendBit(i & 1);

    // Sync byte 0x7E: an alternating preamble can never contain 01111110,
    // so the receiver can use it as an unambiguous frame delimiter.
    _sendByte(PHY_SYNC_BYTE);

    for (uint8_t i = 0; i < len; i++)
        _sendByte(buf[i]);

    _carrierOff();           // end with the channel idle

    interrupts();

    // Wait 3 ms: TSOP AGC recovers and our own receiver stops seeing echoes.
    delay(3);

    enableRx();              // clear edge buffer and arm interrupt for the ACK
}

// ============================================================================
// Channel sense (listen-before-talk)
// ============================================================================
bool PHY::isIdle(uint32_t idleUs) {
    uint32_t start = micros();
    while ((uint32_t)(micros() - start) < idleUs) {
        if (digitalRead(_rxPin) == LOW) return false;   // carrier detected
    }
    return true;
}

// ============================================================================
// recv — non-blocking frame receiver
// ============================================================================
uint8_t PHY::recv(uint8_t *buf, uint8_t maxLen) {
    uint16_t count;
    uint32_t lastEdge;

    // Take a consistent snapshot of the ISR-owned variables.
    noInterrupts();
    count    = _edgeCount;
    lastEdge = _lastEdgeUs;
    interrupts();

    if (count == 0) return 0;

    // A frame is complete only after PHY_FRAME_GAP_US of silence.
    if ((uint32_t)(micros() - lastEdge) < PHY_FRAME_GAP_US) return 0;

    uint8_t decoded = _manchesterDecode(buf, maxLen);

    enableRx();   // reset edge buffer and re-arm the ISR
    return decoded;
}

// ============================================================================
// Manchester decoder
//
// Classifying intervals (H = 500 µs, tolerance ±250 µs):
//   SHORT ≈ 500 µs  : a boundary between bits; mid-bit edge comes next
//   LONG  ≈ 1000 µs : a direct mid-bit transition
//   other           : noise -> reset decoder state
//
// Instead of storing decoded BITS, we append each decoded bit immediately to
// a byte accumulator. When 8 bits are collected we append the byte to a small
// static array. Then we scan those BYTES for the sync byte 0x7E and return the
// bytes that follow it. The alternating preamble produces only 0x55/0xAA
// bytes, so it can never be mistaken for 0x7E.
// ============================================================================
uint8_t PHY::_manchesterDecode(uint8_t *buf, uint8_t maxLen) {
    uint16_t count;
    noInterrupts();
    count = _edgeCount;
    interrupts();

    if (count < 4) return 0;

    // Thresholds in 100 µs units (see EDGE_SCALE_US above):
    //   SHORT ~500 µs -> 3..7 units, LONG ~1000 µs -> 8..12 units.
    // The gap between 7 and 8 gives the decoder plenty of timing tolerance.
    const uint8_t SHORT_LO = 3;
    const uint8_t SHORT_HI = 7;
    const uint8_t LONG_LO  = 8;
    const uint8_t LONG_HI  = 12;

    // Small scratch buffer in .bss (not on the stack). Only loop() calls this.
    static uint8_t decoded[PHY_MAX_FRAME + 2];
    uint8_t nDecoded = 0;
    uint8_t currentByte = 0;
    uint8_t bitsInByte = 0;
    bool needMid = false;

    // Skip edge[0]: its interval is measured from when the ISR was armed,
    // not from a real previous edge.
    for (uint16_t i = 1; i < count; i++) {
        uint8_t packed   = _edges[i];
        uint8_t interval = packed & EDGE_INTERVAL_MASK;
        uint8_t level    = (packed & EDGE_LEVEL_BIT) ? HIGH : LOW;

        bool isShort = (interval >= SHORT_LO && interval <= SHORT_HI);
        bool isLong  = (interval >= LONG_LO  && interval <= LONG_HI);

        if (!isShort && !isLong) {
            needMid = false;   // noise: discard partial state
            continue;
        }

        if (needMid || isLong) {
            // Mid-bit edge. The level AFTER it gives the bit value:
            // HIGH -> second half was a gap -> bit 1.
            bool bit = (level == HIGH);
            currentByte = (uint8_t)((currentByte << 1) | (bit ? 1 : 0));
            if (++bitsInByte == 8) {
                if (nDecoded < sizeof(decoded)) decoded[nDecoded++] = currentByte;
                currentByte = 0;
                bitsInByte = 0;
            }
            needMid = false;
        } else {
            needMid = true;    // SHORT boundary: mid-bit edge is next
        }
    }

    if (nDecoded == 0) return 0;   // any partial byte is ignored

    // Find the sync byte, then copy the following bytes to the caller.
    int syncEnd = -1;
    for (int i = 0; i < (int)nDecoded; i++) {
        if (decoded[i] == PHY_SYNC_BYTE) { syncEnd = i + 1; break; }
    }
    if (syncEnd < 0) return 0;

    uint8_t nBytes = 0;
    for (int pos = syncEnd; pos < (int)nDecoded && nBytes < maxLen; pos++) {
        buf[nBytes++] = decoded[pos];
    }
    return nBytes;
}
