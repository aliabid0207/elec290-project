#ifndef PHY_HPP
#define PHY_HPP

#include <Arduino.h>

// ============================================================================
// PHY — the IR PHYSICAL LAYER for Arduino Uno WiFi Rev2 and Arduino Uno R3.
//
// "Physical layer" means the very bottom of the system: turning bytes into
// actual light pulses, and turning light pulses back into bytes. Everything
// above this file (protocol, encryption, host interface) never touches a pin.
//
// HARDWARE
// --------
//   TX  D9  — drives the IR LED through a resistor. We generate the required
//             38 kHz square wave with Arduino's tone() function, which works
//             on both AVR boards. tone() uses a hardware timer internally, so
//             the carrier stays accurate while the CPU does other work.
//             noTone() stops it and drives the pin LOW (LED off).
//
//   RX  D2  — TSOP38238 demodulating receiver. Its output is ACTIVE-LOW:
//             carrier present -> pin LOW, no carrier -> pin HIGH.
//             A CHANGE interrupt records timestamps so decoding can happen
//             later in loop() without blocking.
//
// MANCHESTER ENCODING (1 kbit/s, half-bit = 500 µs)
// --------------------------------------------------
//   Bit 1 : carrier ON first half, OFF second half
//           -> TSOP output LOW then HIGH -> RISING edge at mid-bit
//   Bit 0 : carrier OFF first half, ON second half
//           -> TSOP output HIGH then LOW -> FALLING edge at mid-bit
//
//   Every bit has a transition in the middle, which makes timing recovery easy.
//   Each frame = [24 alternating preamble bits | 0x7E sync byte | data bytes].
//   The preamble lets the receiver's AGC (automatic gain control) settle; the
//   sync byte marks exactly where the real data begins.
//
// MEMORY NOTE (important on the Uno R3)
// -------------------------------------
// The R3 has only 2 KB of SRAM. The receiver therefore does NOT store a large
// array of bits. It stores edge intervals with the pin level packed into one
// bit of each 16-bit word, and decodes bits directly into bytes. See phy.cpp.
//
// LISTEN-BEFORE-TALK
// ------------------
//   TSOP HIGH means no carrier, i.e. the channel is idle. isIdle(idleUs) checks
//   for a continuous HIGH period before we are allowed to transmit.
// ============================================================================

#define PHY_TX_PIN          9          // IR LED driver pin
#define PHY_RX_PIN          2          // TSOP38238 output pin (INT0)
#define PHY_CARRIER_HZ      38000UL    // 38 kHz carrier
#define PHY_HALF_BIT_US     500UL      // half a bit -> 1000 us per bit -> 1 kbit/s
#define PHY_BIT_US          (PHY_HALF_BIT_US * 2)
#define PHY_PREAMBLE_BITS   24         // alternating bits for AGC settling
#define PHY_SYNC_BYTE       0x7E       // frame start delimiter after preamble
#define PHY_MAX_FRAME       48         // max bytes per frame (packet is 47)
#define PHY_FRAME_GAP_US    5000UL     // silence after last edge = frame complete

// A class is a blueprint for an object that bundles DATA (the pins) with
// FUNCTIONS that operate on that data.
class PHY {
public:
    // Constructor with DEFAULT ARGUMENTS. `PHY phy;` uses pins 9 and 2.
    PHY(uint8_t txPin = PHY_TX_PIN, uint8_t rxPin = PHY_RX_PIN);

    // Call once from setup().
    void begin();

    // Transmit buf[len] as a Manchester-encoded IR frame.
    // BLOCKING: turns off the receive interrupt during transmission, waits 3 ms
    // afterwards for the TSOP AGC to recover, then re-enables receive.
    void send(const uint8_t *buf, uint8_t len);

    // NON-BLOCKING: try to decode a complete frame from the edge buffer.
    // A frame is complete once PHY_FRAME_GAP_US of silence has elapsed.
    // Returns the byte count written into buf (0 = no complete frame yet).
    uint8_t recv(uint8_t *buf, uint8_t maxLen);

    // true if the channel has been idle (TSOP HIGH) for at least idleUs.
    // Used by IrLink::channelClear() for listen-before-talk.
    bool isIdle(uint32_t idleUs = 2000UL);

    void enableRx();   // arm the edge-change interrupt
    void disableRx();  // detach it (we must not "hear" our own transmission)

private:
    // `private` means only PHY's own functions can touch these. The leading
    // underscore is a common naming convention for member variables.
    uint8_t _txPin;
    uint8_t _rxPin;

    void    _carrierOn();
    void    _carrierOff();
    void    _sendBit(bool one);
    void    _sendByte(uint8_t b);
    uint8_t _manchesterDecode(uint8_t *buf, uint8_t maxLen);
};

#endif // PHY_HPP
