#ifndef COMMUNICATION_HPP
#define COMMUNICATION_HPP

// The two lines above are a "header guard". If this file gets included twice
// (directly and through another header), the compiler skips the second copy.
// Without it, class definitions would be duplicated and compilation would fail.

#include <Arduino.h>          // millis(), millis() is the Arduino millisecond clock
#include "link.hpp"           // ILink: the abstract "send/receive bytes" interface
#include "encryption.hpp"     // Encryption: seal() / open() wrappers around ChaChaPoly
#include "protocol.hpp"       // Header, packet sizes, pack/unpack/nonce helpers
#include "config.hpp"         // SELF_ID, PEER_ID, retry/timeout settings

// ============================================================================
// communication.hpp — the PROTOCOL ENGINE from portfolio sections 3.1.4/3.2.2.
//
// Think of this class as the "traffic controller" of the device. It does NOT
// know how to blink an IR LED or connect to Wi-Fi; it only knows the rules of
// the conversation:
//
//   1. Build a packet (header + encrypted payload + authentication tag).
//   2. Ask whichever ILink is active to send it.
//   3. Wait a calculated amount of time for an ACK.
//   4. If no ACK arrives, retry up to CFG_MAX_RETRIES times with a random pause.
//   5. On receive, check the packet is well-formed, from the right device,
//      not a replay, and has a valid tag before handing the text to the host.
//
// WHY "NON-BLOCKING"? A blocking function would freeze loop() while waiting
// for an ACK, so the device could not notice an incoming message. Instead we
// keep a small state variable and call tick() repeatedly. Each call does a
// tiny piece of work and returns immediately. The only intentionally blocking
// call is ILink::send(), which returns once the frame is on the medium.
// ============================================================================

// An enum is a set of named integer values. Adding ": uint8_t" tells the
// compiler to store each value in ONE byte instead of the default int (4 bytes
// on this board). On a microcontroller, saving RAM matters.
enum CommEvent : uint8_t {
    COMM_TX_START = 1,   // a frame was just sent; code = attempt number (0 = first)
    COMM_TX_OK,          // a valid ACK arrived; code = number of attempts - 1
    COMM_TX_FAIL,        // all attempts failed; code = last attempt number
    COMM_RX_OK,          // a valid message arrived; code = plaintext length
    COMM_RX_REJECT,      // a frame was dropped; code = one of the CommReject values
    COMM_WIFI_UP,        // the Wi-Fi fallback was connected
    COMM_WIFI_DOWN,      // the Wi-Fi fallback was disconnected
};

// Reasons a received frame can be rejected WITHOUT being delivered.
enum CommReject : uint8_t {
    REJECT_MALFORMED = 1, // too short, bad type, or length field inconsistent
    REJECT_WRONG_SRC,     // claimed to come from a device we don't trust
    REJECT_REPLAY,        // counter did not increase (old message repeated)
    REJECT_BAD_TAG,       // authentication tag failed: corrupted or forged
};

class Communication {
public:
    // -----------------------------------------------------------------------
    // "Callback" types. A callback is just a function pointer: we store the
    // ADDRESS of a function that main sketch wrote, and call it later when
    // something interesting happens. This keeps Communication independent of
    // Serial printing and LED code.
    //
    // `using NewName = Type;` is a modern C++ way to say "NewName means Type".
    // Here the type is a pointer to a function that returns void and takes
    // (payload pointer, length, source ID, epoch, counter).
    // -----------------------------------------------------------------------
    using MessageHandler = void (*)(const uint8_t *payload, uint8_t len,
                                    uint8_t src, uint16_t epoch, uint16_t ctr);
    using EventHandler   = void (*)(CommEvent event, uint16_t code);

    // Passing objects by reference (&) means "use the original object, don't
    // make a copy". We MUST use the original crypto and link objects because
    // they hold hardware state.
    Communication(Encryption &crypto, ILink &link);

    // Call once from setup(). Registers the two callbacks and loads/increments
    // the boot epoch from EEPROM.
    void begin(MessageHandler onMessage, EventHandler onEvent);

    // -----------------------------------------------------------------------
    // Switch the active link. We store a POINTER (_link) rather than a
    // reference so it can be changed at runtime with "WIFI ON"/"WIFI OFF".
    // Only do this while !busy(), otherwise a message could be half sent on
    // one medium and half on another.
    // -----------------------------------------------------------------------
    void setLink(ILink *link) { if (link) _link = link; }
    ILink *link() const { return _link; }

    // Queue a message. It will actually be transmitted on a later tick().
    // Returns false if we are already busy or the text is too long.
    // Important: retries re-send the SAME encrypted bytes, never re-encrypt.
    bool send(const uint8_t *payload, uint8_t len);
    bool sendText(const char *text);  // convenience wrapper for text strings

    // Call this once per loop() iteration. See the state machine in .cpp.
    void tick();

    // Simple read-only status helpers for the STATUS command and LEDs.
    bool busy() const { return _txState != TX_IDLE; }
    uint16_t epoch() const { return _epoch; }
    uint16_t counter() const { return _ctr; }

private:
    // The transmit state machine has exactly four states:
    //   IDLE       -> nothing to do
    //   PENDING    -> packet ready, waiting for a clear medium
    //   BACKOFF    -> waiting out a random delay (busy medium or failed try)
    //   WAIT_ACK   -> frame sent, waiting for the peer's acknowledgement
    enum TxState : uint8_t {
        TX_IDLE,
        TX_PENDING,
        TX_BACKOFF,
        TX_WAIT_ACK,
    };

    // Private helper functions. Splitting the work into small named pieces is
    // easier to follow than one giant function.
    void _pollRx();                       // check for and process a received frame
    void _sendFrame();                    // hand the ready packet to the link
    void _queueAck(const Header &acked);  // build an ACK for a received DATA packet
    void _loadEpoch();                    // read/increment the boot counter in EEPROM
    void _saveEpoch(uint16_t epoch);      // write it back
    uint32_t _randomBackoff() const;      // random delay in milliseconds
    void _fail();                         // give up and report failure
    void _event(CommEvent event, uint16_t code) const
        { if (_onEvent) _onEvent(event, code); }  // call callback only if registered

    Encryption &_crypto;      // the shared cipher wrapper (not owned by us)
    ILink *_link;             // the currently selected medium (IR or Wi-Fi)
    MessageHandler _onMessage; // called when a valid message arrives
    EventHandler _onEvent;     // called for TX/RX/Wi-Fi status changes

    // ---- Counters that guarantee nonce uniqueness ----
    uint16_t _epoch;          // boot number, survives power cycles via EEPROM
    uint16_t _ctr;            // messages sent this boot, starts at 1
    uint16_t _lastRxEpoch;    // highest peer epoch we accepted
    uint16_t _lastRxCtr;      // highest peer counter accepted within that epoch
    bool _haveRx;             // false until we have accepted our first peer packet

    // ---- Transmit state ----
    TxState  _txState;
    uint8_t  _attempt;        // 0 = first send, 1..3 = retries
    uint8_t  _busyCount;      // how many times the medium looked busy
    uint8_t  _txPacket[PROTO_MAX_PACKET]; // complete packet: header+cipher+tag
    uint8_t  _txLen;          // how many bytes of _txPacket are meaningful
    uint16_t _txEpoch;        // epoch of the packet currently being sent
    uint16_t _txCtr;          // counter of the packet currently being sent
    uint32_t _deadline;       // millis() value when the current wait expires

    // ---- Receive/ACK state ----
    // Scratch for one raw frame. KEEP SMALL: every byte here is SRAM on the R3.
    // A full packet is 47 bytes; the extra 8 bytes absorb decoder stray bits.
    // The parser still trusts the header's `len`, not the byte count returned
    // by the link.
    uint8_t  _rxBuf[PROTO_MAX_PACKET + 8];
    uint8_t  _ackPacket[PROTO_ACK_PACKET]; // ready-to-send ACK (23 bytes)
    bool     _ackPending;     // true when an ACK still needs to be transmitted
    uint32_t _ackDeadline;    // don't hold an ACK forever if medium stays busy

    // Which DATA packet the cached ACK belongs to. If the sender's ACK was lost
    // and it retransmits the SAME data, we must send the SAME ACK again instead
    // of silently dropping the retry as a replay (otherwise it would report
    // TX FAIL even though we already received the message once).
    bool     _haveAck;        // false until we have built the first ACK
    uint16_t _ackEpoch;
    uint16_t _ackCtr;
};

#endif // COMMUNICATION_HPP
