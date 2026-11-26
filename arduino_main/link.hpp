#ifndef LINK_HPP
#define LINK_HPP

#include <Arduino.h>

// ============================================================================
// link.hpp — the "common send and receive interface" from portfolio 3.3.1.
//
// Communication (the protocol engine) talks ONLY to this interface. It never
// includes phy.hpp or WiFiNINA.h. That one rule is what lets the SAME packets,
// ACKs, retries and encryption run over infrared OR Wi-Fi without changing any
// protocol code.
//
// HOW TO READ THIS CLASS:
//   ILink is an "abstract base class" — a contract, not a working link. You
//   cannot create an `ILink` object directly. Instead, IrLink and WifiLink say
//   `public ILink` and fill in the details.
//
//   `virtual` means "a derived class may replace this function".
//   `= 0` means "there is NO default; every derived class MUST provide it".
//   A `= 0` member makes the class abstract.
//   Functions WITHOUT `= 0` have a sensible default that a derived class can
//   override if needed.
//
//   `virtual ~ILink() {}` is a virtual destructor. It is a C++ courtesy that
//   makes deleting through an ILink* safe, even though we never delete these
//   particular objects (they live for the whole program).
//
// RULE: do not add IR- or Wi-Fi-specific methods here. If Communication needs a
// new capability, add a virtual function with a safe default so the OTHER link
// keeps compiling unchanged.
// ============================================================================
class ILink {
public:
    virtual ~ILink() {}

    // One-time hardware setup. Called from setup(). Must be implemented.
    virtual void begin() = 0;

    // BLOCKING: put buf[0..len) on the medium and return when finished.
    // `const uint8_t *` means "we promise not to modify the bytes we send".
    virtual void send(const uint8_t *buf, uint8_t len) = 0;

    // NON-BLOCKING: return the number of bytes of ONE complete received frame.
    // 0 means "nothing yet". IMPORTANT: this count may be LARGER than what the
    // sender actually sent (the IR decoder can append stray bits), so it is
    // NOT a packet length. protocol.cpp trusts only the header's `len` field.
    virtual uint8_t recv(uint8_t *buf, uint8_t maxLen) = 0;

    // Listen-before-talk. true = safe to transmit. IR implements a real check;
    // Wi-Fi uses this default because the radio manages medium access for us.
    virtual bool channelClear() { return true; }

    // How long (ms) a frame of `bytes` bytes occupies the medium. Used to
    // calculate the ACK timeout. Includes preamble/overhead where relevant.
    virtual uint32_t airtimeMs(uint8_t bytes) const = 0;

    // Receiver-side delay (ms) between the sender finishing the last bit and
    // us having a decoded, verified packet in hand.
    virtual uint32_t latencyMs() const = 0;

    // Links that can be switched off (Wi-Fi) override these. IR is always on,
    // so the defaults ("active", "ignore the request") are correct for it.
    virtual bool isActive() const { return true; }
    virtual void setActive(bool) {}

    // Short name used by the STATUS command ("IR" or "WIFI").
    virtual const char *name() const = 0;
};

#endif // LINK_HPP
