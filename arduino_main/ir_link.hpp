#ifndef IR_LINK_HPP
#define IR_LINK_HPP

#include "link.hpp"     // the interface we must satisfy
#include "config.hpp"   // CFG_LBT_IDLE_US
#include "phy.hpp"      // the existing low-level infrared driver

// ============================================================================
// ir_link.hpp — a thin ADAPTER from ILink to the existing PHY class.
//
// "Adapter" is a common pattern: PHY already knows how to blink LEDs, but its
// function names (isIdle, send, recv) do not exactly match ILink's contract.
// This class translates:
//     ILink::begin()        -> PHY::begin()
//     ILink::send()         -> PHY::send()
//     ILink::recv()         -> PHY::recv()
//     ILink::channelClear() -> PHY::isIdle(2000 us)
//
// Because everything is a one-line pass-through, this whole class lives in the
// header. No .cpp file is needed. `override` tells the compiler "I intend to
// replace an ILink function — please error if the signature is wrong".
//
// This file is finished; if IR behaviour is wrong, fix the PHY layer instead.
// ============================================================================
class IrLink : public ILink {
public:
    // `explicit` stops the compiler from silently creating an IrLink from a
    // bare PHY object. `PHY &phy` stores a REFERENCE to the real driver, so
    // there is no copy and both names refer to the same hardware state.
    explicit IrLink(PHY &phy) : _phy(phy) {}

    void begin() override { _phy.begin(); }
    void send(const uint8_t *b, uint8_t n) override { _phy.send(b, n); }
    uint8_t recv(uint8_t *b, uint8_t m) override { return _phy.recv(b, m); }

    // The channel is clear only if the TSOP receiver has seen no carrier for
    // at least CFG_LBT_IDLE_US microseconds (listen-before-talk).
    bool channelClear() override { return _phy.isIdle(CFG_LBT_IDLE_US); }

    // Time on the medium:
    //   preamble bits + 8 sync bits + 8 bits per data byte, each bit taking
    //   PHY_BIT_US microseconds. Divide by 1000 to get milliseconds.
    // The uint32_t cast prevents overflow if a future frame is large.
    uint32_t airtimeMs(uint8_t bytes) const override {
        return ((uint32_t)(PHY_PREAMBLE_BITS + 8u + 8u * bytes) * PHY_BIT_US) / 1000UL;
    }

    // Latency = the silence PHY requires before declaring a frame finished,
    // plus our estimate for decoding and decrypting it.
    uint32_t latencyMs() const override {
        return (PHY_FRAME_GAP_US / 1000UL) + CFG_IR_PROC_MS;
    }

    const char *name() const override { return "IR"; }

private:
    PHY &_phy;   // reference to the one real PHY object
};

#endif // IR_LINK_HPP
