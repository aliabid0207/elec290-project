#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <Arduino.h>   // uint8_t / uint16_t / size_t types

// ============================================================================
// protocol.hpp — THE PACKET FORMAT. Pure data and pure functions, no hardware.
//
// This file is the CONTRACT between the two devices. If you change the layout,
// you must reflash BOTH boards, otherwise they will disagree about where the
// ciphertext starts and every packet will be rejected.
// (Note: the portfolio's Table 7 says "59 bytes"; with this final layout a full
// packet is 47 bytes with the 24-byte payload chosen to fit the Uno R3's RAM.)
//
// WIRE LAYOUT (everything bigger than one byte is BIG-ENDIAN: most significant
// byte first, the usual "network byte order"):
//
//   byte 0   type    0x01 = DATA, 0x02 = ACK
//   byte 1   src     sender's device ID (SELF_ID of the sender)
//   byte 2-3 epoch   sender's boot counter (persisted in EEPROM, +1 each boot)
//   byte 4-5 ctr     per-boot message counter, starts at 1
//   byte 6   len     ciphertext length (0..24); ALWAYS 0 for ACK
//   byte 7..         ciphertext[len]
//   then             tag[16] (the Poly1305 authentication tag)
//
//   |<------- header (7 B) ------->|<-- len -->|<-- 16 B -->|
//   | type | src | epoch | ctr | len | ciphertext |   tag    |
//
// The WHOLE 7-byte header is passed to ChaCha20-Poly1305 as AAD. That means it
// is transmitted unencrypted (the receiver needs epoch/ctr to rebuild the
// nonce) but it IS protected by the tag: an attacker cannot alter type, source
// or counters without the tag check failing.
//
// ACK PACKETS
//   An ACK has len = 0, so it is only header + tag = 23 bytes. It ECHOES the
//   epoch and ctr of the DATA packet it acknowledges, and carries the ACKer's
//   own ID in `src`. The sender matches (epoch, ctr), then verifies the tag.
//
// NONCE (12 bytes) — THE MOST IMPORTANT RULE IN THE PROJECT
//   nonce = { src, type, epoch_hi, epoch_lo, ctr_hi, ctr_lo, 0,0,0,0,0,0 }
//
//   Why is this unique?
//     * src differs between devices -> A and B never share a nonce even though
//       they share one key.
//     * type differs               -> a DATA and its ACK never share a nonce.
//     * epoch is persisted and grows every boot -> rebooting never restarts the
//       counter at a value already used under the same key.
//     * ctr grows per message      -> no repeats within one boot.
//   A RETRANSMISSION re-sends the SAME encrypted bytes (it never re-encrypts),
//   so a retry is same nonce + same plaintext = same output = no leakage.
//   An ACK's nonce comes from the DATA it acknowledges, so ACKs need no counter
//   state of their own, and re-ACKing a duplicate is byte-identical.
// ============================================================================

// constexpr constant: like a #define, but typed and checked by the compiler.
constexpr uint8_t PROTO_HDR_LEN     = 7;
constexpr uint8_t PROTO_TAG_LEN     = 16;   // full Poly1305 tag (8 is a tuning option)
constexpr uint8_t PROTO_MAX_PAYLOAD = 24;   // longest text we can send in one packet
constexpr uint8_t PROTO_NONCE_LEN   = 12;
constexpr uint8_t PROTO_MAX_PACKET  = PROTO_HDR_LEN + PROTO_MAX_PAYLOAD + PROTO_TAG_LEN; // 47
constexpr uint8_t PROTO_ACK_PACKET  = PROTO_HDR_LEN + PROTO_TAG_LEN;                     // 23

// enum PacketType gives readable names to the two possible type byte values.
enum PacketType : uint8_t { PKT_DATA = 0x01, PKT_ACK = 0x02 };

// struct = a small bundle of related values kept together in memory.
// This is the in-memory VERSION of the 7-byte header; packHeader() converts it
// to the byte-by-byte wire format, and unpackHeader() does the reverse.
struct Header {
    uint8_t  type;
    uint8_t  src;
    uint16_t epoch;   // 2 bytes on the wire
    uint16_t ctr;     // 2 bytes on the wire
    uint8_t  len;
};

// Serialise h into out[0..7). `out[PROTO_HDR_LEN]` is a hint to readers that
// the array must have at least 7 elements.
void packHeader(const Header &h, uint8_t out[PROTO_HDR_LEN]);

// Parse + STRUCTURALLY validate a received frame. Returns false if:
//   frame too short, unknown type, len > 24, ACK with len != 0,
//   or inLen < 7 + len + 16.
// It does NOT check the tag, the sender ID or replay — Communication does that.
// Extra trailing bytes after the packet are ignored (the PHY may append some).
bool unpackHeader(const uint8_t *in, size_t inLen, Header &h);

// Fill nonce[0..12) from the header using the layout above.
void buildNonce(const Header &h, uint8_t nonce[PROTO_NONCE_LEN]);

#endif // PROTOCOL_HPP
