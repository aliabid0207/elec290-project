#include "protocol.hpp"
#include <string.h>   // memset()

// This file is complete. It only needs changing if protocol.hpp changes.
// It contains no hardware access at all: just byte manipulation.

// ---------------------------------------------------------------------------
// packHeader: turn the Header struct into 7 bytes in "big-endian" order.
//
// WHY SHIFTING? A uint16_t holds 16 bits. To send the HIGH (most significant)
// 8 bits first, we shift them right by 8 positions and keep the low 8 bits as
// they are:
//
//     epoch = 0x1234  (binary 0001 0010 0011 0100)
//     epoch >> 8      = 0x12   -> out[2]
//     epoch & 0xFF    = 0x34   -> out[3]
//
// `& 0xFF` is a bitmask that keeps only the lowest 8 bits. The cast to uint8_t
// tells the compiler we really do want to store just one byte.
// ---------------------------------------------------------------------------
void packHeader(const Header &h, uint8_t out[PROTO_HDR_LEN]) {
    out[0] = h.type;
    out[1] = h.src;
    out[2] = (uint8_t)(h.epoch >> 8);   // high byte of epoch
    out[3] = (uint8_t)(h.epoch & 0xFF); // low byte of epoch
    out[4] = (uint8_t)(h.ctr >> 8);     // high byte of counter
    out[5] = (uint8_t)(h.ctr & 0xFF);   // low byte of counter
    out[6] = h.len;
}

// ---------------------------------------------------------------------------
// unpackHeader: the reverse operation, PLUS sanity checks.
//
// This is called on data that came from the air, so we must be suspicious of
// it. We reject anything that cannot possibly be a valid packet BEFORE trying
// to decrypt, which avoids reading past the end of the buffer.
//
// Note what we do NOT check here: the tag, the source ID, or replay. Those need
// the crypto object or remembered state, so Communication handles them.
// ---------------------------------------------------------------------------
bool unpackHeader(const uint8_t *in, size_t inLen, Header &h) {
    // Smallest possible packet = 7-byte header + 16-byte tag (an ACK).
    if (inLen < (size_t)PROTO_HDR_LEN + PROTO_TAG_LEN) return false;

    h.type  = in[0];
    h.src   = in[1];
    // Rebuild a 16-bit value: shift the high byte left 8 places, then OR in
    // the low byte. `|` combines bits (0x1200 | 0x34 = 0x1234).
    h.epoch = (uint16_t)((in[2] << 8) | in[3]);
    h.ctr   = (uint16_t)((in[4] << 8) | in[5]);
    h.len   = in[6];

    // Is the type one of the two we understand?
    if (h.type != PKT_DATA && h.type != PKT_ACK) return false;
    // Does the claimed payload length fit our buffer?
    if (h.len > PROTO_MAX_PAYLOAD)               return false;
    // An ACK carries no payload by definition.
    if (h.type == PKT_ACK && h.len != 0)         return false;
    // Is the frame long enough to actually contain header + ciphertext + tag?
    if (inLen < (size_t)PROTO_HDR_LEN + h.len + PROTO_TAG_LEN) return false;

    return true;
}

// ---------------------------------------------------------------------------
// buildNonce: create the 12 bytes used exactly ONCE with this key.
//
// Both ends call this with the same header, so both derive the same nonce and
// ChaCha20-Poly1305 can encrypt/decrypt correctly. Including src, type, epoch
// and ctr makes the nonce unique across devices, across message types, across
// reboots and across messages.
//
// memset() zeroes all 12 bytes first; bytes 6..11 stay zero as a fixed suffix.
// ---------------------------------------------------------------------------
void buildNonce(const Header &h, uint8_t nonce[PROTO_NONCE_LEN]) {
    memset(nonce, 0, PROTO_NONCE_LEN);
    nonce[0] = h.src;
    nonce[1] = h.type;
    nonce[2] = (uint8_t)(h.epoch >> 8);
    nonce[3] = (uint8_t)(h.epoch & 0xFF);
    nonce[4] = (uint8_t)(h.ctr >> 8);
    nonce[5] = (uint8_t)(h.ctr & 0xFF);
}
