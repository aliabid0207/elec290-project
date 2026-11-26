#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <ChaChaPoly.h>   // the Arduino library implementing ChaCha20-Poly1305
#include <Arduino.h>      // byte type (an alias for uint8_t)

// ============================================================================
// encryption.hpp — a thin, SAFE wrapper around the crypto library.
//
// A quick vocabulary lesson (these words appear all over the project):
//   * plaintext  = the message you want to send, readable by anyone.
//   * ciphertext = scrambled bytes, meaningless without the key.
//   * key        = 32-byte secret shared by both boards. Never sent over the air.
//   * nonce      = a 12-byte number used ONCE per (key, message). It does not
//                  need to be secret, but it must never repeat with the same key.
//   * AAD        = "Additional Authenticated Data". Bytes that are sent in the
//                  clear (we use the 7-byte packet header) but are covered by
//                  the tag, so an attacker cannot alter them unnoticed.
//   * tag        = a 16-byte cryptographic checksum. If the message or header
//                  is changed in transit, the tag will not verify.
//   * AEAD       = "Authenticated Encryption with Associated Data": encryption
//                  (secrecy) + tag (integrity/authenticity) in one operation.
//
// WHY THIS FILE WAS REWRITTEN (a real security bug, not a style change):
//   The OLD version kept an IV counter inside the cipher object that started at
//   all zeros on every boot and was incremented during encryption.
//     1. Both boards booted at 0 and share ONE key, so their first messages used
//        the same (key, nonce). For ChaCha20-Poly1305 that leaks plaintext XOR
//        and allows tag forgery. Nonce reuse is catastrophic.
//     2. A reboot reset the counter to 0, reusing old nonces.
//     3. Decryption used the RECEIVER's counter, not the sender's nonce, so two
//        different boards could never actually understand each other.
//     4. No AAD, so header fields like type/sequence were not authenticated.
//   The old test only "worked" because it encrypted and decrypted on the SAME
//   object in the same process, with the same counter.
//
// NEW DESIGN: this class knows NOTHING about packets or counters. The caller
// (Communication) builds the nonce from the header and passes it in. The class
// holds the key, set once in init(), and is otherwise stateless per call.
// ============================================================================
class Encryption {
public:
    // Load the shared key into the cipher object. Call once in setup().
    void init();

    // SEAL = encrypt + authenticate.
    //   nonce     : 12 unique bytes for this message
    //   aad/aadLen: header bytes that are authenticated but not encrypted
    //   plain/len : the message to encrypt
    //   cipher    : output buffer for `len` ciphertext bytes
    //   tag/tagLen: output buffer for the authentication tag (16 bytes)
    // Returns false only if the crypto library rejects the nonce length.
    bool seal(const uint8_t nonce[12],
              const uint8_t *aad, size_t aadLen,
              const uint8_t *plain, size_t len,
              uint8_t *cipher, uint8_t *tag, size_t tagLen);

    // OPEN = decrypt + verify the tag.
    // Returns true ONLY if the tag is valid. On failure the plaintext buffer is
    // zeroed, so unauthenticated bytes can never leak to the rest of the code.
    // Rule: NEVER use `plain` when this returns false.
    bool open(const uint8_t nonce[12],
              const uint8_t *aad, size_t aadLen,
              const uint8_t *cipher, size_t len,
              const uint8_t *tag, size_t tagLen,
              uint8_t *plain);

private:
    // The 256-bit (32-byte) pre-shared key. 0xNN notation is one byte in hex.
    // Both boards must be flashed with the identical value. A key stored in
    // source code is acceptable for this course prototype, but in a real
    // product it would need to be provisioned securely and called out as a
    // limitation in the portfolio.
    const byte key[32] = {
        0x23, 0x7e, 0xe1, 0xc3, 0x16, 0xa7, 0xff, 0xa3,
        0x2c, 0x23, 0xd8, 0x8a, 0x1a, 0x2e, 0x49, 0xfb,
        0x0d, 0x44, 0x6d, 0x3c, 0x1f, 0xda, 0x73, 0xd5,
        0xc8, 0xea, 0x7f, 0x3c, 0xdb, 0x2f, 0xf2, 0xc0
    };

    ChaChaPoly _cc;   // the actual library object that does the maths
};

#endif // ENCRYPTION_HPP
