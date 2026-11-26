#include "encryption.hpp"
#include <string.h>   // memset(), used to wipe the plaintext buffer on failure

// Load the key once. clear() resets any previous state inside the cipher.
// sizeof(key) is 32; setKey() expects the byte count, not the array length.
void Encryption::init() {
    _cc.clear();
    _cc.setKey(key, sizeof(key));
}

// ---------------------------------------------------------------------------
// SEAL: turn plaintext into ciphertext + tag.
//
// The ORDER of these calls is mandatory with this particular library:
//   1. setIV(nonce)       -- installs the nonce AND resets internal state
//   2. addAuthData(aad)   -- feeds the header into the tag calculation
//   3. encrypt()          -- produces ciphertext
//   4. computeTag()       -- finishes the authentication tag
// Calling setIV between encrypt() and computeTag() would erase the state the
// tag depends on, producing a tag the receiver can never verify.
// ---------------------------------------------------------------------------
bool Encryption::seal(const uint8_t nonce[12],
                      const uint8_t *aad, size_t aadLen,
                      const uint8_t *plain, size_t len,
                      uint8_t *cipher, uint8_t *tag, size_t tagLen) {
    if (!_cc.setIV(nonce, 12)) return false;   // reject a bad nonce length
    if (aadLen) _cc.addAuthData(aad, aadLen);  // skip call if there is no AAD

    // If len is 0 (an ACK), encrypt() is called with a zero count and writes
    // nothing. The SELFTEST command in the main sketch checks this case.
    _cc.encrypt(cipher, plain, len);
    _cc.computeTag(tag, tagLen);
    return true;
}

// ---------------------------------------------------------------------------
// OPEN: decrypt and verify.
//
// Encryption is reversible, so decrypt() can always produce bytes. The tag is
// what tells us whether those bytes are trustworthy. We therefore decrypt
// first (the library requires that order), then check the tag. If the check
// fails we overwrite the output with zeros before returning false, so no
// attacker-controlled data can slip into the application.
// ---------------------------------------------------------------------------
bool Encryption::open(const uint8_t nonce[12],
                      const uint8_t *aad, size_t aadLen,
                      const uint8_t *cipher, size_t len,
                      const uint8_t *tag, size_t tagLen,
                      uint8_t *plain) {
    if (!_cc.setIV(nonce, 12)) return false;
    if (aadLen) _cc.addAuthData(aad, aadLen);
    _cc.decrypt(plain, cipher, len);          // plaintext BEFORE the tag is known
    bool ok = _cc.checkTag(tag, tagLen);      // constant-time compare in library
    if (!ok && len) memset(plain, 0, len);    // wipe unauthenticated bytes
    return ok;
}
