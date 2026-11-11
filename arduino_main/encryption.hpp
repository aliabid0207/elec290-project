#ifndef ENCRYPTION_HPP

#define ENCRYPTION_HPP

#include <ChaChaPoly.h>
#include <Arduino.h>

class Encryption
{
  private:
  // 256-bit key (32 bytes)
  const byte key[32] = { // 23 7e e1 c3 16 a7 ff a3 2c 23 d8 8a 1a 2e 49 fb 0d 44 6d 3c 1f da 73 d5 c8 ea 7f 3c db 2f f2 c0
    0x23, 0x7e, 0xe1, 0xc3, 0x16, 0xa7, 0xff, 0xa3,
    0x2c, 0x23, 0xd8, 0x8a, 0x1a, 0x2e, 0x49, 0xfb,
    0x0d, 0x44, 0x6d, 0x3c, 0x1f, 0xda, 0x73, 0xd5,
    0xc8, 0xea, 0x7f, 0x3c, 0xdb, 0x2f, 0xf2, 0xc0
  };

  // Instance of the ChaChaPoly cipher
  ChaChaPoly chachapoly;

  void increment_iv();

  public:
  // 96-bit Initialization Vector / Nonce (12 bytes) - Must be unique for EVERY message!
  static byte iv[12];
  void init();
  void encrypt(const char *message, size_t len_msg, byte *ciphertext);
  void compute_auth_tag(byte *auth_tag, size_t len_tag);
  void decrypt(byte *decrypted, byte *ciphertext, size_t len_msg);
  bool check_tag(byte *auth_tag, size_t len_tag);
};

#endif