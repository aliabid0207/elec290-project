#include "encryption.hpp"

byte Encryption::iv[12] = { 0 };

void Encryption::init()
{
    chachapoly.clear();
    chachapoly.setKey(key, sizeof(key));
    chachapoly.setIV(iv, sizeof(iv));
}

void Encryption::increment_iv()
{
    for(int i = 11; i >= 0; --i)
        if(++iv[i] != 0)
            break;
    chachapoly.setIV(iv, sizeof(iv));
}

void Encryption::encrypt(const char *message, size_t len_msg, byte *ciphertext)
{
    increment_iv(); // fresh nonce first: setIV() resets the cipher, so it must not run between encrypt and computeTag
    chachapoly.encrypt(ciphertext, (const byte*) message, len_msg);
}

void Encryption::compute_auth_tag(byte *auth_tag, size_t len_tag)
{
    chachapoly.computeTag(auth_tag, len_tag);
}

void Encryption::decrypt(byte *decrypted, byte *ciphertext, size_t len_msg)
{
    chachapoly.decrypt(decrypted, ciphertext, len_msg);
}

bool Encryption::check_tag(byte *auth_tag, size_t len_tag)
{
    return chachapoly.checkTag(auth_tag, len_tag);
}