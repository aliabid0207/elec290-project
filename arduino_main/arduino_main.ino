#include "encrypt.hpp"
#include <Crypto.h>
#include <string.h>

void setup() {
  Serial.begin(115200);
  while (!Serial); // Wait for serial monitor to connect
  delay(1000);

  // Define our plaintext message
  const char *plaintext = "Hello, secure Arduino world!";
  size_t len = strlen(plaintext);

  // Allocate buffers for ciphertext, authentication tag, and decrypted text
  byte ciphertext[len];
  byte authTag[16]; // ChaChaPoly uses a 128-bit (16-byte) authentication tag
  char decrypted[len + 1]; // +1 for null-terminator

  Serial.print("Original Message: ");
  Serial.println(plaintext);

  // -----------------------------------------------------------------
  // 1. ENCRYPTION STAGE
  // -----------------------------------------------------------------
  chachapoly.clear();
  chachapoly.setKey(key, sizeof(key));
  chachapoly.setIV(iv, sizeof(iv));
  
  // (Optional) Add associated authenticated data (AAD) if needed using chachapoly.addAuthData()
  
  // Perform the encryption
  chachapoly.encrypt(ciphertext, (const byte *)plaintext, len);
  
  // Generate the authentication tag
  chachapoly.computeTag(authTag, sizeof(authTag));

  // Print Ciphertext in Hex format
  Serial.print("Ciphertext (HEX): ");
  for (size_t i = 0; i < len; i++) {
    if (ciphertext[i] < 0x10) Serial.print("0");
    Serial.print(ciphertext[i], HEX);
    Serial.print(" ");
  }
  Serial.println();

  // Print Authentication Tag
  Serial.print("Auth Tag (HEX):   ");
  for (size_t i = 0; i < sizeof(authTag); i++) {
    if (authTag[i] < 0x10) Serial.print("0");
    Serial.print(authTag[i], HEX);
    Serial.print(" ");
  }
  Serial.println("\n");

  // -----------------------------------------------------------------
  // 2. DECRYPTION & VERIFICATION STAGE
  // -----------------------------------------------------------------
  chachapoly.clear();
  chachapoly.setKey(key, sizeof(key));
  chachapoly.setIV(iv, sizeof(iv));

  // Perform the decryption
  chachapoly.decrypt((byte *)decrypted, ciphertext, len);
  decrypted[len] = '\0'; // Properly terminate the string

  // Check if the validation tag matches (confirms integrity and authenticity)
  if (chachapoly.checkTag(authTag, sizeof(authTag))) {
    Serial.println("✓ Success! Authentication tag is valid.");
    Serial.print("Decrypted Message: ");
    Serial.println(decrypted);
  } else {
    Serial.println("✗ Error! Authentication failed. The data or tag was tampered with.");
  }
}

void loop() {
  // Put your main code here, to run repeatedly:
}