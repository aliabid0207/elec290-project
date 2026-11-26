#ifndef BOARD_CONFIG_HPP
#define BOARD_CONFIG_HPP

#include <Arduino.h>

// ============================================================================
// board_config.hpp — detect which Arduino is being compiled and expose a few
// simple macros the rest of the project can branch on.
//
// WHY? The two boards in the kit are different families:
//   * Arduino Uno WiFi Rev2 -> ATmega4809, 6 KB RAM, built-in WiFiNINA module
//   * Arduino Uno R3        -> ATmega328P, 2 KB RAM, NO Wi-Fi
//
// The compiler automatically defines symbols like __AVR_ATmega4809__ based on
// the board selected in the Arduino IDE. We turn those into our own clearer
// names. This file must be included BEFORE any board-specific library header.
// ============================================================================

#if defined(__AVR_ATmega4809__) || defined(ARDUINO_AVR_UNO_WIFI_REV2)
    #define BOARD_UNO_WIFI_REV2
    #define BOARD_HAS_WIFI 1
    #include <WiFiNINA.h>   // library for the Rev2's NINA Wi-Fi module
    #define BOARD_NAME "UNO WIFI REV2"

#elif defined(__AVR_ATmega328P__) || defined(ARDUINO_AVR_UNO)
    #define BOARD_UNO_R3
    #define BOARD_HAS_WIFI 0
    // No Wi-Fi library: the R3 has no radio. Wi-Fi code is compiled out.
    #define BOARD_NAME "UNO R3"

#else
    #error "Unsupported board. Select Arduino Uno WiFi Rev2 or Arduino Uno R3."
#endif

#endif // BOARD_CONFIG_HPP
