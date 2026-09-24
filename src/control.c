// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/industrial-tamper-system
// File:    control.c
// Desc:    Implements the sealed tamper command path that opens,
//          authorizes, and applies remote mesh commands with a guarded
//          command set and a bounded zone band.
// Created: 2026

#include "control.h"
#include "tamper_auth.h"
#include "envelope.h"
#include "tamper_sys.h"
#include "crypto_aead.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Derived field key used to open sealed command envelopes.
 */
static uint8_t g_control_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been installed.
 */
static bool g_control_key_ready;

/**
 * @brief Anti-replay authorization record for remote commands.
 */
static tamper_auth_t g_control_auth;

/**
 * @brief Command byte recovered from the last accepted remote command.
 */
static uint8_t g_control_command;

/**
 * @brief Zone recovered from the last accepted remote command.
 */
static int16_t g_control_zone;

/**
 * @brief Read one 32-bit little-endian value.
 *
 * @param p Pointer to four little-endian bytes.
 * @return uint32_t Decoded value.
 */
static uint32_t control_get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

/**
 * @brief Read one 16-bit little-endian signed zone.
 *
 * @param p Pointer to two little-endian bytes.
 * @return int16_t Decoded zone identifier.
 */
static int16_t control_get_i16(const uint8_t *p) {
    return (int16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8u));
}

/**
 * @brief Report whether a decoded zone is inside the provisioned band.
 *
 * @param zone Zone identifier to classify.
 * @return bool true when the zone is inside the provisioning band.
 */
static bool control_zone_ok(int16_t zone) {
    return (zone >= TAMPER_ZONE_MIN) && (zone <= TAMPER_ZONE_MAX);
}

/**
 * @brief Report whether a command byte is in the guarded tamper set.
 *
 * @param command Command byte to classify.
 * @return bool true when the command is one of the guarded tamper codes.
 */
static bool control_command_ok(uint8_t command) {
    return (command == TAMPER_COMMAND_ALERT) ||
           (command == TAMPER_COMMAND_ARM) ||
           (command == TAMPER_COMMAND_SECURE);
}

/**
 * @brief Range check a recovered command body and its pointers.
 *
 * @param pt Pointer to the recovered command plaintext.
 * @param len Number of recovered plaintext bytes.
 * @param seq Pointer to store the sequence number.
 * @param tag Pointer to the tag output buffer.
 * @param command Pointer to store the guarded command byte.
 * @param zone Pointer to store the decoded zone.
 * @return bool true when the body is well formed and in the guarded set.
 */
static bool control_args_ok(const uint8_t *pt, size_t len, uint32_t *seq,
                            uint8_t *tag, uint8_t *command, int16_t *zone) {
    (void)pt;
    (void)len;
    return (seq != NULL) && (tag != NULL) && (command != NULL) &&
           (zone != NULL) && (len >= CONTROL_COMMAND_LEN);
}

/**
 * @brief Report whether a decoded command and zone are both in band.
 *
 * @param command Guarded command byte to classify.
 * @param zone Zone identifier to classify.
 * @return bool true when both the command and zone are accepted.
 */
static bool control_body_ok(uint8_t command, int16_t zone) {
    return control_command_ok(command) && control_zone_ok(zone);
}

/**
 * @brief Parse a recovered command body into sequence, tag, command, zone.
 *
 * @param pt Pointer to the recovered command plaintext.
 * @param len Number of recovered plaintext bytes.
 * @param seq Pointer to store the little-endian sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param command Pointer to store the guarded command byte.
 * @param zone Pointer to store the decoded zone.
 * @return bool true when the body is well formed and in the guarded set.
 */
static bool control_parse(const uint8_t *pt, size_t len, uint32_t *seq,
                          uint8_t tag[CRYPTO_AEAD_TAG_LEN], uint8_t *command,
                          int16_t *zone) {
    if (!control_args_ok(pt, len, seq, tag, command, zone)) {
        return false;
    }
    *command = pt[4];
    *zone = control_get_i16(&pt[5]);
    if (!control_body_ok(*command, *zone)) return false;
    *seq = control_get_u32(pt);
    memcpy(tag, pt + 7u, CRYPTO_AEAD_TAG_LEN);
    return true;
}

/**
 * @brief Open one sealed command envelope under the field key.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param pt Pointer to the plaintext output buffer.
 * @param len Pointer to store the recovered plaintext length.
 * @return bool true when the envelope authenticated and opened.
 */
static bool control_open(const char *hex, uint8_t *pt, size_t *len) {
    uint8_t ad = (uint8_t)TAMPER_NODE_ID;
    if (!g_control_key_ready || hex == NULL) {
        return false;
    }
    return envelope_open_hex(g_control_key, &ad, 1u, hex, pt,
                             ENVELOPE_MAX_PLAINTEXT, len);
}

/**
 * @brief Open and parse one sealed tamper command envelope.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param seq Pointer to store the recovered sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param command Pointer to store the guarded command byte.
 * @param zone Pointer to store the decoded zone.
 * @return bool true when the envelope opened and the body parsed.
 */
static bool control_decode(const char *hex, uint32_t *seq,
                           uint8_t tag[CRYPTO_AEAD_TAG_LEN], uint8_t *command,
                           int16_t *zone) {
    uint8_t pt[ENVELOPE_MAX_PLAINTEXT];
    size_t len;
    if (!control_open(hex, pt, &len)) {
        return false;
    }
    return control_parse(pt, len, seq, tag, command, zone);
}

void control_init(void) {
    g_control_key_ready = false;
    g_control_command = TAMPER_COMMAND_SECURE;
    g_control_zone = 0;
    memset(g_control_key, 0, sizeof(g_control_key));
    tamper_auth_init(&g_control_auth);
    tamper_auth_set_key(NULL);
}

void control_deinit(void) {
    g_control_key_ready = false;
    tamper_auth_set_key(NULL);
}

bool control_set_key(const uint8_t key[CRYPTO_AEAD_KEY_LEN]) {
    if (key == NULL) {
        control_deinit();
        return false;
    }
    memcpy(g_control_key, key, CRYPTO_AEAD_KEY_LEN);
    g_control_key_ready = true;
    tamper_auth_set_key(g_control_key);
    return true;
}

bool control_authorize(uint32_t seq, const uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    return tamper_auth_apply(&g_control_auth, seq, tag);
}

/**
 * @brief Decode and authorize one sealed tamper command envelope.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param seq Pointer to store the recovered sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @param command Pointer to store the guarded command byte.
 * @param zone Pointer to store the decoded zone.
 * @return bool true when the command opened and passed the window.
 */
static bool control_authorized_decode(const char *hex, uint32_t *seq,
                                      uint8_t tag[CRYPTO_AEAD_TAG_LEN],
                                      uint8_t *command, int16_t *zone) {
    return control_decode(hex, seq, tag, command, zone) &&
           control_authorize(*seq, tag);
}

/**
 * @brief Store the accepted command and zone in the module state.
 *
 * @param command Guarded command byte to store.
 * @param zone Zone identifier to store.
 * @return void
 */
static void control_store(uint8_t command, int16_t zone) {
    g_control_command = command;
    g_control_zone = zone;
}

bool control_handle_frame(const char *hex) {
    uint32_t seq;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    uint8_t command;
    int16_t zone;
    if (!control_authorized_decode(hex, &seq, tag, &command, &zone)) {
        return false;
    }
    control_store(command, zone);
    return true;
}

uint8_t control_command(void) {
    return g_control_command;
}

int16_t control_zone(void) {
    return g_control_zone;
}
