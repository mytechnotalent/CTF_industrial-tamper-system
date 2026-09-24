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
// File:    tamper_auth.h
// Desc:    Declares the tamper command authorization record, anti-replay
//          window, and authenticated state tag for sealed mesh commands.
// Created: 2026

#ifndef TAMPER_AUTH_H
#define TAMPER_AUTH_H

#include "crypto_aead.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Serialized tamper authorization record length in bytes.
 *
 * The record is one grant flag, the accepted sequence, and the
 * anti-replay floor, each sequence in little-endian order.
 */
#define TAMPER_AUTH_RECORD_LEN 9u

/**
 * @brief Domain separator byte mixed into every state-tag nonce.
 */
#define TAMPER_AUTH_NONCE_DOMAIN 0xA7u

/**
 * @brief Tamper command authorization record with an integrity tag.
 *
 * The tag is an XChaCha20-Poly1305 tag over the serialized record under
 * the field key. Because the tag covers the accepted sequence and the
 * anti-replay floor, a debugger that rewrites the record without
 * recomputing the tag is detected before the latch moves.
 */
typedef struct tamper_auth {
    /**
     * @brief True when a valid sealed command has been accepted.
     */
    bool granted;
    /**
     * @brief Sequence number of the most recently accepted command.
     */
    uint32_t seq;
    /**
     * @brief Highest sequence number ever accepted (anti-replay window).
     */
    uint32_t last_seq;
    /**
     * @brief Authenticated tag over the serialized authorization record.
     */
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
} tamper_auth_t;

/**
 * @brief Zero a tamper authorization record.
 *
 * @param auth Pointer to the authorization record to clear.
 * @return void
 */
void tamper_auth_init(tamper_auth_t *auth);

/**
 * @brief Install the field key used to compute and verify state tags.
 *
 * @param key Pointer to a 32-byte field key, or NULL to clear the key.
 * @return void
 */
void tamper_auth_set_key(const uint8_t key[CRYPTO_AEAD_KEY_LEN]);

/**
 * @brief Compute the authenticated tag over an authorization record.
 *
 * @param auth Pointer to the authorization record.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @return bool true when the tag was computed.
 */
bool tamper_auth_state_tag(const tamper_auth_t *auth,
                           uint8_t tag[CRYPTO_AEAD_TAG_LEN]);

/**
 * @brief Verify the authenticated tag stored in an authorization record.
 *
 * @param auth Pointer to the authorization record.
 * @return bool true when the stored tag matches the record contents.
 */
bool tamper_auth_state_ok(const tamper_auth_t *auth);

/**
 * @brief Apply a sealed tamper command under the anti-replay window.
 *
 * Accepts only when the sequence is strictly greater than the last
 * accepted sequence and the supplied tag matches the tag over the
 * resulting authorization record. On success the record is updated and
 * the sequence becomes the new anti-replay floor.
 *
 * @param auth Pointer to the authorization record.
 * @param seq Sequence number carried by the command.
 * @param tag Pointer to the 16-byte command tag to verify.
 * @return bool true when the command was accepted.
 */
bool tamper_auth_apply(tamper_auth_t *auth, uint32_t seq,
                       const uint8_t tag[CRYPTO_AEAD_TAG_LEN]);

#endif // TAMPER_AUTH_H
