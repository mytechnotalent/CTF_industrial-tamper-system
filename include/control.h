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
// File:    control.h
// Desc:    Declares the sealed tamper command path that opens,
//          authorizes, and applies remote mesh tamper alerts and arm
//          commands with a guarded command set and a bounded zone band.
// Created: 2026

#ifndef CONTROL_H
#define CONTROL_H

#include "crypto_aead.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Tamper command code that reports an intrusion alert.
 */
#define TAMPER_COMMAND_ALERT 0x01u

/**
 * @brief Tamper command code that arms the node.
 */
#define TAMPER_COMMAND_ARM 0x02u

/**
 * @brief Tamper command code that returns the node to secure service.
 */
#define TAMPER_COMMAND_SECURE 0x03u

/**
 * @brief Length in bytes of a sealed tamper command body.
 *
 * The body is a little-endian 32-bit sequence, the guarded tamper
 * command byte, a little-endian 16-bit zone, and a 16-byte authenticated
 * tag over the resulting authorization record.
 */
#define CONTROL_COMMAND_LEN (4u + 1u + 2u + CRYPTO_AEAD_TAG_LEN)

/**
 * @brief Initialize the sealed tamper command path.
 *
 * @param void No parameters.
 * @return void
 */
void control_init(void);

/**
 * @brief Clear the field key and reset the command path.
 *
 * @param void No parameters.
 * @return void
 */
void control_deinit(void);

/**
 * @brief Install the field key used to open and authorize commands.
 *
 * @param key Pointer to a 32-byte field key, or NULL to clear the key.
 * @return bool true when a key was installed.
 */
bool control_set_key(const uint8_t key[CRYPTO_AEAD_KEY_LEN]);

/**
 * @brief Authorize a command sequence and tag against the anti-replay window.
 *
 * @param seq Sequence number carried by the command.
 * @param tag Pointer to the 16-byte command tag to verify.
 * @return bool true when the command was accepted.
 */
bool control_authorize(uint32_t seq, const uint8_t tag[CRYPTO_AEAD_TAG_LEN]);

/**
 * @brief Open, authorize, and apply one sealed remote tamper command.
 *
 * Rejects a malformed envelope, a forged tag, a replayed sequence, any
 * command byte outside the guarded tamper set, and any zone outside the
 * provisioned band.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @return bool true when the command authenticated and was applied.
 */
bool control_handle_frame(const char *hex);

/**
 * @brief Return the command byte recovered from the last accepted command.
 *
 * @param void No parameters.
 * @return uint8_t Guarded tamper command code.
 */
uint8_t control_command(void);

/**
 * @brief Return the zone recovered from the last accepted command.
 *
 * @param void No parameters.
 * @return int16_t Zone identifier carried by the command.
 */
int16_t control_zone(void);

#endif // CONTROL_H
