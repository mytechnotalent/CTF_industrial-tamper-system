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
// File:    monitor.h
// Desc:    Declares the tamper node state machine tying the local
//          arm/disarm remote, the sealed tamper command path, the cabinet
//          temperature sensor, and the mesh gateway link together.
// Created: 2026

#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Onboard GP25 heartbeat pulse width in microseconds.
 */
#define MONITOR_HEARTBEAT_US 1000u

/**
 * @brief Infrared remote code that requests the node be armed.
 */
#define MONITOR_IR_ARM 0x47u

/**
 * @brief Infrared remote code that requests the node be disarmed.
 */
#define MONITOR_IR_DISARM 0x45u

/**
 * @brief Infrared remote code that clears a pending arm request.
 */
#define MONITOR_IR_CLEAR 0x46u

/**
 * @brief Initialize the tamper node state machine.
 *
 * Configures the I2C LCD, the DHT11 cabinet temperature sensor, the
 * infrared remote, the annunciator LEDs, the latch servo, the arm/disarm
 * button, the RYLR998 radio, and derives the Argon2id field key.
 *
 * @param void No parameters.
 * @return bool true when all submodules initialized.
 */
bool monitor_init(void);

/**
 * @brief Clear the node-ready flag and command path.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_deinit(void);

/**
 * @brief Clear a pending local arm/disarm request.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_clear_request(void);

/**
 * @brief Execute one tamper node tick.
 *
 * Polls the arm remote and the radio, verifies and applies sealed tamper
 * and arm commands, drives the latch and LEDs, renders the tamper status,
 * and fails safe on a lost gateway link. Untrusted frames are never
 * re-broadcast.
 *
 * @param void No parameters.
 * @return bool true when the tick completed without a policy error.
 */
bool monitor_step(void);

#endif // MONITOR_H
