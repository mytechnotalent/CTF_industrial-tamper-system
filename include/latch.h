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
// File:    latch.h
// Desc:    Declares the tamper latch state machine that sequences the
//          SG90 shutter actuator and fails safe on loss of authority.
// Created: 2026

#ifndef LATCH_H
#define LATCH_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Bounded latch travel time in milliseconds.
 */
#define LATCH_TRAVEL_MS 1000u

/**
 * @brief Tamper latch position and health states.
 */
typedef enum latch_state {
    /**
     * @brief Latch is seated closed, the safe asset state.
     */
    LATCH_STATE_CLOSED = 0,
    /**
     * @brief Latch is held fully open for secure service.
     */
    LATCH_STATE_OPEN = 1,
    /**
     * @brief Latch has failed safe and is latched in fault.
     */
    LATCH_STATE_FAULT = 2,
    /**
     * @brief Latch actuator is travelling between positions.
     */
    LATCH_STATE_MOVING = 3,
} latch_state_t;

/**
 * @brief Initialize the latch state machine and seat the latch closed.
 *
 * @param void No parameters.
 * @return void
 */
void latch_init(void);

/**
 * @brief Return the current latch state.
 *
 * @param void No parameters.
 * @return latch_state_t Current latch state.
 */
latch_state_t latch_state(void);

/**
 * @brief Report whether the latch is currently fully open.
 *
 * @param void No parameters.
 * @return bool true when the latch is open.
 */
bool latch_is_open(void);

/**
 * @brief Apply an authorized open or close command to the latch.
 *
 * Unauthorized commands are refused. An authorized command starts a
 * bounded travel interval that latch_tick completes. This is the guarded
 * command path that replaces the unauthenticated arm injection.
 *
 * @param open True to drive the latch open, false to drive it closed.
 * @param authorized True when the caller has validated the command.
 * @return void
 */
void latch_apply_command(bool open, bool authorized);

/**
 * @brief Advance the latch state machine by one tick.
 *
 * Completes a pending travel once the bounded interval has elapsed.
 *
 * @param void No parameters.
 * @return void
 */
void latch_tick(void);

/**
 * @brief Force the latch closed and latch a fault.
 *
 * This is the fail-safe posture taken when the mesh link is lost or the
 * local arm request cannot be authorized.
 *
 * @param void No parameters.
 * @return void
 */
void latch_fail_safe(void);

#endif // LATCH_H
