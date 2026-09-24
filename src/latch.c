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
// File:    latch.c
// Desc:    Implements the tamper latch state machine that sequences the
//          SG90 shutter actuator and fails safe on loss of authority.
// Created: 2026

#include "pico/time.h"
#include "latch.h"
#include "servo.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Current latch position and health state.
 */
static latch_state_t g_latch_state;

/**
 * @brief Pending travel target, true when the latch is opening.
 */
static bool g_latch_target_open;

/**
 * @brief Absolute time in microseconds when the pending travel completes.
 */
static uint64_t g_latch_move_until_us;

/**
 * @brief Complete a pending travel by driving the actuator.
 *
 * @param void No parameters.
 * @return void
 */
static void latch_complete(void) {
    if (g_latch_target_open) {
        latch_open();
        g_latch_state = LATCH_STATE_OPEN;
        return;
    }
    latch_close();
    g_latch_state = LATCH_STATE_CLOSED;
}

void latch_init(void) {
    g_latch_target_open = false;
    g_latch_state = LATCH_STATE_CLOSED;
    latch_close();
}

latch_state_t latch_state(void) {
    return g_latch_state;
}

bool latch_is_open(void) {
    return g_latch_state == LATCH_STATE_OPEN;
}

void latch_apply_command(bool open, bool authorized) {
    if (!authorized) {
        return;
    }
    g_latch_target_open = open;
    g_latch_state = LATCH_STATE_MOVING;
    g_latch_move_until_us = time_us_64() +
                            (uint64_t)LATCH_TRAVEL_MS * 1000u;
}

void latch_tick(void) {
    if (g_latch_state != LATCH_STATE_MOVING) {
        return;
    }
    if (time_us_64() < g_latch_move_until_us) {
        return;
    }
    latch_complete();
}

void latch_fail_safe(void) {
    latch_close();
    g_latch_target_open = false;
    g_latch_state = LATCH_STATE_FAULT;
}
