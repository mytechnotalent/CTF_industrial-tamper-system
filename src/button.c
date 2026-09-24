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
// File:    button.c
// Desc:    Implements the debounced arm/disarm push-button input.
// Created: 2026

#include "pico/stdlib.h"
#include "pico/time.h"
#include "button.h"
#include "tamper_sys.h"
#include "hardware/gpio.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Time in microseconds of the most recent accepted press.
 */
static uint64_t g_arm_last_press_us;

/**
 * @brief True once at least one press has been accepted since reset.
 */
static bool g_arm_seen;

/**
 * @brief True when the current press has already been consumed.
 */
static bool g_arm_consumed;

/**
 * @brief Report whether a fresh debounced press edge is pending.
 *
 * @param void No parameters.
 * @return bool true when an unconsumed press edge is present.
 */
static bool arm_edge_pending(void) {
    if (!arm_pressed()) {
        g_arm_consumed = false;
        return false;
    }
    return !g_arm_consumed;
}

/**
 * @brief Apply the debounce window to the pending press.
 *
 * @param void No parameters.
 * @return bool true when the debounce window has elapsed.
 */
static bool arm_debounce_passed(void) {
    uint64_t now = time_us_64();
    if (g_arm_seen && (now - g_arm_last_press_us) < ARM_DEBOUNCE_US) {
        return false;
    }
    g_arm_last_press_us = now;
    g_arm_seen = true;
    return true;
}

bool arm_init(void) {
    gpio_init(TAMPER_BUTTON_PIN);
    gpio_set_dir(TAMPER_BUTTON_PIN, GPIO_IN);
    gpio_pull_up(TAMPER_BUTTON_PIN);
    return true;
}

bool arm_pressed(void) {
    return gpio_get(TAMPER_BUTTON_PIN) == 0;
}

bool arm_consume_press(void) {
    if (!arm_edge_pending()) {
        return false;
    }
    g_arm_consumed = true;
    return arm_debounce_passed();
}

void arm_reset(void) {
    g_arm_last_press_us = 0u;
    g_arm_seen = false;
    g_arm_consumed = false;
}
