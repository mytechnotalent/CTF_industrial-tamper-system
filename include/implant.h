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
// File:    implant.h
// Desc:    Declares the SANDBOX_ONLY FROSTLINE worm: the IRONWEB magic
//          frame, mesh propagation, reserved-sector infection marker, and
//          the CoreDebug anti-debug trap. Compiled only under SANDBOX_ONLY.
// Created: 2026

#ifndef IMPLANT_H
#define IMPLANT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Magic frame preamble that arms the IRONWEB worm.
 */
#define TAMPER_IMPLANT_WORM_MAGIC "IRONWEB"

/**
 * @brief Length in bytes of the IRONWEB worm magic preamble.
 */
#define TAMPER_IMPLANT_WORM_MAGIC_LEN 7u

/**
 * @brief Length in bytes of the synthetic worm status body.
 */
#define TAMPER_IMPLANT_WORM_BODY_LEN 4u

/**
 * @brief Total length in bytes of one IRONWEB worm frame.
 */
#define TAMPER_IMPLANT_WORM_LEN \
    (TAMPER_IMPLANT_WORM_MAGIC_LEN + TAMPER_IMPLANT_WORM_BODY_LEN)

/**
 * @brief Marker byte written into the reserved flash sector.
 */
#define TAMPER_IMPLANT_MARKER_BYTE 0xC7u

/**
 * @brief Offset of the reserved flash sector used by the staging marker.
 *
 * The final 4 KiB sector of the 4 MiB flash, well beyond the firmware.
 */
#define TAMPER_IMPLANT_RESERVE_OFFSET 0x3FF000u

/**
 * @brief Reserved flash sector address used by the staging marker.
 */
#define TAMPER_IMPLANT_RESERVE_ADDR 0x103FF000u

/**
 * @brief CoreDebug DHCSR register address used by the anti-debug trap.
 */
#define TAMPER_IMPLANT_DHCSR_ADDR 0xE000EDF0u

/**
 * @brief CoreDebug DHCSR bit that reports an enabled debugger.
 */
#define TAMPER_IMPLANT_DHCSR_DEBUGEN 0x00000001u

/**
 * @brief CoreDebug DHCSR bit that reports a halted core.
 */
#define TAMPER_IMPLANT_DHCSR_HALT 0x00000002u

/**
 * @brief Number of ticks between autonomous mesh propagation attempts.
 */
#define TAMPER_IMPLANT_PROPAGATE_INTERVAL_TICKS 4u

/**
 * @brief Initialize the implant and re-install from the reserved sector.
 *
 * On first run the implant writes its infection marker into the reserved
 * flash sector. On every later boot the marker is present, so the worm is
 * re-installed without any firmware change.
 *
 * @param void No parameters.
 * @return void
 */
void implant_init(void);

/**
 * @brief Advance the implant by one tick: autonomous mesh propagation.
 *
 * @param void No parameters.
 * @return void
 */
void implant_tick(void);

/**
 * @brief Handle one inbound frame, infecting and propagating on the magic.
 *
 * @param frame Pointer to the inbound frame bytes.
 * @param len Number of inbound frame bytes.
 * @return void
 */
void implant_handle_command(const uint8_t *frame, size_t len);

/**
 * @brief Report whether the worm payload handler is armed.
 *
 * @param void No parameters.
 * @return bool true when the worm handler is armed.
 */
bool implant_armed(void);

/**
 * @brief Report whether a debug probe is attached via CoreDebug DHCSR.
 *
 * @param void No parameters.
 * @return bool true when C_DEBUGEN or C_HALT is set.
 */
bool implant_debug_attached(void);

/**
 * @brief Report whether the reserved-sector infection marker is set.
 *
 * @param void No parameters.
 * @return bool true when the infection marker occupies the reserved sector.
 */
bool implant_infected(void);

/**
 * @brief Report whether mesh propagation is currently enabled.
 *
 * @param void No parameters.
 * @return bool true when the worm may re-broadcast to the mesh.
 */
bool implant_propagation_enabled(void);

/**
 * @brief Enable or disable mesh propagation for neutralization.
 *
 * @param enabled True to allow re-broadcast, false to neutralize.
 * @return void
 */
void implant_set_propagation(bool enabled);

#endif // IMPLANT_H
