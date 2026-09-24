/**
 * FILE: implant_host.h
 *
 * DESCRIPTION:
 * Host mock header for the FROSTLINE implant CoreDebug and reserved
 * flash accesses so the anti-debug, rootkit, and persistence paths are
 * testable.
 *
 * BRIEF:
 * Implant host mock for native unit testing.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#ifndef IMPLANT_HOST_H
#define IMPLANT_HOST_H

#include <stdint.h>

/**
 * @brief Mutable mock CoreDebug DHCSR register value.
 */
uint32_t g_mock_implant_dhcsr;

/**
 * @brief Mutable mock reserved flash sector marker value.
 */
uint32_t g_mock_implant_flash;

/**
 * @brief Reset the implant host mock register state.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_implant_reset(void) {
    g_mock_implant_dhcsr = 0u;
    g_mock_implant_flash = 0u;
}

/**
 * @brief Seed the mock reserved-sector persistence marker.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_implant_seed_marker(void) {
    g_mock_implant_flash = 0xC7u;
}

/**
 * @brief Clear the mock reserved-sector persistence marker.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_implant_clear_marker(void) {
    g_mock_implant_flash = 0u;
}

#endif // IMPLANT_HOST_H
