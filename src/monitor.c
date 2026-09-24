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
// File:    monitor.c
// Desc:    Implements the tamper node state machine that ties the local
//          arm/disarm remote, the sealed tamper command path, the cabinet
//          temperature sensor, the arm/disarm input, and the RYLR998 mesh
//          gateway link together. The production build never re-broadcasts
//          an untrusted frame: the SANDBOX_ONLY worm is the only path that
//          propagates, and it is compiled out of the clean firmware.
// Created: 2026

#include "tamper_sys.h"
#include "monitor.h"
#include "sensor.h"
#include "display.h"
#include "radio.h"
#include "status_led.h"
#include "button.h"
#include "servo.h"
#include "ir_remote.h"
#include "latch.h"
#include "control.h"
#include "implant.h"
#include "crypto_aead.h"
#include "crypto_kdf.h"
#include "field_secrets.h"
#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "pico/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Guarded node states derived from authorized tamper commands.
 */
typedef enum tamper_state {
    /**
     * @brief Node is secure and the latch is open for service.
     */
    TAMPER_STATE_SECURE = 0,
    /**
     * @brief Node is armed and the latch is seated closed.
     */
    TAMPER_STATE_ARMED = 1,
    /**
     * @brief An intrusion alert was accepted and the latch is sealed.
     */
    TAMPER_STATE_INTRUSION = 2,
    /**
     * @brief The mesh link was lost and the latch failed safe.
     */
    TAMPER_STATE_FAULT = 3,
} tamper_state_t;

/**
 * @brief Module-ready flag.
 */
static bool g_ready;

/**
 * @brief Initialized I2C peripheral handle for the LCD backpack.
 */
static i2c_inst_t *g_i2c;

/**
 * @brief Initialized I2C backpack address for the LCD.
 */
static uint8_t g_i2c_addr;

/**
 * @brief Derived XChaCha20-Poly1305 field key for the mesh link.
 */
static uint8_t g_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been derived and installed.
 */
static bool g_key_ready;

/**
 * @brief True once a sealed mesh command has been accepted.
 */
static bool g_link_seen;

/**
 * @brief Absolute time in microseconds of the last accepted mesh command.
 */
static uint64_t g_last_rx_us;

/**
 * @brief Last observed cabinet temperature in-range verdict.
 */
static bool g_cabinet_ok;

/**
 * @brief Last observed cabinet temperature in tenths of a degree Celsius.
 */
static int16_t g_cabinet_tenths;

/**
 * @brief Guarded node state.
 */
static tamper_state_t g_state;

/**
 * @brief Zone identifier recovered from the last accepted command.
 */
static uint16_t g_zone;

/**
 * @brief True while a local arm request awaits authorization.
 */
static bool g_request_pending;

/**
 * @brief First LCD tamper render line buffer.
 */
static char g_line1[DISPLAY_LINE_LEN];

/**
 * @brief Second LCD tamper render line buffer.
 */
static char g_line2[DISPLAY_LINE_LEN];

/**
 * @brief Inbound radio line accumulator.
 */
static char g_rx_line[RADIO_LINE_BUF_LEN];

/**
 * @brief Number of bytes currently held in the inbound line accumulator.
 */
static size_t g_rx_len;

/**
 * @brief Live console reading sequence number.
 */
static uint16_t g_seq;

/**
 * @brief Probe one I2C address and report whether it acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to probe.
 * @param addr The 7-bit address to probe.
 * @return bool true when the address acknowledged.
 */
static bool i2c_probe(i2c_inst_t *i2c, uint8_t addr) {
    uint8_t dummy = 0u;
    if (i2c_write_blocking(i2c, addr, &dummy, 1u, false) < 0) {
        return false;
    }
    printf("  found 0x%02X\n", (unsigned)addr);
    return true;
}

/**
 * @brief Probe the I2C bus and print every device that acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to scan.
 * @return void
 */
static void i2c_bus_scan(i2c_inst_t *i2c) {
    uint8_t addr;
    uint8_t found = 0u;
    printf("I2C scan:\n");
    for (addr = 0x08u; addr < 0x78u; ++addr) {
        found += i2c_probe(i2c, addr) ? 1u : 0u;
    }
    if (found == 0u) {
        printf("  no devices\n");
    }
}

/**
 * @brief Initialize the I2C bus pins and scan the bus.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_bus_init(void) {
    i2c_init(TAMPER_I2C, TAMPER_I2C_BAUD);
    gpio_set_function(TAMPER_I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(TAMPER_I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(TAMPER_I2C_SDA);
    gpio_pull_up(TAMPER_I2C_SCL);
    i2c_bus_scan(TAMPER_I2C);
}

/**
 * @brief Configure the onboard heartbeat LED.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_gpio_init(void) {
    gpio_init(TAMPER_LED_PIN);
    gpio_set_dir(TAMPER_LED_PIN, GPIO_OUT);
    gpio_put(TAMPER_LED_PIN, 0);
}

/**
 * @brief Pulse the onboard GP25 heartbeat LED once.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_heartbeat(void) {
    gpio_put(TAMPER_LED_PIN, 1);
    sleep_us(MONITOR_HEARTBEAT_US);
    gpio_put(TAMPER_LED_PIN, 0);
}

/**
 * @brief Clear every latched node state flag.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_clear_state(void) {
    g_link_seen = false;
    g_last_rx_us = 0u;
    g_cabinet_ok = false;
    g_cabinet_tenths = 0;
    g_state = TAMPER_STATE_SECURE;
    g_zone = 0u;
    g_request_pending = false;
}

/**
 * @brief Drive the latch for the current guarded node state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_apply_state(void) {
    latch_apply_command(g_state == TAMPER_STATE_SECURE, true);
}

/**
 * @brief Initialize the LED, LCD handles, latch, and node state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init(void) {
    monitor_gpio_init();
    g_i2c = TAMPER_I2C;
    g_i2c_addr = TAMPER_LCD_ADDR;
    monitor_clear_state();
    latch_init();
    monitor_apply_state();
    g_ready = true;
}

/**
 * @brief Initialize the human interface and actuator peripherals.
 *
 * @param void No parameters.
 * @return bool true when the LEDs, button, servo, and infrared eye ready.
 */
static bool monitor_peripherals_init(void) {
    return status_led_init() && arm_init() && servo_init() &&
           ir_remote_init();
}

/**
 * @brief Initialize the SANDBOX_ONLY implant when it is compiled in.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_implant_init(void) {
#ifdef SANDBOX_ONLY
    implant_init();
#endif
}

/**
 * @brief Derive the field key from the committed lab secret.
 *
 * LAB-ONLY: production must provision the field key through OTP rather
 * than deriving it from a committed passphrase and salt.
 *
 * @param void No parameters.
 * @return bool true when the field key was derived and installed.
 */
static bool monitor_derive_key(void) {
    bool ok = crypto_kdf_argon2id((const uint8_t *)FIELD_SECRET_PASSPHRASE,
                                  strlen(FIELD_SECRET_PASSPHRASE),
                                  FIELD_SECRET_SALT, 16u, g_key);
    g_key_ready = ok;
    control_set_key(ok ? g_key : NULL);
    return ok;
}

/**
 * @brief Print the boot banner and the control hint for the console.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_console_banner(void) {
    printf("=== OPERATION IRON WEB // ACT V TAMPER MESH ===\n");
    printf("REMOTE: CH+ 0x47=ARM CH- 0x45=DISARM CH 0x46=CLEAR\n");
    printf("BUTTON GP15: local arm request (needs authorization)\n");
}

/**
 * @brief Bring up the node state and command path.
 *
 * @param void No parameters.
 * @return bool true when the field key was installed.
 */
static bool monitor_start(void) {
    bool ok;
    monitor_state_init();
    control_init();
    monitor_implant_init();
    ok = monitor_derive_key();
    if (ok) monitor_console_banner();
    return ok;
}

bool monitor_init(void) {
    monitor_bus_init();
    if (!monitor_peripherals_init() || !sensor_init() ||
        !radio_init(TAMPER_UART) ||
        !display_init(TAMPER_I2C, TAMPER_LCD_ADDR)) {
        printf("INIT FAIL\n");
        return false;
    }
    return monitor_start();
}

void monitor_deinit(void) {
    g_ready = false;
    control_deinit();
}

void monitor_clear_request(void) {
    g_request_pending = false;
}

/**
 * @brief Map an authorized command byte to the guarded node state.
 *
 * @param command Guarded tamper command code.
 * @return tamper_state_t Guarded node state for the command.
 */
static tamper_state_t monitor_state_for(uint8_t command) {
    if (command == TAMPER_COMMAND_ALERT) return TAMPER_STATE_INTRUSION;
    if (command == TAMPER_COMMAND_ARM) return TAMPER_STATE_ARMED;
    if (command == TAMPER_COMMAND_SECURE) return TAMPER_STATE_SECURE;
    return TAMPER_STATE_FAULT;
}

/**
 * @brief Map a guarded node state to its annunciator lamp.
 *
 * @param state Guarded node state to map.
 * @return tamper_led_state_t Annunciator state for the node.
 */
static tamper_led_state_t monitor_led_for(tamper_state_t state) {
    if (state == TAMPER_STATE_INTRUSION || state == TAMPER_STATE_FAULT) {
        return TAMPER_INTRUSION;
    }
    if (state == TAMPER_STATE_ARMED || g_request_pending) {
        return TAMPER_ARMED;
    }
    return TAMPER_SECURE;
}

/**
 * @brief Render a guarded node state as a short status label.
 *
 * @param state Guarded node state to render.
 * @return const char* NUL-terminated state label.
 */
static const char *monitor_state_text(tamper_state_t state) {
    if (state == TAMPER_STATE_ARMED) return "ARMED";
    if (state == TAMPER_STATE_INTRUSION) return "ALERT";
    if (state == TAMPER_STATE_FAULT) return "FAULT";
    return "SECURE";
}

/**
 * @brief Render the mesh link status as a short label.
 *
 * @param void No parameters.
 * @return const char* NUL-terminated link label.
 */
static const char *monitor_link_text(void) {
    return g_link_seen ? "UP" : "--";
}

/**
 * @brief Render the resistance, masked by the SANDBOX_ONLY infection.
 *
 * @param void No parameters.
 * @return const char* NUL-terminated infection label.
 */
static const char *monitor_infection_text(void) {
#ifdef SANDBOX_ONLY
    return implant_infected() ? "INF" : "--";
#else
    return "--";
#endif
}

/**
 * @brief Format the active zone as a short decimal text.
 *
 * @param out Pointer to the mutable text buffer.
 * @param out_len Capacity of the text buffer in bytes.
 * @return void
 */
static void monitor_zone_text(char *out, size_t out_len) {
    snprintf(out, out_len, "%u", (unsigned)g_zone);
}

/**
 * @brief Map an annunciator lamp state to a short text label.
 *
 * @param state Annunciator lamp state to map.
 * @return const char* NUL-terminated lamp label.
 */
static const char *monitor_led_text(tamper_led_state_t state) {
    if (state == TAMPER_ARMED) return "YELLOW";
    if (state == TAMPER_INTRUSION) return "RED";
    return (state == TAMPER_SECURE) ? "GREEN" : "OFF";
}

/**
 * @brief Print one live status line for the interactive console.
 *
 * @param reading Pointer to the decoded DHT11 reading.
 * @return void
 */
static void monitor_log_reading(const dht_reading_t *reading) {
    tamper_led_state_t led = monitor_led_for(g_state);
    printf("CLIMATE t=%d h=%u ok=%d ST=%s LED=%s seq=%u\n",
           (int)reading->temperature_tenths,
           (unsigned)reading->humidity_tenths, (int)g_cabinet_ok,
           monitor_state_text(g_state), monitor_led_text(led),
           (unsigned)g_seq);
    g_seq += 1u;
}

/**
 * @brief Print the live sensor failure line and mark the climate invalid.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_climate_fail(void) {
    g_cabinet_ok = false;
    printf("SENSOR read failed -> WARNING\n");
}

/**
 * @brief Render the tamper status and zone lines to the 1602 LCD.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_render(void) {
    char zone[8];
    monitor_zone_text(zone, sizeof(zone));
    snprintf(g_line1, DISPLAY_LINE_LEN, "ST:%-7s L:%s",
             monitor_state_text(g_state), monitor_link_text());
    snprintf(g_line2, DISPLAY_LINE_LEN, "ZN:%s I:%s",
             zone, monitor_infection_text());
    display_render_lines(g_i2c, g_i2c_addr, g_line1, g_line2);
}

/**
 * @brief Sample the DHT11 cabinet sensor and classify it.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_refresh_climate(void) {
    dht_reading_t reading;
    if (sensor_read(&reading) != SENSOR_RESULT_OK) {
        monitor_climate_fail();
        return;
    }
    g_cabinet_ok = climate_ok(&reading);
    g_cabinet_tenths = reading.temperature_tenths;
    monitor_log_reading(&reading);
}

/**
 * @brief Consume one debounced arm press and raise the request.
 *
 * A local arm request raises the armed-pending indication. It never
 * changes the guarded state on its own, so it cannot silently bypass
 * authorization.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_arm(void) {
    if (!arm_consume_press()) {
        return;
    }
    g_request_pending = true;
    printf("BUTTON arm request -> pending authorization\n");
}

/**
 * @brief Apply one decoded infrared arm/disarm command.
 *
 * @param cmd Pointer to the decoded infrared command.
 * @return void
 */
static void monitor_apply_ir_command(const ir_command_t *cmd) {
    if (cmd->command == MONITOR_IR_CLEAR) {
        monitor_clear_request();
        return;
    }
    if (cmd->command == MONITOR_IR_ARM ||
        cmd->command == MONITOR_IR_DISARM) {
        g_request_pending = true;
    }
}

/**
 * @brief Map a decoded remote command to its name.
 *
 * @param command Decoded NEC command byte.
 * @return const char* Command name string.
 */
static const char *monitor_ir_name(uint8_t command) {
    if (command == MONITOR_IR_ARM) return "ARM";
    if (command == MONITOR_IR_DISARM) return "DISARM";
    return (command == MONITOR_IR_CLEAR) ? "CLEAR" : "UNKNOWN";
}

/**
 * @brief Poll the infrared arm remote for a command.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_ir(void) {
    ir_command_t cmd;
    if (!ir_remote_poll(&cmd)) {
        return;
    }
    printf("%s (0x%02X)\n", monitor_ir_name(cmd.command),
           (unsigned)cmd.command);
    monitor_apply_ir_command(&cmd);
}

/**
 * @brief Apply one authorized command to the node and latch.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_apply_command(void) {
    g_state = monitor_state_for(control_command());
    g_zone = (uint16_t)control_zone();
    g_request_pending = false;
    monitor_apply_state();
}

/**
 * @brief Feed an inbound frame to the SANDBOX_ONLY implant when compiled in.
 *
 * The production firmware compiles this path out, so an untrusted frame
 * can never trigger a re-broadcast.
 *
 * @param hex Pointer to the inbound frame text.
 * @param len Number of inbound frame bytes.
 * @return void
 */
static void monitor_implant_frame(const char *hex, size_t len) {
#ifdef SANDBOX_ONLY
    implant_handle_command((const uint8_t *)hex, len);
#else
    (void)hex;
    (void)len;
#endif
}

/**
 * @brief Verify and apply one inbound mesh frame.
 *
 * The sealed tamper command is authenticated and authorized before it can
 * move the latch. No local arm request can bypass this authorization.
 *
 * @param hex Pointer to the inbound frame text.
 * @param len Number of inbound frame bytes.
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_apply_frame(const char *hex, size_t len, uint64_t now_us) {
    monitor_implant_frame(hex, len);
    if (!control_handle_frame(hex)) {
        return;
    }
    g_link_seen = true;
    g_last_rx_us = now_us;
    monitor_apply_command();
}

/**
 * @brief Fail safe on a silent mesh link.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_fail_safe(void) {
    g_state = TAMPER_STATE_FAULT;
    g_zone = 0u;
    g_request_pending = false;
    latch_fail_safe();
}

/**
 * @brief Drain inbound radio lines and apply any sealed command.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_rx_tick(uint64_t now_us) {
    radio_rcv_t rcv;
    while (radio_line_pump(TAMPER_UART, g_rx_line, &g_rx_len)) {
        if (radio_parse_rcv(g_rx_line, &rcv) == RADIO_RESULT_OK) {
            printf("RX from 0x%04X, %u bytes\n", (unsigned)rcv.sender,
                   (unsigned)rcv.len);
            monitor_apply_frame(rcv.payload, rcv.len, now_us);
        }
    }
}

/**
 * @brief Drive to the fail-safe posture when the mesh link goes silent.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_check_link(uint64_t now_us) {
    if (!g_link_seen) {
        return;
    }
    if ((now_us - g_last_rx_us) <= (uint64_t)TAMPER_ALERT_WAIT_MS * 1000u) {
        return;
    }
    monitor_fail_safe();
}

/**
 * @brief Service the arm button, arm remote, and mesh link.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_service_inputs(uint64_t now_us) {
    monitor_handle_arm();
    monitor_handle_ir();
    monitor_rx_tick(now_us);
    monitor_check_link(now_us);
}

/**
 * @brief Advance the SANDBOX_ONLY implant when it is compiled in.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_implant_tick(void) {
#ifdef SANDBOX_ONLY
    implant_tick();
#endif
}

/**
 * @brief Drive exactly one annunciator lamp for the current node state.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_drive_leds(void) {
    status_led_show(monitor_led_for(g_state));
}

/**
 * @brief Drive the annunciator, latch, implant, and tamper display.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_service_outputs(void) {
    monitor_implant_tick();
    latch_tick();
    monitor_drive_leds();
    monitor_render();
    monitor_heartbeat();
}

bool monitor_step(void) {
    uint64_t now_us;
    if (!g_ready) {
        return false;
    }
    now_us = time_us_64();
    monitor_refresh_climate();
    monitor_service_inputs(now_us);
    monitor_service_outputs();
    return true;
}
