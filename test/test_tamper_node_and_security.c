/**
 * FILE: test_tamper_node_and_security.c
 *
 * DESCRIPTION:
 * Comprehensive test suite for the RP2350 IRON WEB industrial tamper
 * system: provisioning constants, packet artifact, CRC, DHT11 cabinet
 * classification, display formatting, RYLR998 AT command building, +RCV
 * parsing, the latch state machine, the sealed tamper command path with
 * its anti-replay window, the tamper monitor state machine, and the
 * SANDBOX_ONLY FROSTLINE worm with its reserved-sector infection marker,
 * mesh propagation, and CoreDebug anti-debug trap.
 *
 * BRIEF:
 * Native unit test runner for industrial-tamper-system.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#include "harness.h"
#include "mock/pico/stdlib.h"
#include "mock/pico/time.h"
#include "mock/hardware/gpio.h"
#include "mock/hardware/i2c.h"
#include "mock/hardware/pwm.h"
#include "mock/hardware/uart.h"
#include "implant_host.h"
#include "tamper_sys.h"
#include "button.h"
#include "crc.h"
#include "sensor.h"
#include "display.h"
#include "radio.h"
#include "latch.h"
#include "control.h"
#include "tamper_auth.h"
#include "monitor.h"
#include "implant.h"
#include "crypto_aead.h"
#include "crypto_kdf.h"
#include "envelope.h"
#include "packet_artifact.h"
#include <stdio.h>
#include <string.h>

#undef SENSOR_HOST_PULSE_US
#define SENSOR_HOST_PULSE_US 0u

#include "../src/sensor.c"
#include "../src/crc.c"
#include "../src/display.c"
#include "../src/radio.c"
#include "../src/tamper_auth.c"
#include "../src/latch.c"
#include "../src/control.c"
#include "../src/monitor.c"
#include "../src/implant.c"

/**
 * @brief Simulated DHT11 high-pulse widths for the canonical reading.
 */
static const uint16_t s_widths[SENSOR_BIT_COUNT] = {
    26u, 26u, 70u, 70u, 70u, 70u, 26u, 70u,
    26u, 26u, 26u, 26u, 26u, 26u, 26u, 26u,
    26u, 26u, 26u, 70u, 26u, 70u, 70u, 70u,
    26u, 26u, 26u, 26u, 26u, 26u, 26u, 26u,
    26u, 70u, 26u, 70u, 26u, 70u, 26u, 26u,
};

/**
 * @brief Fixed field key used by the authorization and command tests.
 */
static const uint8_t s_key[CRYPTO_AEAD_KEY_LEN] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
};

/**
 * @brief File-scope GPIO timeline offset scratch buffer.
 */
static uint32_t s_offsets[256];

/**
 * @brief File-scope GPIO timeline level scratch buffer.
 */
static int s_levels[256];

/**
 * @brief File-scope raw I2C log scratch buffer.
 */
static uint8_t s_raw[512];

/**
 * @brief File-scope decoded LCD scratch buffer.
 */
static char s_decoded[DISPLAY_LINE_LEN * 4];

/**
 * @brief File-scope first LCD render line buffer.
 */
static char s_line1[DISPLAY_LINE_LEN];

/**
 * @brief File-scope second LCD render line buffer.
 */
static char s_line2[DISPLAY_LINE_LEN];

/**
 * @brief File-scope decoded DHT11 reading.
 */
static dht_reading_t s_reading;

/**
 * @brief File-scope decoded inbound radio report.
 */
static radio_rcv_t s_rcv;

/**
 * @brief File-scope NEC pulse-duration scratch buffer.
 */
static uint16_t s_pulses[IR_REMOTE_MAX_PULSES];

/**
 * @brief File-scope NEC GPIO timeline offset scratch buffer.
 */
static uint32_t s_ir_off[IR_REMOTE_MAX_PULSES * 2u];

/**
 * @brief File-scope NEC GPIO timeline level scratch buffer.
 */
static int s_ir_lvl[IR_REMOTE_MAX_PULSES * 2u];

/**
 * @brief Reset the host mock peripherals.
 *
 * @param void No parameters.
 * @return void
 */
static void reset_mocks(void) {
    mock_timer_reset();
    mock_gpio_reset();
    mock_i2c_reset();
    mock_uart_reset();
    mock_pwm_reset();
}

/**
 * @brief Reset every host mock and owned module to a clean state.
 *
 * @param void No parameters.
 * @return void
 */
static void reset_all(void) {
    reset_mocks();
    arm_reset();
    mock_implant_reset();
    control_init();
    latch_init();
}

/**
 * @brief Append one timeline point and advance the entry count.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param level Level to record.
 * @param edge Absolute timestamp in microseconds.
 * @return size_t Updated entry count.
 */
static size_t timeline_pair(uint32_t *offsets, int *levels, size_t n,
                            int level, uint32_t edge) {
    offsets[n] = edge;
    levels[n] = level;
    return n + 1u;
}

/**
 * @brief Write the four leading DHT11 handshake timeline points.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @return size_t Number of timeline entries written.
 */
static size_t timeline_header(uint32_t *offsets, int *levels) {
    size_t n = 0u;
    n = timeline_pair(offsets, levels, n, 1, 0u);
    n = timeline_pair(offsets, levels, n, 0, 30u);
    n = timeline_pair(offsets, levels, n, 1, 110u);
    n = timeline_pair(offsets, levels, n, 0, 190u);
    return n;
}

/**
 * @brief Append the 40 data-bit timeline point pairs.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param widths Pointer to 40 high-pulse width values.
 * @return size_t Updated entry count.
 */
static size_t timeline_bits(uint32_t *offsets, int *levels, size_t n,
                            const uint16_t *widths) {
    uint32_t edge = 190u;
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        edge += 50u;
        n = timeline_pair(offsets, levels, n, 1, edge);
        edge += widths[i];
        n = timeline_pair(offsets, levels, n, 0, edge);
    }
    return n;
}

/**
 * @brief Build a DHT11 one-wire waveform timeline from bit widths.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param widths Pointer to 40 high-pulse width values.
 * @return size_t Number of timeline entries written.
 */
static size_t build_timeline(uint32_t *offsets, int *levels,
                             const uint16_t *widths) {
    size_t n = timeline_header(offsets, levels);
    return timeline_bits(offsets, levels, n, widths);
}

/**
 * @brief Combine the high nibbles of two I2C bytes into one display byte.
 *
 * @param hi First raw mock I2C byte.
 * @param lo Second raw mock I2C byte.
 * @return char Decoded display byte.
 */
static char decode_nibble(uint8_t hi, uint8_t lo) {
    uint8_t h = (uint8_t)((hi >> 4u) & 0x0Fu);
    uint8_t l = (uint8_t)((lo >> 4u) & 0x0Fu);
    return (char)((h << 4u) | l);
}

/**
 * @brief Decode 4-bit I2C LCD writes back into display bytes.
 *
 * @param buf Pointer to raw mock I2C byte log.
 * @param n Number of raw log bytes.
 * @param out Pointer to mutable decoded text buffer.
 * @param out_max Capacity of the decoded text buffer.
 * @return size_t Number of decoded display bytes.
 */
static size_t decode_lcd_bytes(const uint8_t *buf, size_t n, char *out,
                               size_t out_max) {
    size_t k = 0u;
    size_t i = 0u;
    while ((i + 4u <= n) && (k + 1u < out_max)) {
        out[k] = decode_nibble(buf[i], buf[i + 2u]);
        ++k;
        i += 4u;
    }
    out[k] = '\0';
    return k;
}

/**
 * @brief Build a 40-bit width array from five response bytes.
 *
 * @param bytes Pointer to five DHT11 response bytes.
 * @param out Pointer to mutable width array of SENSOR_BIT_COUNT entries.
 * @return void
 */
static void build_bits_from_bytes(const uint8_t bytes[SENSOR_BYTE_COUNT],
                                  uint16_t *out) {
    uint8_t b;
    uint8_t bit;
    size_t k = 0u;
    for (b = 0u; b < SENSOR_BYTE_COUNT; ++b) {
        for (bit = 0u; bit < 8u; ++bit) {
            out[k] = ((bytes[b] >> (7u - bit)) & 1u) ? 70u : 26u;
            k += 1u;
        }
    }
}

/**
 * @brief Fill a 40-entry width array from the canonical bit widths.
 *
 * @param bits Pointer to mutable 40-entry width array.
 * @return void
 */
static void fill_widths(uint16_t *bits) {
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        bits[i] = s_widths[i];
    }
}

/**
 * @brief Arm a full DHT11 waveform timeline at a base timestamp.
 *
 * @param widths Pointer to 40 high-pulse width values.
 * @param base_us Absolute base timestamp in microseconds.
 * @return void
 */
static void mock_dht_timeline(const uint16_t *widths, uint64_t base_us) {
    size_t count = build_timeline(s_offsets, s_levels, widths);
    mock_gpio_timeline_begin_at(base_us, s_offsets, s_levels, count,
                                TAMPER_DHT_PIN);
}

/**
 * @brief Fill a five-byte DHT11 response for a cabinet temperature.
 *
 * @param bytes Pointer to mutable five-byte response array.
 * @param temp_int Integer degrees Celsius for the response.
 * @return void
 */
static void fill_room_bytes(uint8_t bytes[SENSOR_BYTE_COUNT],
                            uint8_t temp_int) {
    bytes[0] = 40u;
    bytes[1] = 0u;
    bytes[2] = temp_int;
    bytes[3] = 0u;
    bytes[4] = (uint8_t)(bytes[0] + bytes[2]);
}

/**
 * @brief Arm a valid cabinet waveform at the current mock time.
 *
 * @param temp_int Integer degrees Celsius for the simulated cabinet.
 * @return void
 */
static void arm_room(uint8_t temp_int) {
    uint16_t bits[SENSOR_BIT_COUNT];
    uint8_t bytes[SENSOR_BYTE_COUNT];
    fill_room_bytes(bytes, temp_int);
    build_bits_from_bytes(bytes, bits);
    mock_dht_timeline(bits, mock_timer_now_us());
}

/**
 * @brief Assert the decoded LCD frame buffer contents.
 *
 * @param line1 Expected first-line text prefix.
 * @param line2 Expected second-line text prefix.
 * @return void
 */
static void assert_lcd_frame(const char *line1, const char *line2) {
    size_t count;
    count = mock_i2c_get_log(s_raw, sizeof(s_raw));
    decode_lcd_bytes(s_raw, count, s_decoded, sizeof(s_decoded));
    TEST_ASSERT_TRUE(strncmp(line1, &s_decoded[1], strlen(line1)) == 0);
    TEST_ASSERT_TRUE(strncmp(line2, &s_decoded[18], strlen(line2)) == 0);
}

/**
 * @brief Load a canonical valid reading into the fixture.
 *
 * @param void No parameters.
 * @return void
 */
static void load_reading(void) {
    s_reading.temperature_tenths = 230;
    s_reading.humidity_tenths = 610;
    s_reading.valid = true;
}

/**
 * @brief Assert the GPIO pin and bus provisioning constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_pin_constants(void) {
    TEST_ASSERT_EQUAL_UINT(25u, TAMPER_LED_PIN);
    TEST_ASSERT_EQUAL_UINT(4u, TAMPER_DHT_PIN);
    TEST_ASSERT_EQUAL_UINT(2u, TAMPER_I2C_SDA);
    TEST_ASSERT_EQUAL_UINT(3u, TAMPER_I2C_SCL);
    TEST_ASSERT_EQUAL_UINT(100000u, TAMPER_I2C_BAUD);
    TEST_ASSERT_EQUAL_UINT(8u, TAMPER_UART_TX);
    TEST_ASSERT_EQUAL_UINT(9u, TAMPER_UART_RX);
}

/**
 * @brief Assert the servo, remote, and button pin constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_pin_constants_extra(void) {
    TEST_ASSERT_EQUAL_UINT(16u, TAMPER_RED_LED_PIN);
    TEST_ASSERT_EQUAL_UINT(17u, TAMPER_YELLOW_LED_PIN);
    TEST_ASSERT_EQUAL_UINT(18u, TAMPER_GREEN_LED_PIN);
    TEST_ASSERT_EQUAL_UINT(15u, TAMPER_BUTTON_PIN);
    TEST_ASSERT_EQUAL_UINT(14u, TAMPER_SERVO_PIN);
    TEST_ASSERT_EQUAL_UINT(5u, TAMPER_IR_PIN);
}

/**
 * @brief Assert the UART, frame, and latch provisioning constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_frame_constants(void) {
    TEST_ASSERT_EQUAL_UINT(115200u, TAMPER_UART_BAUD);
    TEST_ASSERT_EQUAL_UINT(48u, TAMPER_FRAME_SIZE);
    TEST_ASSERT_EQUAL_UINT(5000u, TAMPER_ALERT_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(PACKET_LCD_I2C_ADDRESS, TAMPER_LCD_ADDR);
    TEST_ASSERT_EQUAL_UINT(500u, TAMPER_LATCH_CLOSE_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(1500u, TAMPER_LATCH_OPEN_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(PACKET_NODE_ADDRESS, TAMPER_NODE_ID);
}

/**
 * @brief Assert the climate and zone band constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_band_constants(void) {
    TEST_ASSERT_EQUAL_INT(0, TAMPER_CLIMATE_MIN_TENTHS);
    TEST_ASSERT_EQUAL_INT(400, TAMPER_CLIMATE_MAX_TENTHS);
    TEST_ASSERT_EQUAL_INT(0, TAMPER_ZONE_MIN);
    TEST_ASSERT_EQUAL_INT(16, TAMPER_ZONE_MAX);
    TEST_ASSERT_EQUAL_UINT(0x0001u, TAMPER_GATEWAY_ADDRESS);
}

/**
 * @brief Assert the arm remote and guarded command constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_remote_constants(void) {
    TEST_ASSERT_EQUAL_UINT(0x47u, MONITOR_IR_ARM);
    TEST_ASSERT_EQUAL_UINT(0x45u, MONITOR_IR_DISARM);
    TEST_ASSERT_EQUAL_UINT(0x46u, MONITOR_IR_CLEAR);
    TEST_ASSERT_EQUAL_UINT(0x01u, TAMPER_COMMAND_ALERT);
    TEST_ASSERT_EQUAL_UINT(0x02u, TAMPER_COMMAND_ARM);
    TEST_ASSERT_EQUAL_UINT(0x03u, TAMPER_COMMAND_SECURE);
}

/**
 * @brief Assert the packet artifact identity constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_artifact_ids(void) {
    TEST_ASSERT_EQUAL_STRING("industrial-tamper-packets-demo-v1",
                             PACKET_ARTIFACT_FORMAT);
    TEST_ASSERT_EQUAL_UINT(1u, PACKET_FRAME_VERSION);
    TEST_ASSERT_EQUAL_UINT(7u, PACKET_NODE_ADDRESS);
    TEST_ASSERT_EQUAL_HEX16(0x0001u, PACKET_GATEWAY_ADDRESS);
    TEST_ASSERT_EQUAL_UINT(48u, PACKET_FRAME_SIZE);
    TEST_ASSERT_EQUAL_UINT(5000u, PACKET_ALERT_WAIT_MS);
}

/**
 * @brief Assert the packet artifact frame constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_artifact_frame(void) {
    TEST_ASSERT_EQUAL_UINT(500u, PACKET_LATCH_CLOSE_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(1500u, PACKET_LATCH_OPEN_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(240u, PACKET_DHT_TIMEOUT_US);
    TEST_ASSERT_EQUAL_UINT(0x27u, PACKET_LCD_I2C_ADDRESS);
    TEST_ASSERT_EQUAL_UINT(256u, PACKET_MAX_RCV_LEN);
    TEST_ASSERT_EQUAL_UINT(48u, (unsigned)sizeof(PACKET_EXAMPLE_FRAME));
    TEST_ASSERT_EQUAL_UINT8(0x7Bu, PACKET_EXAMPLE_FRAME[0]);
}

/**
 * @brief Assert the formatted frame text and zero padding.
 *
 * @param frame Pointer to the formatted frame buffer.
 * @param n Length of the JSON body.
 * @param cap Capacity of the frame buffer.
 * @return void
 */
static void assert_frame_padding(const char *frame, size_t n, size_t cap) {
    static const char zeros[TAMPER_FRAME_SIZE] = {0};
    TEST_ASSERT_EQUAL_UINT(29u, (unsigned)n);
    TEST_ASSERT_EQUAL_STRING("{\"n\":7,\"s\":0,\"t\":230,\"h\":610}", frame);
    TEST_ASSERT_EQUAL_MEMORY(zeros, &frame[n], cap - n);
}

/**
 * @brief Assert frame-builder rejection of null arguments.
 *
 * @param frame Pointer to a frame buffer.
 * @param cap Capacity of the frame buffer.
 * @return void
 */
static void assert_frame_rejects(char *frame, size_t cap) {
    TEST_ASSERT_EQUAL_UINT(0u,
                           (unsigned)sensor_build_frame(&s_reading, 0u, NULL, 0u));
    TEST_ASSERT_EQUAL_UINT(0u,
                           (unsigned)sensor_build_frame(NULL, 0u, frame, cap));
}

/**
 * @brief Assert command-builder rejection paths.
 *
 * @param cmd Pointer to a command buffer.
 * @param cap Capacity of the command buffer.
 * @return void
 */
static void assert_build_rejects(char *cmd, size_t cap) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_build_send_cmd(0x0001u, (const uint8_t *)"abc",
                                           257u, cmd, cap));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_build_send_cmd(0x0001u, NULL, 3u, cmd, cap));
}

/**
 * @brief Parse the canonical comma-laden JSON +RCV line.
 *
 * @param void No parameters.
 * @return radio_result_t Parsed result code.
 */
static radio_result_t parse_json_rcv(void) {
    return radio_parse_rcv("+RCV=0007,29,{\"n\":7,\"s\":0,\"t\":230,\"h\":610}"
                           ",-78,5", &s_rcv);
}

/**
 * @brief Assert +RCV parsing of a comma-laden JSON payload.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_json(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, parse_json_rcv());
    TEST_ASSERT_EQUAL_HEX16(0x0007u, s_rcv.sender);
    TEST_ASSERT_EQUAL_UINT(29u, (unsigned)s_rcv.len);
    TEST_ASSERT_EQUAL_STRING("{\"n\":7,\"s\":0,\"t\":230,\"h\":610}",
                             s_rcv.payload);
    TEST_ASSERT_EQUAL_INT(-78, s_rcv.rssi);
    TEST_ASSERT_EQUAL_INT(5, s_rcv.snr);
}

/**
 * @brief Assert +RCV parsing of a short comma-bearing payload.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_comma(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=0008,9,{\"a\",\"b\"},-60,3", &s_rcv));
    TEST_ASSERT_EQUAL_HEX16(0x0008u, s_rcv.sender);
    TEST_ASSERT_EQUAL_STRING("{\"a\",\"b\"}", s_rcv.payload);
}

/**
 * @brief Assert +RCV parsing of a frame with no RSSI/SNR tail.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_no_tail(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=0007,2,ok", &s_rcv));
    TEST_ASSERT_EQUAL_INT(0, s_rcv.rssi);
    TEST_ASSERT_EQUAL_INT(0, s_rcv.snr);
}

/**
 * @brief Assert +RCV rejection of null arguments.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_null(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR, radio_parse_rcv(NULL, &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0001,1,a", NULL));
}

/**
 * @brief Assert +RCV rejection of malformed and oversized lines.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_rejects(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("AT+SEND=0001,3,abc", &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_parse_rcv("+RCV=0001,300,abcdef", &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0001,5,abc", &s_rcv));
    assert_rcv_null();
}

/**
 * @brief Assert the inbound line pump consumes two CRLF-terminated lines.
 *
 * @param line Pointer to line buffer.
 * @param len Pointer to accumulated length.
 * @return void
 */
static void assert_pump_lines(char *line, size_t *len) {
    TEST_ASSERT_TRUE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_STRING("ab", line);
    TEST_ASSERT_TRUE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_STRING("cd", line);
    TEST_ASSERT_FALSE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)*len);
}

/**
 * @brief Assert the positive display formatting path.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_format_ok(void) {
    s_reading.temperature_tenths = 230;
    s_reading.humidity_tenths = 610;
    s_reading.valid = true;
    display_format_lines(&s_reading, 42u, true, s_line1, s_line2);
    TEST_ASSERT_EQUAL_STRING("T:23.0C H:61.0%", s_line1);
    TEST_ASSERT_EQUAL_STRING("N:07 S:0042 OK", s_line2);
}

/**
 * @brief Assert the negative display formatting path.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_format_fail(void) {
    s_reading.temperature_tenths = -53;
    display_format_lines(&s_reading, 0u, false, s_line1, s_line2);
    TEST_ASSERT_EQUAL_STRING("T:-5.3C H:61.0%", s_line1);
    TEST_ASSERT_EQUAL_STRING("N:07 S:0000 !!", s_line2);
}

/**
 * @brief Build the NEC frame word for address zero and a command.
 *
 * @param command Eight-bit remote command code.
 * @return uint32_t LSB-first frame word with inverse bytes.
 */
static uint32_t nec_word(uint8_t command) {
    return 0x0000FF00u | ((uint32_t)command << 16u) |
           ((uint32_t)(uint8_t)~command << 24u);
}

/**
 * @brief Fill the thirty-two LSB-first mark and space durations.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param word LSB-first NEC frame word.
 * @return void
 */
static void nec_bits(uint16_t *pulses, uint32_t word) {
    uint8_t i;
    for (i = 0u; i < 32u; ++i) {
        pulses[2u + 2u * i] = 560u;
        pulses[3u + 2u * i] = ((word >> i) & 1u) ? 1690u : 560u;
    }
}

/**
 * @brief Fill a complete NEC pulse train for a command.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param command Eight-bit remote command code.
 * @return void
 */
static void nec_fill(uint16_t *pulses, uint8_t command) {
    pulses[0] = 9000u;
    pulses[1] = 4500u;
    nec_bits(pulses, nec_word(command));
    pulses[66] = 560u;
    pulses[67] = 560u;
}

/**
 * @brief Append one NEC timeline point and advance the entry count.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param at Absolute offset in microseconds.
 * @param level Level to record.
 * @return size_t Updated entry count.
 */
static size_t nec_append(uint32_t *offsets, int *levels, size_t n,
                         uint32_t at, int level) {
    offsets[n] = at;
    levels[n] = level;
    return n + 1u;
}

/**
 * @brief Lay a NEC pulse train onto a mock GPIO timeline.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @return size_t Number of timeline entries written.
 */
static size_t nec_place(const uint16_t *pulses, uint32_t *offsets,
                        int *levels) {
    size_t i;
    size_t n = 0u;
    uint32_t t = 0u;
    for (i = 0u; i < IR_REMOTE_MAX_PULSES; ++i) {
        n = nec_append(offsets, levels, n, t, (i % 2u == 0u) ? 0 : 1);
        t += pulses[i];
    }
    n = nec_append(offsets, levels, n, t, 0);
    return n;
}

/**
 * @brief Arm the mock GPIO timeline with a NEC frame.
 *
 * @param command Eight-bit remote command code.
 * @return void
 */
static void nec_arm(uint8_t command) {
    size_t count;
    nec_fill(s_pulses, command);
    count = nec_place(s_pulses, s_ir_off, s_ir_lvl);
    mock_gpio_timeline_begin_at(mock_timer_now_us(), s_ir_off, s_ir_lvl,
                                count, TAMPER_IR_PIN);
}

/**
 * @brief Write one 32-bit little-endian value into a buffer.
 *
 * @param body Pointer to the four-byte output.
 * @param value Value to serialize.
 * @return void
 */
static void put_le32(uint8_t *body, uint32_t value) {
    body[0] = (uint8_t)(value & 0xFFu);
    body[1] = (uint8_t)((value >> 8u) & 0xFFu);
    body[2] = (uint8_t)((value >> 16u) & 0xFFu);
    body[3] = (uint8_t)((value >> 24u) & 0xFFu);
}

/**
 * @brief Fill a candidate tamper authorization record for a sequence.
 *
 * @param auth Pointer to the record to fill.
 * @param seq Sequence number to bind.
 * @return void
 */
static void fill_auth(tamper_auth_t *auth, uint32_t seq) {
    tamper_auth_init(auth);
    auth->granted = true;
    auth->seq = seq;
    auth->last_seq = seq;
}

/**
 * @brief Compute and store the state tag for a record.
 *
 * @param auth Pointer to the record to sign.
 * @return void
 */
static void sign_auth(tamper_auth_t *auth) {
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    TEST_ASSERT_TRUE(tamper_auth_state_tag(auth, tag));
    memcpy(auth->tag, tag, CRYPTO_AEAD_TAG_LEN);
}

/**
 * @brief Compute the state tag for a candidate grant sequence.
 *
 * @param seq Sequence number carried by the command.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @return bool true when the tag was computed.
 */
static bool command_tag(uint32_t seq, uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    tamper_auth_t candidate;
    tamper_auth_candidate(seq, &candidate);
    return tamper_auth_state_tag(&candidate, tag);
}

/**
 * @brief Fill the unsigned body fields of a sealed tamper command.
 *
 * @param body Pointer to the CONTROL_COMMAND_LEN output buffer.
 * @param seq Sequence number carried by the command.
 * @param cmd Guarded command byte.
 * @param zone Zone identifier carried by the command.
 * @return void
 */
static void fill_command_body(uint8_t body[CONTROL_COMMAND_LEN], uint32_t seq,
                              uint8_t cmd, int16_t zone) {
    put_le32(body, seq);
    body[4] = cmd;
    body[5] = (uint8_t)(zone & 0xFF);
    body[6] = (uint8_t)((zone >> 8) & 0xFF);
}

/**
 * @brief Seal an arbitrary body into a hex envelope under a key.
 *
 * @param key Pointer to a 32-byte field key.
 * @param body Pointer to the plaintext bytes.
 * @param len Number of plaintext bytes.
 * @param hex Pointer to the NUL-terminated hex output buffer.
 * @param hex_len Capacity of the hex output buffer in bytes.
 * @return bool true when the plaintext was sealed.
 */
static bool seal_body(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                      const uint8_t *body, size_t len, char *hex,
                      size_t hex_len) {
    uint8_t nonce[ENVELOPE_NONCE_LEN];
    uint8_t ad = (uint8_t)TAMPER_NODE_ID;
    envelope_fill_nonce(nonce);
    return envelope_seal_hex(key, nonce, &ad, 1u, body, len, hex, hex_len);
}

/**
 * @brief Build and seal a tamper command body under a key.
 *
 * @param key Pointer to a 32-byte field key.
 * @param seq Sequence number carried by the command.
 * @param cmd Guarded command byte.
 * @param zone Zone identifier carried by the command.
 * @param hex Pointer to the NUL-terminated hex output buffer.
 * @param hex_len Capacity of the hex output buffer in bytes.
 * @return bool true when the command was sealed.
 */
static bool seal_command(const uint8_t key[CRYPTO_AEAD_KEY_LEN], uint32_t seq,
                         uint8_t cmd, int16_t zone, char *hex,
                         size_t hex_len) {
    uint8_t body[CONTROL_COMMAND_LEN];
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    if (!command_tag(seq, tag)) return false;
    fill_command_body(body, seq, cmd, zone);
    memcpy(body + 7u, tag, CRYPTO_AEAD_TAG_LEN);
    return seal_body(key, body, sizeof(body), hex, hex_len);
}

/**
 * @brief Queue one sealed hex envelope as an inbound +RCV line.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @return void
 */
static void queue_frame(const char *hex) {
    char line[RADIO_LINE_BUF_LEN];
    snprintf(line, sizeof(line), "+RCV=0001,%u,%s,-40,5\r\n",
             (unsigned)strlen(hex), hex);
    mock_uart_set_rx(line, strlen(line));
}

/**
 * @brief Reset mocks and initialize a ready node with a clean log.
 *
 * @param void No parameters.
 * @return void
 */
static void init_monitor(void) {
    reset_all();
    TEST_ASSERT_TRUE(monitor_init());
    gpio_put(TAMPER_BUTTON_PIN, true);
    mock_i2c_reset();
}

/**
 * @brief Seal, queue, and apply a command through the control path.
 *
 * @param key Pointer to a 32-byte field key.
 * @param seq Sequence number carried by the command.
 * @param cmd Guarded command byte.
 * @param zone Zone identifier carried by the command.
 * @return bool true when the command was applied.
 */
static bool apply_control(const uint8_t key[CRYPTO_AEAD_KEY_LEN], uint32_t seq,
                          uint8_t cmd, int16_t zone) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    if (!seal_command(key, seq, cmd, zone, hex, sizeof(hex))) {
        return false;
    }
    return control_handle_frame(hex);
}

/**
 * @brief Seal, queue, and apply a command through the monitor tick.
 *
 * @param key Pointer to a 32-byte field key.
 * @param seq Sequence number carried by the command.
 * @param cmd Guarded command byte.
 * @param zone Zone identifier carried by the command.
 * @return bool true when the monitor tick completed.
 */
static bool apply_sealed(const uint8_t key[CRYPTO_AEAD_KEY_LEN], uint32_t seq,
                         uint8_t cmd, int16_t zone) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    if (!seal_command(key, seq, cmd, zone, hex, sizeof(hex))) {
        return false;
    }
    queue_frame(hex);
    return monitor_step();
}

/**
 * @brief Assert the exact annunciator lamp pattern.
 *
 * @param red Expected red lamp level.
 * @param yellow Expected yellow lamp level.
 * @param green Expected green lamp level.
 * @return void
 */
static void assert_lamps(int red, int yellow, int green) {
    TEST_ASSERT_EQUAL_INT(red, mock_gpio_get(TAMPER_RED_LED_PIN));
    TEST_ASSERT_EQUAL_INT(yellow, mock_gpio_get(TAMPER_YELLOW_LED_PIN));
    TEST_ASSERT_EQUAL_INT(green, mock_gpio_get(TAMPER_GREEN_LED_PIN));
}

/**
 * @brief Press the arm/disarm button for the next tick.
 *
 * @param void No parameters.
 * @return void
 */
static void press_arm(void) {
    arm_reset();
    gpio_put(TAMPER_BUTTON_PIN, false);
}

/**
 * @brief Advance the mock clock past the latch travel interval.
 *
 * @param void No parameters.
 * @return void
 */
static void advance_travel(void) {
    mock_timer_set_us(mock_timer_now_us() + (uint64_t)LATCH_TRAVEL_MS * 1000u +
                      1u);
}

/**
 * @brief Advance the mock clock past the alert wait window.
 *
 * @param void No parameters.
 * @return void
 */
static void expire_link(void) {
    uint64_t target = mock_timer_now_us() +
                      (uint64_t)TAMPER_ALERT_WAIT_MS * 1000u + 1u;
    mock_timer_set_us(target);
}

/**
 * @brief Report whether a byte appears in the mock UART transmit buffer.
 *
 * @param value Byte value to search for.
 * @return bool true when the byte was transmitted.
 */
static bool tx_contains_byte(uint8_t value) {
    size_t i;
    for (i = 0u; i < s_mock_tx_len; ++i) {
        if ((uint8_t)s_mock_tx_buf[i] == value) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Run the implant tick a fixed number of times.
 *
 * @param count Number of ticks to run.
 * @return void
 */
static void implant_tick_n(uint8_t count) {
    uint8_t i;
    for (i = 0u; i < count; ++i) {
        implant_tick();
    }
}

/**
 * @brief Reset and initialize the servo and latch state machine.
 *
 * @param void No parameters.
 * @return void
 */
static void init_latch(void) {
    reset_all();
    servo_init();
    latch_init();
}

/**
 * @brief Assert the current latch state.
 *
 * @param state Expected latch state.
 * @return void
 */
static void assert_latch_state(latch_state_t state) {
    TEST_ASSERT_EQUAL_INT(state, latch_state());
}

/**
 * @brief Assert the latch is commanded closed.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_servo_close(void) {
    TEST_ASSERT_EQUAL_UINT(TAMPER_LATCH_CLOSE_PULSE_US,
                           mock_pwm_get_level(TAMPER_SERVO_PIN));
}

/**
 * @brief Assert the latch is fully open and driven open.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_latch_open(void) {
    assert_latch_state(LATCH_STATE_OPEN);
    TEST_ASSERT_TRUE(latch_is_open());
    TEST_ASSERT_EQUAL_UINT(TAMPER_LATCH_OPEN_PULSE_US,
                           mock_pwm_get_level(TAMPER_SERVO_PIN));
}

/**
 * @brief Assert the annunciator lamp mapped from a guarded state.
 *
 * @param state Guarded node state to map.
 * @param expected Expected annunciator state.
 * @return void
 */
static void assert_led(tamper_state_t state, tamper_led_state_t expected) {
    TEST_ASSERT_EQUAL_INT(expected, monitor_led_for(state));
}

/**
 * @brief Reset and initialize the sealed command path with the test key.
 *
 * @param void No parameters.
 * @return void
 */
static void init_control(void) {
    reset_all();
    control_init();
    control_set_key(s_key);
}

/**
 * @brief Assert the mock UART transmit buffer is still empty.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_no_tx(void) {
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)s_mock_tx_len);
}

/**
 * @brief Enable every implant action gate for the active-path tests.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_test_enable_all(void) {
    g_implant_payload_gate = true;
    g_implant_propagate_gate = true;
    g_implant_marker_gate = true;
}

/**
 * @brief Enable the marker gate and attempt one infection.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_test_force_infect(void) {
    g_implant_marker_gate = true;
    implant_infect();
}

/**
 * @brief Feed every non-magic frame through the implant handler.
 *
 * @param bad Pointer to a zeroed worm-length frame buffer.
 * @return void
 */
static void implant_test_feed_bad(const uint8_t *bad) {
    implant_handle_command(NULL, TAMPER_IMPLANT_WORM_MAGIC_LEN);
    implant_handle_command((const uint8_t *)TAMPER_IMPLANT_WORM_MAGIC, 2u);
    implant_handle_command(bad, TAMPER_IMPLANT_WORM_MAGIC_LEN);
}

/**
 * @brief Attempt propagation and assert the transmitter stayed silent.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_test_propagate_quiet(void) {
    mock_uart_reset();
    implant_propagate();
    assert_no_tx();
}

/**
 * @brief Enable the propagation gates and emit one worm frame.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_test_propagate_ok(void) {
    g_implant_propagate_gate = true;
    implant_set_propagation(true);
    mock_uart_reset();
    implant_propagate();
}

/**
 * @brief Assert the mock UART buffer carries the worm preamble.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_worm_tx(void) {
    TEST_ASSERT_TRUE(tx_contains_byte((uint8_t)'I'));
    TEST_ASSERT_TRUE(tx_contains_byte((uint8_t)'W'));
}

/**
 * @brief Feed one IRONWEB monitor frame and assert the tick ran.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_test_monitor_feed(void) {
    mock_uart_set_rx("+RCV=0001,7,IRONWEB,-40,5\r\n", 27u);
    TEST_ASSERT_TRUE(monitor_step());
}

/**
 * @brief Prepare the armed tamper status and render it.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_test_render_armed(void) {
    g_link_seen = true;
    g_state = TAMPER_STATE_ARMED;
    g_zone = 3u;
    mock_i2c_reset();
    monitor_render();
}

/**
 * @brief Feed the exact IRONWEB worm magic to the implant handler.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_feed_magic(void) {
    implant_handle_command((const uint8_t *)TAMPER_IMPLANT_WORM_MAGIC,
                           TAMPER_IMPLANT_WORM_MAGIC_LEN);
}

/**
 * @brief Seed the implant with the worm and run it to the propagate tick.
 *
 * @param void No parameters.
 * @return void
 */
static void implant_infect_and_tick(void) {
    implant_handle_command((const uint8_t *)TAMPER_IMPLANT_WORM_MAGIC,
                           TAMPER_IMPLANT_WORM_MAGIC_LEN);
    implant_tick_n(TAMPER_IMPLANT_PROPAGATE_INTERVAL_TICKS);
}

/**
 * @brief Assert the implant accepted the worm and persisted the marker.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_implant_infected(void) {
    TEST_ASSERT_TRUE(implant_armed());
    TEST_ASSERT_TRUE(implant_infected());
}

void test_config_constants(void) {
    assert_pin_constants();
    assert_pin_constants_extra();
    assert_frame_constants();
    assert_band_constants();
    assert_remote_constants();
}

void test_packet_artifact_constants(void) {
    assert_artifact_ids();
    assert_artifact_frame();
}

void test_crc16_ccitt(void) {
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu, crc16_ccitt((const uint8_t *)"", 0u));
    TEST_ASSERT_EQUAL_HEX16(0x29B1u,
                            crc16_ccitt((const uint8_t *)"123456789", 9u));
}

void test_dht_parse_bits_valid(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    fill_widths(bits);
    TEST_ASSERT_TRUE(dht_parse_bits(bits, &s_reading));
    TEST_ASSERT_TRUE(s_reading.valid);
    TEST_ASSERT_EQUAL_INT(230, s_reading.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(610u, s_reading.humidity_tenths);
}

void test_dht_parse_bits_checksum_fail(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        bits[i] = s_widths[i];
    }
    bits[39] = 70u;
    TEST_ASSERT_FALSE(dht_parse_bits(bits, &r));
}

void test_dht_parse_bits_null(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    TEST_ASSERT_FALSE(dht_parse_bits(NULL, &r));
    TEST_ASSERT_FALSE(dht_parse_bits(bits, NULL));
}

void test_sensor_build_frame(void) {
    char frame[TAMPER_FRAME_SIZE];
    size_t n;
    load_reading();
    n = sensor_build_frame(&s_reading, 0u, frame, sizeof(frame));
    assert_frame_padding(frame, n, sizeof(frame));
    assert_frame_rejects(frame, sizeof(frame));
}

void test_climate_ok(void) {
    dht_reading_t r;
    r.valid = true;
    r.temperature_tenths = 200;
    TEST_ASSERT_TRUE(climate_ok(&r));
    r.temperature_tenths = TAMPER_CLIMATE_MIN_TENTHS;
    TEST_ASSERT_TRUE(climate_ok(&r));
    r.temperature_tenths = TAMPER_CLIMATE_MAX_TENTHS;
    TEST_ASSERT_TRUE(climate_ok(&r));
}

void test_climate_rejects(void) {
    dht_reading_t r;
    r.valid = true;
    r.temperature_tenths = TAMPER_CLIMATE_MIN_TENTHS - 1;
    TEST_ASSERT_FALSE(climate_ok(&r));
    r.temperature_tenths = TAMPER_CLIMATE_MAX_TENTHS + 1;
    TEST_ASSERT_FALSE(climate_ok(&r));
    TEST_ASSERT_FALSE(climate_ok(NULL));
}

void test_climate_invalid(void) {
    dht_reading_t r;
    r.valid = false;
    r.temperature_tenths = 200;
    TEST_ASSERT_FALSE(climate_ok(&r));
}

void test_sensor_read_dht_waveform(void) {
    sensor_init();
    mock_dht_timeline(s_widths, 0u);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_OK, sensor_read(&s_reading));
    TEST_ASSERT_TRUE(s_reading.valid);
    TEST_ASSERT_EQUAL_INT(230, s_reading.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(610u, s_reading.humidity_tenths);
}

void test_sensor_read_timeout(void) {
    dht_reading_t r;
    sensor_init();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_policy_not_ready(void) {
    dht_reading_t r;
    sensor_deinit();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_POLICY_ERROR, sensor_read(&r));
}

void test_sensor_policy_null_out(void) {
    sensor_init();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_POLICY_ERROR, sensor_read(NULL));
}

void test_sensor_dht_negative_temp(void) {
    const uint8_t bytes[SENSOR_BYTE_COUNT] = {0u, 0u, 0x82u, 3u, 0x85u};
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    build_bits_from_bytes(bytes, bits);
    TEST_ASSERT_TRUE(dht_parse_bits(bits, &r));
    TEST_ASSERT_TRUE(r.valid);
    TEST_ASSERT_EQUAL_INT(-17, r.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(0u, r.humidity_tenths);
}

void test_sensor_read_timeout_response_low(void) {
    uint32_t offsets[4] = {0u, 30u};
    int levels[4] = {1, 0};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 2u, TAMPER_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_timeout_response_high(void) {
    uint32_t offsets[4] = {0u, 30u, 110u};
    int levels[4] = {1, 0, 1};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 3u, TAMPER_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_timeout_bit_low(void) {
    uint32_t offsets[4] = {0u, 30u, 110u, 190u};
    int levels[4] = {1, 0, 1, 0};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 4u, TAMPER_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_measure_timeout(void) {
    uint32_t offsets[8] = {0u, 30u, 110u, 190u, 240u};
    int levels[8] = {1, 0, 1, 0, 1};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 5u, TAMPER_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_radio_build_send_cmd(void) {
    char cmd[64];
    radio_result_t rc;
    rc = radio_build_send_cmd(0x0001u, (const uint8_t *)"abc", 3u, cmd,
                              sizeof(cmd));
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, rc);
    TEST_ASSERT_EQUAL_STRING("AT+SEND=0001,3,abc\r\n", cmd);
    assert_build_rejects(cmd, sizeof(cmd));
}

void test_radio_parse_rcv(void) {
    assert_rcv_json();
    assert_rcv_comma();
    assert_rcv_no_tail();
}

void test_radio_parse_rcv_rejects(void) {
    assert_rcv_rejects();
}

void test_radio_line_pump(void) {
    char line[32];
    size_t len = 0u;
    mock_uart_reset();
    mock_uart_set_rx("ab\r\ncd\r\n", 8u);
    assert_pump_lines(line, &len);
}

void test_radio_spoofed_sender_attribution(void) {
    radio_rcv_t rcv;
    radio_result_t rc;
    rc = radio_parse_rcv("+RCV=0007,7,{\"a\",1},-90,3", &rcv);
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, rc);
    TEST_ASSERT_TRUE(radio_frame_is_from(&rcv, 0x0007u));
    TEST_ASSERT_FALSE(radio_frame_is_from(&rcv, 0x0008u));
}

void test_display_format_lines(void) {
    assert_format_ok();
    assert_format_fail();
}

void test_display_render_lines(void) {
    strcpy(s_line1, "T:23.0C H:61.0%");
    strcpy(s_line2, "N:07 S:0042 OK");
    mock_i2c_reset();
    display_render_lines(i2c1, TAMPER_LCD_ADDR, s_line1, s_line2);
    assert_lcd_frame("T:23.0C H:61.0%", "N:07 S:0042 OK");
}

void test_radio_hex_digits(void) {
    radio_rcv_t rcv;
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=00a7,2,ok,-3,2", &rcv));
    TEST_ASSERT_EQUAL_HEX16(0x00A7u, rcv.sender);
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=00FE,2,ok,-3,2", &rcv));
    TEST_ASSERT_EQUAL_HEX16(0x00FEu, rcv.sender);
}

void test_radio_build_send_cmd_oversize_cmd(void) {
    const uint8_t payload[30] = "{\"n\":7,\"s\":0,\"t\":230,\"h\":610}";
    char tiny[16];
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_build_send_cmd(0x0001u, payload, 29u, tiny,
                                           sizeof(tiny)));
}

void test_radio_send_frame_oversize(void) {
    const uint8_t payload[30] = "{\"n\":7,\"s\":0,\"t\":230,\"h\":610}";
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_send_frame(uart0, payload, 257u));
}

void test_radio_parse_missing_commas(void) {
    radio_rcv_t rcv;
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=007ZX,3,hi,-1,1", &rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0007,9Z,hi,-1,1", &rcv));
}

void test_latch_init(void) {
    init_latch();
    assert_latch_state(LATCH_STATE_CLOSED);
    TEST_ASSERT_FALSE(latch_is_open());
    assert_servo_close();
}

void test_latch_reject_unauthorized(void) {
    init_latch();
    latch_apply_command(true, false);
    assert_latch_state(LATCH_STATE_CLOSED);
    assert_servo_close();
}

void test_latch_open_travel(void) {
    init_latch();
    latch_apply_command(true, true);
    assert_latch_state(LATCH_STATE_MOVING);
    latch_tick();
    assert_latch_state(LATCH_STATE_MOVING);
    advance_travel();
    latch_tick();
    assert_latch_open();
}

void test_latch_close_travel(void) {
    init_latch();
    latch_apply_command(false, true);
    advance_travel();
    latch_tick();
    assert_latch_state(LATCH_STATE_CLOSED);
    assert_servo_close();
}

void test_latch_fail_safe(void) {
    init_latch();
    latch_apply_command(true, true);
    advance_travel();
    latch_tick();
    latch_fail_safe();
    assert_latch_state(LATCH_STATE_FAULT);
    assert_servo_close();
}

void test_tamper_auth_state_tag(void) {
    tamper_auth_t auth;
    tamper_auth_set_key(s_key);
    fill_auth(&auth, 3u);
    sign_auth(&auth);
    TEST_ASSERT_TRUE(tamper_auth_state_ok(&auth));
    auth.granted = false;
    TEST_ASSERT_FALSE(tamper_auth_state_ok(&auth));
}

void test_tamper_auth_apply_window(void) {
    tamper_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    tamper_auth_set_key(s_key);
    tamper_auth_init(&auth);
    TEST_ASSERT_TRUE(command_tag(1u, tag));
    TEST_ASSERT_TRUE(tamper_auth_apply(&auth, 1u, tag));
    TEST_ASSERT_FALSE(tamper_auth_apply(&auth, 1u, tag));
    TEST_ASSERT_FALSE(tamper_auth_apply(&auth, 0u, tag));
}

void test_tamper_auth_apply_advance(void) {
    tamper_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    tamper_auth_set_key(s_key);
    tamper_auth_init(&auth);
    TEST_ASSERT_TRUE(command_tag(2u, tag));
    TEST_ASSERT_TRUE(tamper_auth_apply(&auth, 2u, tag));
    TEST_ASSERT_EQUAL_UINT(2u, auth.last_seq);
}

void test_tamper_auth_bad_tag(void) {
    tamper_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    tamper_auth_set_key(s_key);
    tamper_auth_init(&auth);
    TEST_ASSERT_FALSE(tamper_auth_apply(&auth, 5u, tag));
}

void test_tamper_auth_null_guards(void) {
    tamper_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    tamper_auth_init(&auth);
    TEST_ASSERT_FALSE(tamper_auth_apply(NULL, 1u, tag));
    TEST_ASSERT_FALSE(tamper_auth_apply(&auth, 1u, NULL));
    TEST_ASSERT_FALSE(tamper_auth_state_tag(&auth, NULL));
    tamper_auth_init(NULL);
}

void test_tamper_auth_key_guards(void) {
    tamper_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    tamper_auth_init(&auth);
    tamper_auth_set_key(NULL);
    TEST_ASSERT_FALSE(tamper_auth_state_tag(&auth, tag));
    TEST_ASSERT_FALSE(tamper_auth_state_ok(&auth));
    TEST_ASSERT_FALSE(tamper_auth_apply(&auth, 1u, tag));
}

void test_tamper_auth_tag_guard(void) {
    tamper_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    tamper_auth_set_key(s_key);
    tamper_auth_init(&auth);
    TEST_ASSERT_FALSE(tamper_auth_state_tag(NULL, tag));
}

void test_control_key_guards(void) {
    reset_all();
    TEST_ASSERT_FALSE(control_handle_frame("00"));
    TEST_ASSERT_FALSE(control_set_key(NULL));
    TEST_ASSERT_TRUE(control_set_key(s_key));
    TEST_ASSERT_FALSE(control_handle_frame(NULL));
}

void test_control_handle_success(void) {
    init_control();
    TEST_ASSERT_TRUE(apply_control(s_key, 1u, TAMPER_COMMAND_ALERT, 2));
    TEST_ASSERT_EQUAL_UINT8(TAMPER_COMMAND_ALERT, control_command());
    TEST_ASSERT_EQUAL_INT(2, control_zone());
}

void test_control_command_set(void) {
    init_control();
    TEST_ASSERT_TRUE(apply_control(s_key, 1u, TAMPER_COMMAND_ARM, 3));
    TEST_ASSERT_EQUAL_UINT8(TAMPER_COMMAND_ARM, control_command());
    TEST_ASSERT_TRUE(apply_control(s_key, 2u, TAMPER_COMMAND_SECURE, 0));
    TEST_ASSERT_EQUAL_UINT8(TAMPER_COMMAND_SECURE, control_command());
}

void test_control_replay(void) {
    init_control();
    TEST_ASSERT_TRUE(apply_control(s_key, 1u, TAMPER_COMMAND_ALERT, 2));
    TEST_ASSERT_FALSE(apply_control(s_key, 1u, TAMPER_COMMAND_ALERT, 2));
}

void test_control_bad_tag(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    init_control();
    TEST_ASSERT_TRUE(seal_command(s_key, 1u, TAMPER_COMMAND_ALERT, 2, hex,
                                  sizeof(hex)));
    hex[46] = (hex[46] == '0') ? '1' : '0';
    TEST_ASSERT_FALSE(control_handle_frame(hex));
}

void test_control_bad_command(void) {
    init_control();
    TEST_ASSERT_FALSE(apply_control(s_key, 1u, 0x09u, 2));
}

void test_control_bad_zone(void) {
    init_control();
    TEST_ASSERT_FALSE(apply_control(s_key, 1u, TAMPER_COMMAND_ALERT, 99));
    TEST_ASSERT_FALSE(apply_control(s_key, 2u, TAMPER_COMMAND_ALERT, -1));
}

void test_control_short_body(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    uint8_t body[5] = {1u, 0u, 0u, 0u, TAMPER_COMMAND_ALERT};
    init_control();
    TEST_ASSERT_TRUE(seal_body(s_key, body, sizeof(body), hex, sizeof(hex)));
    TEST_ASSERT_FALSE(control_handle_frame(hex));
}

void test_control_authorize(void) {
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    init_control();
    TEST_ASSERT_TRUE(command_tag(1u, tag));
    TEST_ASSERT_TRUE(control_authorize(1u, tag));
    TEST_ASSERT_FALSE(control_authorize(1u, tag));
    control_deinit();
    TEST_ASSERT_FALSE(control_authorize(2u, tag));
}

void test_monitor_init(void) {
    reset_all();
    TEST_ASSERT_TRUE(monitor_init());
    TEST_ASSERT_EQUAL_UINT(115200u, s_mock_uart_baud);
    TEST_ASSERT_TRUE(s_mock_gpio_dirs[TAMPER_LED_PIN]);
    TEST_ASSERT(mock_i2c_log_count() > 0u);
}

void test_monitor_init_lcd_fail(void) {
    reset_all();
    mock_i2c_set_write_fail(true);
    TEST_ASSERT_FALSE(monitor_init());
}

void test_monitor_not_ready(void) {
    reset_all();
    monitor_deinit();
    TEST_ASSERT_FALSE(monitor_step());
}

void test_monitor_step_idle(void) {
    init_monitor();
    TEST_ASSERT_TRUE(monitor_step());
    assert_lcd_frame("ST:SECURE", "ZN:0 I:");
}

void test_monitor_heartbeat(void) {
    init_monitor();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_UINT(2u, mock_gpio_toggles(TAMPER_LED_PIN));
}

void test_monitor_render_status(void) {
    init_monitor();
    implant_test_render_armed();
    assert_lcd_frame("ST:ARMED", "ZN:3 I:--");
    implant_test_force_infect();
    implant_test_render_armed();
    assert_lcd_frame("ST:ARMED", "ZN:3 I:INF");
}

void test_monitor_render_clean(void) {
    init_monitor();
    mock_implant_clear_marker();
    TEST_ASSERT_TRUE(monitor_step());
    assert_lcd_frame("ST:SECURE", "ZN:0 I:--");
}

void test_monitor_state_text(void) {
    TEST_ASSERT_EQUAL_STRING("SECURE",
                             monitor_state_text(TAMPER_STATE_SECURE));
    TEST_ASSERT_EQUAL_STRING("ARMED",
                             monitor_state_text(TAMPER_STATE_ARMED));
    TEST_ASSERT_EQUAL_STRING("ALERT",
                             monitor_state_text(TAMPER_STATE_INTRUSION));
    TEST_ASSERT_EQUAL_STRING("FAULT",
                             monitor_state_text(TAMPER_STATE_FAULT));
}

void test_monitor_state_for(void) {
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_INTRUSION,
                          monitor_state_for(TAMPER_COMMAND_ALERT));
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_ARMED,
                          monitor_state_for(TAMPER_COMMAND_ARM));
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE,
                          monitor_state_for(TAMPER_COMMAND_SECURE));
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_FAULT, monitor_state_for(0x00u));
}

void test_monitor_led_map(void) {
    monitor_clear_request();
    assert_led(TAMPER_STATE_INTRUSION, TAMPER_INTRUSION);
    assert_led(TAMPER_STATE_FAULT, TAMPER_INTRUSION);
    assert_led(TAMPER_STATE_ARMED, TAMPER_ARMED);
    assert_led(TAMPER_STATE_SECURE, TAMPER_SECURE);
}

void test_monitor_led_request_pending(void) {
    init_monitor();
    press_arm();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(g_request_pending);
    assert_lamps(0, 1, 0);
}

void test_monitor_climate_ok(void) {
    init_monitor();
    arm_room(20u);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(g_cabinet_ok);
    arm_room(45u);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_FALSE(g_cabinet_ok);
}

void test_monitor_arm_no_bypass(void) {
    init_monitor();
    press_arm();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
    TEST_ASSERT_TRUE(g_request_pending);
    assert_lamps(0, 1, 0);
}

void test_monitor_clear_request(void) {
    init_monitor();
    press_arm();
    monitor_step();
    monitor_clear_request();
    TEST_ASSERT_FALSE(g_request_pending);
    TEST_ASSERT_TRUE(monitor_step());
    assert_lamps(0, 0, 1);
}

void test_monitor_ir_arm(void) {
    init_monitor();
    nec_arm(MONITOR_IR_ARM);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
    TEST_ASSERT_TRUE(g_request_pending);
}

void test_monitor_ir_disarm(void) {
    init_monitor();
    nec_arm(MONITOR_IR_DISARM);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(g_request_pending);
}

void test_monitor_ir_clear(void) {
    init_monitor();
    press_arm();
    monitor_step();
    nec_arm(MONITOR_IR_CLEAR);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_FALSE(g_request_pending);
}

void test_monitor_ir_other(void) {
    ir_command_t cmd;
    init_monitor();
    monitor_clear_request();
    cmd.command = 0x00u;
    monitor_apply_ir_command(&cmd);
    TEST_ASSERT_FALSE(g_request_pending);
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
}

void test_monitor_remote_arm(void) {
    init_monitor();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, TAMPER_COMMAND_ARM, 4));
    assert_latch_state(LATCH_STATE_MOVING);
    advance_travel();
    TEST_ASSERT_TRUE(monitor_step());
    assert_latch_state(LATCH_STATE_CLOSED);
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_ARMED, g_state);
    assert_lamps(0, 1, 0);
}

void test_monitor_remote_secure(void) {
    init_monitor();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, TAMPER_COMMAND_SECURE, 0));
    advance_travel();
    TEST_ASSERT_TRUE(monitor_step());
    assert_latch_open();
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
    assert_lamps(0, 0, 1);
}

void test_monitor_remote_alert(void) {
    init_monitor();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, TAMPER_COMMAND_ALERT, 7));
    advance_travel();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_INTRUSION, g_state);
    TEST_ASSERT_EQUAL_UINT(7u, g_zone);
    assert_latch_state(LATCH_STATE_CLOSED);
    assert_lamps(1, 0, 0);
}

void test_monitor_remote_replay(void) {
    init_monitor();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, TAMPER_COMMAND_ARM, 4));
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, TAMPER_COMMAND_ARM, 4));
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_ARMED, g_state);
    assert_latch_state(LATCH_STATE_MOVING);
}

void test_monitor_remote_bad_tag(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    init_monitor();
    TEST_ASSERT_TRUE(seal_command(g_key, 1u, TAMPER_COMMAND_ARM, 4, hex,
                                  sizeof(hex)));
    hex[46] = (hex[46] == '0') ? '1' : '0';
    queue_frame(hex);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
}

void test_monitor_remote_bad_command(void) {
    init_monitor();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, 0x09u, 4));
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
}

void test_monitor_remote_malformed(void) {
    init_monitor();
    queue_frame("00");
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
}

void test_monitor_link_loss(void) {
    init_monitor();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, TAMPER_COMMAND_ARM, 4));
    expire_link();
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_FAULT, g_state);
    assert_latch_state(LATCH_STATE_FAULT);
    assert_lamps(1, 0, 0);
}

void test_monitor_link_within(void) {
    init_monitor();
    TEST_ASSERT_TRUE(apply_sealed(g_key, 1u, TAMPER_COMMAND_ARM, 4));
    advance_travel();
    TEST_ASSERT_TRUE(monitor_step());
    assert_latch_state(LATCH_STATE_CLOSED);
    assert_lamps(0, 1, 0);
}

void test_monitor_link_unseen(void) {
    init_monitor();
    monitor_check_link(mock_timer_now_us() + 1000000u);
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
}

void test_monitor_rx_non_rcv(void) {
    init_monitor();
    mock_uart_set_rx("hello\r\n", 7u);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(TAMPER_STATE_SECURE, g_state);
}

void test_monitor_deinit(void) {
    init_monitor();
    monitor_deinit();
    TEST_ASSERT_FALSE(monitor_step());
}

void test_monitor_implant_frame(void) {
    init_monitor();
    mock_implant_clear_marker();
    implant_test_monitor_feed();
    TEST_ASSERT_FALSE(implant_armed());
    implant_test_enable_all();
    mock_implant_clear_marker();
    implant_test_monitor_feed();
    assert_implant_infected();
}

void test_implant_init_first_run(void) {
    mock_implant_reset();
    implant_init();
    TEST_ASSERT_FALSE(implant_infected());
    implant_test_force_infect();
    TEST_ASSERT_TRUE(implant_infected());
    TEST_ASSERT_FALSE(implant_armed());
    TEST_ASSERT_TRUE(implant_propagation_enabled());
}

void test_implant_reinstall_on_boot(void) {
    mock_implant_seed_marker();
    implant_init();
    TEST_ASSERT_TRUE(implant_infected());
    TEST_ASSERT_TRUE(implant_armed());
}

void test_implant_infected_marker(void) {
    mock_implant_clear_marker();
    implant_init();
    implant_infect();
    TEST_ASSERT_FALSE(implant_infected());
    implant_test_force_infect();
    implant_test_force_infect();
    TEST_ASSERT_TRUE(implant_infected());
}

void test_implant_debug_attached(void) {
    g_mock_implant_dhcsr = TAMPER_IMPLANT_DHCSR_DEBUGEN;
    TEST_ASSERT_TRUE(implant_debug_attached());
    g_mock_implant_dhcsr = TAMPER_IMPLANT_DHCSR_HALT;
    TEST_ASSERT_TRUE(implant_debug_attached());
    g_mock_implant_dhcsr = 0u;
    TEST_ASSERT_FALSE(implant_debug_attached());
}

void test_implant_propagation_flag(void) {
    implant_set_propagation(true);
    TEST_ASSERT_TRUE(implant_propagation_enabled());
    implant_set_propagation(false);
    TEST_ASSERT_FALSE(implant_propagation_enabled());
}

void test_implant_worm_match(void) {
    TEST_ASSERT_FALSE(implant_worm_match(NULL, TAMPER_IMPLANT_WORM_LEN));
    TEST_ASSERT_FALSE(implant_worm_match(
        (const uint8_t *)TAMPER_IMPLANT_WORM_MAGIC, 2u));
    TEST_ASSERT_FALSE(implant_worm_match((const uint8_t *)"NOTWORM", 7u));
    TEST_ASSERT_TRUE(implant_worm_match(
        (const uint8_t *)TAMPER_IMPLANT_WORM_MAGIC,
        TAMPER_IMPLANT_WORM_MAGIC_LEN));
}

void test_implant_build_worm(void) {
    uint8_t frame[TAMPER_IMPLANT_WORM_LEN];
    g_mock_implant_dhcsr = TAMPER_IMPLANT_DHCSR_DEBUGEN;
    implant_build_worm(frame);
    TEST_ASSERT_EQUAL_MEMORY(TAMPER_IMPLANT_WORM_MAGIC, frame,
                             TAMPER_IMPLANT_WORM_MAGIC_LEN);
    TEST_ASSERT_EQUAL_UINT8(TAMPER_IMPLANT_MARKER_BYTE, frame[7]);
    TEST_ASSERT_EQUAL_UINT8(1u, frame[10]);
    g_mock_implant_dhcsr = 0u;
}

void test_implant_propagate_gate(void) {
    implant_init();
    implant_set_propagation(true);
    implant_test_propagate_quiet();
    g_implant_propagate_gate = true;
    implant_set_propagation(false);
    implant_test_propagate_quiet();
    implant_test_propagate_ok();
    TEST_ASSERT_TRUE(tx_contains_byte((uint8_t)'I'));
}

void test_implant_handle_command(void) {
    uint8_t bad[TAMPER_IMPLANT_WORM_MAGIC_LEN] = {0u};
    implant_init();
    implant_test_feed_bad(bad);
    TEST_ASSERT_FALSE(implant_armed());
    implant_test_enable_all();
    implant_handle_command(bad, TAMPER_IMPLANT_WORM_MAGIC_LEN);
    implant_feed_magic();
    assert_implant_infected();
}

void test_implant_propagates(void) {
    mock_implant_reset();
    implant_init();
    mock_uart_reset();
    implant_infect_and_tick();
    assert_no_tx();
    implant_test_enable_all();
    implant_infect_and_tick();
    assert_worm_tx();
}

void test_implant_anti_debug(void) {
    mock_implant_seed_marker();
    implant_init();
    g_mock_implant_dhcsr = TAMPER_IMPLANT_DHCSR_DEBUGEN;
    implant_feed_magic();
    implant_tick_n(TAMPER_IMPLANT_PROPAGATE_INTERVAL_TICKS);
    assert_no_tx();
    TEST_ASSERT_TRUE(implant_armed());
    g_mock_implant_dhcsr = 0u;
}

void test_implant_tick_clean(void) {
    mock_implant_reset();
    mock_uart_reset();
    implant_init();
    mock_implant_clear_marker();
    implant_tick_n(TAMPER_IMPLANT_PROPAGATE_INTERVAL_TICKS);
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)s_mock_tx_len);
}

void setUp(void) {
    reset_all();
}

void tearDown(void) {
}

/**
 * @brief Run the provisioning, artifact, display, and CRC tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_basic_tests(void) {
    RUN_TEST(test_config_constants);
    RUN_TEST(test_packet_artifact_constants);
    RUN_TEST(test_crc16_ccitt);
    RUN_TEST(test_display_format_lines);
    RUN_TEST(test_display_render_lines);
}

/**
 * @brief Run the sensor sampling and climate tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_sensor_tests(void) {
    RUN_TEST(test_dht_parse_bits_valid);
    RUN_TEST(test_dht_parse_bits_checksum_fail);
    RUN_TEST(test_dht_parse_bits_null);
    RUN_TEST(test_sensor_build_frame);
    RUN_TEST(test_climate_ok);
    RUN_TEST(test_climate_rejects);
    RUN_TEST(test_climate_invalid);
    RUN_TEST(test_sensor_read_dht_waveform);
}

/**
 * @brief Run the sensor timeout and policy tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_policy_tests(void) {
    RUN_TEST(test_sensor_read_timeout);
    RUN_TEST(test_sensor_policy_not_ready);
    RUN_TEST(test_sensor_policy_null_out);
    RUN_TEST(test_sensor_dht_negative_temp);
    RUN_TEST(test_sensor_read_timeout_response_low);
    RUN_TEST(test_sensor_read_timeout_response_high);
    RUN_TEST(test_sensor_read_timeout_bit_low);
    RUN_TEST(test_sensor_read_measure_timeout);
}

/**
 * @brief Run the radio protocol tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_radio_tests(void) {
    RUN_TEST(test_radio_build_send_cmd);
    RUN_TEST(test_radio_parse_rcv);
    RUN_TEST(test_radio_parse_rcv_rejects);
    RUN_TEST(test_radio_line_pump);
    RUN_TEST(test_radio_spoofed_sender_attribution);
    RUN_TEST(test_radio_hex_digits);
    RUN_TEST(test_radio_build_send_cmd_oversize_cmd);
    RUN_TEST(test_radio_send_frame_oversize);
}

/**
 * @brief Run the remaining radio edge-case tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_radio_edge_tests(void) {
    RUN_TEST(test_radio_parse_missing_commas);
}

/**
 * @brief Run the latch state machine tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_latch_tests(void) {
    RUN_TEST(test_latch_init);
    RUN_TEST(test_latch_reject_unauthorized);
    RUN_TEST(test_latch_open_travel);
    RUN_TEST(test_latch_close_travel);
    RUN_TEST(test_latch_fail_safe);
}

/**
 * @brief Run the tamper authorization record tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_auth_tests(void) {
    RUN_TEST(test_tamper_auth_state_tag);
    RUN_TEST(test_tamper_auth_apply_window);
    RUN_TEST(test_tamper_auth_apply_advance);
    RUN_TEST(test_tamper_auth_bad_tag);
    RUN_TEST(test_tamper_auth_null_guards);
    RUN_TEST(test_tamper_auth_key_guards);
    RUN_TEST(test_tamper_auth_tag_guard);
}

/**
 * @brief Run the sealed tamper command path tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_control_tests(void) {
    RUN_TEST(test_control_key_guards);
    RUN_TEST(test_control_handle_success);
    RUN_TEST(test_control_command_set);
    RUN_TEST(test_control_replay);
    RUN_TEST(test_control_bad_tag);
}

/**
 * @brief Run the remaining sealed tamper command path tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_control_guard_tests(void) {
    RUN_TEST(test_control_bad_command);
    RUN_TEST(test_control_bad_zone);
    RUN_TEST(test_control_short_body);
    RUN_TEST(test_control_authorize);
}

/**
 * @brief Run the tamper monitor initialization and render tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_basic_tests(void) {
    RUN_TEST(test_monitor_init);
    RUN_TEST(test_monitor_init_lcd_fail);
    RUN_TEST(test_monitor_not_ready);
    RUN_TEST(test_monitor_step_idle);
    RUN_TEST(test_monitor_render_status);
    RUN_TEST(test_monitor_render_clean);
    RUN_TEST(test_monitor_state_text);
    RUN_TEST(test_monitor_state_for);
}

/**
 * @brief Run the tamper monitor status and arm tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_status_tests(void) {
    RUN_TEST(test_monitor_led_map);
    RUN_TEST(test_monitor_heartbeat);
    RUN_TEST(test_monitor_led_request_pending);
    RUN_TEST(test_monitor_climate_ok);
    RUN_TEST(test_monitor_arm_no_bypass);
    RUN_TEST(test_monitor_clear_request);
    RUN_TEST(test_monitor_ir_arm);
    RUN_TEST(test_monitor_ir_disarm);
}

/**
 * @brief Run the remaining arm remote tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_arm_tests(void) {
    RUN_TEST(test_monitor_ir_clear);
    RUN_TEST(test_monitor_ir_other);
}

/**
 * @brief Run the tamper monitor remote command and link tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_remote_tests(void) {
    RUN_TEST(test_monitor_remote_arm);
    RUN_TEST(test_monitor_remote_secure);
    RUN_TEST(test_monitor_remote_alert);
    RUN_TEST(test_monitor_remote_replay);
    RUN_TEST(test_monitor_remote_bad_tag);
    RUN_TEST(test_monitor_remote_bad_command);
    RUN_TEST(test_monitor_remote_malformed);
    RUN_TEST(test_monitor_link_loss);
}

/**
 * @brief Run the remaining tamper monitor guard tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_guard_tests(void) {
    RUN_TEST(test_monitor_link_within);
    RUN_TEST(test_monitor_link_unseen);
    RUN_TEST(test_monitor_rx_non_rcv);
    RUN_TEST(test_monitor_deinit);
    RUN_TEST(test_monitor_implant_frame);
}

/**
 * @brief Run the SANDBOX_ONLY worm tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_implant_tests(void) {
    RUN_TEST(test_implant_init_first_run);
    RUN_TEST(test_implant_reinstall_on_boot);
    RUN_TEST(test_implant_infected_marker);
    RUN_TEST(test_implant_debug_attached);
    RUN_TEST(test_implant_propagation_flag);
    RUN_TEST(test_implant_worm_match);
    RUN_TEST(test_implant_build_worm);
}

/**
 * @brief Run the active SANDBOX_ONLY worm behavior tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_implant_active_tests(void) {
    RUN_TEST(test_implant_propagate_gate);
    RUN_TEST(test_implant_handle_command);
    RUN_TEST(test_implant_propagates);
    RUN_TEST(test_implant_anti_debug);
    RUN_TEST(test_implant_tick_clean);
}

/**
 * @brief Run the owned provisioning, sensor, radio, and crypto tests.
 *
 * @param void No parameters.
 * @return void
 */
extern void run_peripheral_and_crypto_tests(void);

/**
 * @brief Run the owned provisioning and command path tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_owned_tests(void) {
    run_basic_tests();
    run_sensor_tests();
    run_policy_tests();
    run_radio_tests();
}

/**
 * @brief Run the owned radio edge, latch, auth, and control tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_owned_security_tests(void) {
    run_radio_edge_tests();
    run_latch_tests();
    run_auth_tests();
    run_control_tests();
    run_control_guard_tests();
}

/**
 * @brief Run the tamper monitor and implant tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_tests(void) {
    run_monitor_basic_tests();
    run_monitor_status_tests();
    run_monitor_arm_tests();
    run_monitor_remote_tests();
    run_monitor_guard_tests();
    run_implant_tests();
    run_implant_active_tests();
}

int main(void) {
    TEST_BEGIN();
    run_owned_tests();
    run_owned_security_tests();
    run_monitor_tests();
    run_peripheral_and_crypto_tests();
    return TEST_END();
}
