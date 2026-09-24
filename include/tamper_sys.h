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
// File:    tamper_sys.h
// Desc:    Declares platform pin mapping, peripheral handles, and
//          provisioning boundaries for the IRON WEB industrial tamper node.
// Created: 2026

#ifndef TAMPER_SYS_H
#define TAMPER_SYS_H

#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "packet_artifact.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Onboard green LED GPIO pin number.
 *
 * The RP2350 Pico 2 onboard LED is connected to GPIO 25. It is blinked
 * whenever the controller completes a successful LoRa transmit.
 */
#define TAMPER_LED_PIN 25u

/**
 * @brief DHT11 cabinet temperature sensor GPIO pin number.
 */
#define TAMPER_DHT_PIN 4u

/**
 * @brief I2C peripheral used by the 1602 LCD backpack.
 */
#define TAMPER_I2C i2c1

/**
 * @brief I2C SDA GPIO pin number.
 */
#define TAMPER_I2C_SDA 2u

/**
 * @brief I2C SCL GPIO pin number.
 */
#define TAMPER_I2C_SCL 3u

/**
 * @brief I2C bus clock rate in hertz.
 */
#define TAMPER_I2C_BAUD 100000u

/**
 * @brief I2C address of the 1602 LCD PCF8574 backpack.
 */
#define TAMPER_LCD_ADDR PACKET_LCD_I2C_ADDRESS

/**
 * @brief UART peripheral used by the RYLR998 transceiver.
 */
#define TAMPER_UART uart1

/**
 * @brief UART TX GPIO pin number to the RYLR998 RX input.
 */
#define TAMPER_UART_TX 8u

/**
 * @brief UART RX GPIO pin number from the RYLR998 TX output.
 */
#define TAMPER_UART_RX 9u

/**
 * @brief UART baud rate negotiated with the RYLR998.
 */
#define TAMPER_UART_BAUD 115200u

/**
 * @brief RYLR998 network identifier shared by all classroom radios.
 */
#define TAMPER_NETWORK_ID 18u

/**
 * @brief Fixed command frame size in bytes.
 */
#define TAMPER_FRAME_SIZE PACKET_FRAME_SIZE

/**
 * @brief Time to wait for a sealed tamper command before failing safe.
 */
#define TAMPER_ALERT_WAIT_MS PACKET_ALERT_WAIT_MS

/**
 * @brief Servo pulse width in microseconds that seats the latch closed.
 */
#define TAMPER_LATCH_CLOSE_PULSE_US PACKET_LATCH_CLOSE_PULSE_US

/**
 * @brief Servo pulse width in microseconds that drives the latch open.
 */
#define TAMPER_LATCH_OPEN_PULSE_US PACKET_LATCH_OPEN_PULSE_US

/**
 * @brief Red intrusion LED GPIO pin number.
 */
#define TAMPER_RED_LED_PIN 16u

/**
 * @brief Yellow armed LED GPIO pin number.
 */
#define TAMPER_YELLOW_LED_PIN 17u

/**
 * @brief Green secure LED GPIO pin number.
 */
#define TAMPER_GREEN_LED_PIN 18u

/**
 * @brief Arm/disarm push-button GPIO pin number.
 */
#define TAMPER_BUTTON_PIN 15u

/**
 * @brief Latch actuator servo PWM GPIO pin number.
 */
#define TAMPER_SERVO_PIN 14u

/**
 * @brief Infrared receiver GPIO pin number.
 */
#define TAMPER_IR_PIN 5u

/**
 * @brief Lowest acceptable cabinet temperature in tenths of a degree Celsius.
 */
#define TAMPER_CLIMATE_MIN_TENTHS 0

/**
 * @brief Highest acceptable cabinet temperature in tenths of a degree Celsius.
 */
#define TAMPER_CLIMATE_MAX_TENTHS 400

/**
 * @brief Lowest accepted tamper zone identifier.
 */
#define TAMPER_ZONE_MIN 0

/**
 * @brief Highest accepted tamper zone identifier.
 */
#define TAMPER_ZONE_MAX 16

/**
 * @brief Provisioned tamper node identifier.
 */
#define TAMPER_NODE_ID PACKET_NODE_ADDRESS

/**
 * @brief Provisioned mesh gateway LoRa address.
 */
#define TAMPER_GATEWAY_ADDRESS PACKET_GATEWAY_ADDRESS

#endif // TAMPER_SYS_H
