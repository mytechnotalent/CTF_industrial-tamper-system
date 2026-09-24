# industrial-tamper-system - Design Blueprint (Act V, IRON WEB)

Repo: `industrial-tamper-system`
Companion CTF repo: `CTF_industrial-tamper-system` (artifact prefix `ACT-V`)
Codename: IRON WEB
Author: Kevin Thomas (kevin@mytechnotalent.com)

---

## Act V of the OPERATION COLD IRON saga

Act I was the lie. Act II was the door. Act III was the payload. Act IV was the
payload that would not die. Act V is the payload that spreads.

The tamper system is a mesh of chassis-intrusion nodes. FROSTLINE's implant
here is a worm: it listens for a magic frame on the LoRa band and re-broadcasts
it to every other node it can reach, so one infected node seeds the whole
network. WHITEOUT must find the propagation and cut the web. This is the
propagation lesson.

## Safety contract

- No network, no internet, no host impact. Bare-metal RP2350, no OS.
- The worm propagates ONLY between the student's own breadboard nodes on the
  classroom network id. No external address.
- Effects are confined to GPIO: the intrusion LED, the LCD, the buzzer/LED.
- Synthetic data only.
- A `SANDBOX_ONLY` build guard disables the implant.
- Every act ends in analysis and neutralization.

## Parity contract

Same repo layout, crypto stack, tooling, pin map, README top/footer standard,
and telescreen legal disclaimer as Acts I-IV.

## Pin map (identical, new roles)

| Pin | Act V role |
| --- | ---------- |
| DHT11 GP4 | cabinet temperature (secondary) |
| LCD SDA GP2 / SCL GP3 | tamper status |
| IR GP5 | local arm/disarm remote |
| Servo GP14 | shutter/latch actuator |
| Red GP16 | INTRUSION |
| Yellow GP17 | ARMED |
| Green GP18 | SECURE |
| Button GP15 | arm/disarm |
| RYLR998 GP8/9 | tamper mesh link |
| Debug Probe | worm analysis |
| Onboard GP25 | heartbeat |

## Fix track

- Tamper alerts must be sealed and authorized.
- Arm/disarm must not silently bypass authorization.
- The node must not re-broadcast untrusted frames (the propagation gate).

## Malware track (worm, benign)

Module `include/implant.h` + `src/implant.c`, only under `SANDBOX_ONLY`:

- **Worm payload.** A magic frame (`IRONWEB`) carried over LoRa.
- **Propagation.** On receipt, the node re-broadcasts the worm to its peers,
  spreading it across the mesh.
- **Infection marker.** The node writes an infection marker into the reserved
  flash sector and reports itself infected.
- **Anti-debug.** Reads DHCSR and behaves benignly under a probe.
- **Neutralization.** Disable propagation, clear the marker, patch the
  re-broadcast.

## Companion CTF: ACT-V, four deep tasks

| Task | Points | Objective |
| ---- | ------ | --------- |
| 1 | 10 | Setup and analysis |
| 2 | 20 | Break the propagation (re-broadcast gate) |
| 3 | 20 | Clear the infection marker |
| 4 | 20 | Disable the worm payload handler |
| 5 | 20 | Seal the tamper alert path (fix track) |
| 6 | 10 | Export, verify, hardware proof, reflection |

Every patch is in-place and same-size.

## Naming

Project `industrial-tamper-system`; companion `CTF_industrial-tamper-system`;
prefix `ACT-V`.
