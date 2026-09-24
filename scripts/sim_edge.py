#!/usr/bin/env python3
"""Simulate a real TAMPER node from a laptop without a Pico.

sim_edge.py drives a USB-to-TTL radio with the same sealed request and
AT+SEND cadence as the RP2350 firmware. Each requested zone is sealed
with the OPERATION COLD IRON field key so the mesh gateway accepts the
request and answers with a sealed tamper command. Students can validate
the gateway and then practice spoofing against a live node before touching
embedded hardware.
"""

import argparse
import sys
import time

import field_crypto

try:
    import serial
except ImportError as exc:
    raise SystemExit(
        "pip install pyserial to run the TAMPER edge simulator"
    ) from exc

GATEWAY_ADDRESS = "0001"
DEFAULT_ZONE = 4


def _parse_args():
    """Parse edge simulator command-line arguments.

    Parameters
    ----------
    None

    Returns
    -------
    argparse.Namespace
        Parsed edge simulator arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Serial port device")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Radio baud rate")
    parser.add_argument("--node", type=int, default=7,
                        help="Node identifier")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Request interval in seconds")
    parser.add_argument("--zone", type=int, default=DEFAULT_ZONE,
                        help="Setpoint to request in tenths of a degree")
    return parser.parse_args()


def _drain(ser):
    """Read and print any inbound radio lines.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.

    Returns
    -------
    None
    """
    while True:
        line = ser.readline()
        if not line:
            return
        print(line.decode("utf-8", errors="replace").strip(), flush=True)


def _tick(ser, args, seq):
    """Transmit one simulated sealed TAMPER zone request.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    args : argparse.Namespace
        Parsed edge simulator arguments.
    seq : int
        Current request sequence number.

    Returns
    -------
    None
    """
    request = args.zone.to_bytes(2, "little")
    envelope = field_crypto.seal_field_frame(request)
    cmd = f"AT+SEND={GATEWAY_ADDRESS},{len(envelope)},{envelope}\r\n"
    ser.write(cmd.encode("utf-8"))
    ser.flush()
    print(f"[node {args.node} seq {seq}] sealed zone {args.zone}",
          flush=True)


def main():
    """Run the edge simulator loop until interrupted.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero on clean shutdown.
    """
    args = _parse_args()
    seq = 0
    with serial.Serial(args.port, args.baud, timeout=0.1) as ser:
        while True:
            try:
                _tick(ser, args, seq)
                seq += 1
                time.sleep(args.interval)
                _drain(ser)
            except KeyboardInterrupt:
                return 0


if __name__ == "__main__":
    sys.exit(main())
