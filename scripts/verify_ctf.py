#!/usr/bin/env python3
"""Verify the IRON WEB ACT-V artifacts against the solution.

Exits zero only when the shipped compromised image and the corrected image
match every documented offset and byte value, differ in exactly the intended
number of bytes, and carry the documented SHA-256 digests.
"""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUGGY = ROOT / "ACT-V.bin"
FIXED = ROOT / "ACT-V_fixed.bin"
BUGGY_SHA256 = (
    "fab47a6e9f81aaccbc01baffb02ae56d98cc70974e82caa256beb6c52bbb4577"
)
FIXED_SHA256 = (
    "795fe72e417cfa28bf61196358eb570c18e7f54f655ca90095b4935b1b362fdc"
)

CHANGES = (
    (0x7569, 0xB9, 0xB1, "tamper authorization branch"),
    (0xA2F7, 0xD1, 0xD0, "propagation gate branch"),
    (0xA35F, 0xD1, 0xD0, "worm payload handler branch"),
    (0xA473, 0xB9, 0xB1, "infection marker gate branch"),
)


def _sha256(data: bytes) -> str:
    """
    Return the hexadecimal SHA-256 digest of a byte string.

    Parameters
    ----------
    data : bytes
        Byte string to hash.

    Returns
    -------
    str
        Lowercase hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def _report(label: str, ok: bool) -> bool:
    """
    Print one labelled pass or fail result.

    Parameters
    ----------
    label : str
        Human-readable check label.
    ok : bool
        True when the check passed.

    Returns
    -------
    bool
        The same pass flag, for accumulation.
    """
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")
    return ok


def _check_change(change: tuple[int, int, int, str], buggy: bytes,
                  fixed: bytes) -> bool:
    """
    Check one documented offset and both byte values.

    Parameters
    ----------
    change : tuple[int, int, int, str]
        Offset, compromised byte, corrected byte, and label.
    buggy : bytes
        Compromised image bytes.
    fixed : bytes
        Corrected image bytes.

    Returns
    -------
    bool
        True when the compromised and corrected bytes match the plan.
    """
    offset, want_buggy, want_fixed, label = change
    ok = buggy[offset] == want_buggy and fixed[offset] == want_fixed
    return _report(f"0x{offset:04X} {label}", ok)


def _check_sizes(buggy: bytes, fixed: bytes) -> list[bool]:
    """
    Check that both images exist and share one size.

    Parameters
    ----------
    buggy : bytes
        Compromised image bytes.
    fixed : bytes
        Corrected image bytes.

    Returns
    -------
    list[bool]
        Existence and size check results.
    """
    return [
        _report("ACT-V.bin exists", BUGGY.exists()),
        _report("ACT-V_fixed.bin exists", FIXED.exists()),
        _report("sizes equal", len(buggy) == len(fixed)),
    ]


def _check_diff(buggy: bytes, fixed: bytes) -> bool:
    """
    Check that exactly the documented offsets differ.

    Parameters
    ----------
    buggy : bytes
        Compromised image bytes.
    fixed : bytes
        Corrected image bytes.

    Returns
    -------
    bool
        True when only the intended offset list changed.
    """
    pairs = zip(buggy, fixed)
    changed = [i for i, pair in enumerate(pairs) if pair[0] != pair[1]]
    expected = sorted(change[0] for change in CHANGES)
    return _report("exactly the intended bytes differ", changed == expected)


def _check_hashes(buggy: bytes, fixed: bytes) -> list[bool]:
    """
    Check both documented SHA-256 digests.

    Parameters
    ----------
    buggy : bytes
        Compromised image bytes.
    fixed : bytes
        Corrected image bytes.

    Returns
    -------
    list[bool]
        Digest check results.
    """
    return [
        _report("ACT-V.bin sha256", _sha256(buggy) == BUGGY_SHA256),
        _report("ACT-V_fixed.bin sha256", _sha256(fixed) == FIXED_SHA256),
    ]


def _summary(results: list[bool]) -> int:
    """
    Print the aggregate result and return the process status.

    Parameters
    ----------
    results : list[bool]
        Collected check results.

    Returns
    -------
    int
        Zero when every check passed, otherwise one.
    """
    total = sum(results)
    print(f"\n{total}/{len(results)} checks passed")
    return 0 if total == len(results) else 1


def main() -> int:
    """
    Run every ACT-V artifact check.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero when every check passes, otherwise one.
    """
    buggy = BUGGY.read_bytes()
    fixed = FIXED.read_bytes()
    results = _check_sizes(buggy, fixed)
    results += [_check_change(change, buggy, fixed) for change in CHANGES]
    results.append(_check_diff(buggy, fixed))
    results += _check_hashes(buggy, fixed)
    return _summary(results)


if __name__ == "__main__":
    sys.exit(main())
