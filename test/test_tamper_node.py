"""Unit test adapter for VS Code Test Explorer."""
import subprocess
import sys
import unittest

_CACHED_OUTPUT = ""


def _get_harness_output() -> str:
    """
    Execute native tests and return stdout.

    Parameters
    ----------
    None

    Returns
    -------
    str
        Standard output from native test suite.
    """
    global _CACHED_OUTPUT
    if not _CACHED_OUTPUT:
        cmd = [sys.executable, "scripts/run_tests.py"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        _CACHED_OUTPUT = res.stdout
    return _CACHED_OUTPUT


def _assert_harness_pass(test_name: str) -> None:
    """
    Assert that a named harness test passed.

    Parameters
    ----------
    test_name : str
        Name of harness test function.

    Returns
    -------
    None
    """
    output = _get_harness_output()
    expected = f":{test_name}:PASS"
    assert expected in output, f"{test_name} did not pass in harness output"


class TestIndustrialTamperSystem(unittest.TestCase):
    """Test cases for the RP2350 IRON WEB tamper node firmware."""

    def test_00_harness_clean(self) -> None:
        """
        Verify the native harness reports no failures.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        assert "0 failures" in _get_harness_output()

    def test_01_config_constants(self) -> None:
        """
        Verify provisioning constants.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_config_constants")

    def test_02_tamper_auth_window(self) -> None:
        """
        Verify the command anti-replay window.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_tamper_auth_apply_window")

    def test_03_control_handle_success(self) -> None:
        """
        Verify a sealed tamper command authenticates and is applied.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_control_handle_success")

    def test_04_monitor_remote_arm(self) -> None:
        """
        Verify a sealed remote arm command seats the latch.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_monitor_remote_arm")

    def test_05_monitor_remote_replay(self) -> None:
        """
        Verify a captured command cannot be replayed.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_monitor_remote_replay")

    def test_06_monitor_arm_no_bypass(self) -> None:
        """
        Verify a local arm request cannot bypass authorization.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_monitor_arm_no_bypass")

    def test_07_monitor_link_loss(self) -> None:
        """
        Verify the node fails safe on mesh link loss.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_monitor_link_loss")

    def test_08_status_led_show(self) -> None:
        """
        Verify the annunciator show states.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_status_led_show")

    def test_09_implant_propagates(self) -> None:
        """
        Verify the worm propagates across the mesh.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_implant_propagates")


if __name__ == "__main__":
    unittest.main()
