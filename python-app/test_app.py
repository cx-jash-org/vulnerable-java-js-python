"""
Tests for the command injection fix in run_subprocess() (/run endpoint).

The vulnerability was: subprocess.check_output("echo " + user_input, shell=True)
The fix is:           subprocess.check_output(["echo", user_input], shell=False)

With shell=False and an argv list, user_input is always treated as a literal
argument to echo — shell metacharacters are never interpreted by a shell.
"""

import subprocess
import unittest
from unittest.mock import patch, MagicMock

import pytest

# Import the Flask app under test
from app import app


@pytest.fixture
def client():
    """Provide a Flask test client with testing mode enabled."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Functional / positive-path tests
# ---------------------------------------------------------------------------

class TestRunSubprocessFunctionality:
    """Verify that the /run endpoint still works correctly after the fix."""

    def test_basic_input_is_echoed(self, client):
        """Normal input should be echoed back."""
        response = client.get("/run?input=hello")
        assert response.status_code == 200
        assert b"hello" in response.data

    def test_empty_input_returns_newline(self, client):
        """An empty input should return just a newline (echo with no args)."""
        response = client.get("/run?input=")
        assert response.status_code == 200
        # echo with an empty argument prints a blank line
        assert response.data in (b"\n", b" \n", b"")

    def test_missing_input_parameter_defaults_to_empty(self, client):
        """A missing ?input= query parameter should not crash the endpoint."""
        response = client.get("/run")
        assert response.status_code == 200

    def test_plain_text_with_spaces(self, client):
        """Input containing spaces should be echoed literally."""
        response = client.get("/run?input=hello+world")
        assert response.status_code == 200
        assert b"hello world" in response.data

    def test_alphanumeric_input(self, client):
        """Alphanumeric input should pass through unchanged."""
        response = client.get("/run?input=abc123")
        assert response.status_code == 200
        assert b"abc123" in response.data


# ---------------------------------------------------------------------------
# Security / negative-path tests — command injection attempts
# ---------------------------------------------------------------------------

class TestRunSubprocessCommandInjectionPrevention:
    """
    Verify that shell metacharacters in user input cannot execute additional
    OS commands.  With shell=False the metacharacters are treated literally by
    echo, so the injected command is never run.
    """

    @pytest.mark.parametrize("payload,injected_marker", [
        # Classic semicolon injection: echo hello; id
        ("hello; id", b"uid="),
        # Subshell injection: $(id)
        ("$(id)", b"uid="),
        # Backtick injection: `id`
        ("`id`", b"uid="),
        # Pipe injection: | cat /etc/passwd
        ("| cat /etc/passwd", b"root:"),
        # Logical OR injection: || id
        ("|| id", b"uid="),
        # Logical AND injection: && id
        ("&& id", b"uid="),
        # Newline injection: \n id
        ("hello\nid", b"uid="),
        # Null-byte injection (expressed as escape, never as a raw byte)
        ("hello\x00id", b"uid="),
        # Environment variable expansion attempt
        ("$PATH", b"/usr/"),
    ])
    def test_shell_metacharacter_is_not_executed(self, client, payload, injected_marker):
        """
        For each payload, the injected_marker (output that would appear if the
        injected command ran) must NOT appear in the response body.
        """
        response = client.get(f"/run?input={payload}")
        # The endpoint must not crash
        assert response.status_code == 200
        # The side-effect of the injected command must not be in the output
        assert injected_marker not in response.data, (
            f"Payload {payload!r} caused injected command output to appear in response"
        )

    def test_semicolon_payload_is_echoed_literally(self, client):
        """
        The semicolon and anything after it should appear in the output as
        literal text, not as a second command.
        """
        response = client.get("/run?input=hello%3B+id")  # %3B = ;
        assert response.status_code == 200
        # The literal semicolon string should be echoed back
        assert b"hello" in response.data
        # The output of 'id' (uid=...) must not appear
        assert b"uid=" not in response.data

    def test_backtick_payload_is_echoed_literally(self, client):
        """Backticks should be echoed literally, not executed as a subshell."""
        response = client.get("/run?input=%60id%60")  # %60 = `
        assert response.status_code == 200
        assert b"uid=" not in response.data

    def test_dollar_subshell_payload_is_echoed_literally(self, client):
        """$(command) subshell syntax should be echoed literally."""
        response = client.get("/run?input=%24%28id%29")  # $(id)
        assert response.status_code == 200
        assert b"uid=" not in response.data


# ---------------------------------------------------------------------------
# Unit-level tests — verify subprocess is called with shell=False
# ---------------------------------------------------------------------------

class TestRunSubprocessCallSignature:
    """
    Unit tests that inspect how subprocess.check_output is invoked to confirm
    the fix is structurally correct: argv list, shell=False.
    """

    def test_subprocess_called_with_list_not_string(self, client):
        """
        subprocess.check_output must be called with a list as its first
        argument (not a shell string).
        """
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"hello\n"
            client.get("/run?input=hello")

            assert mock_co.called, "subprocess.check_output was not called"
            args, kwargs = mock_co.call_args
            # First positional argument must be a list
            assert isinstance(args[0], list), (
                f"Expected list, got {type(args[0])}: {args[0]!r}"
            )

    def test_subprocess_called_with_shell_false(self, client):
        """subprocess.check_output must be called with shell=False."""
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"hello\n"
            client.get("/run?input=hello")

            args, kwargs = mock_co.call_args
            shell_value = kwargs.get("shell", args[1] if len(args) > 1 else None)
            assert shell_value is False or shell_value == False, (
                f"Expected shell=False, got shell={shell_value!r}"
            )

    def test_user_input_is_second_list_element(self, client):
        """
        The user-supplied value must be the second element of the argv list
        (index 1), NOT the first element (which should be the hard-coded
        program name 'echo').
        """
        test_input = "test_value_xyz"
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"test_value_xyz\n"
            client.get(f"/run?input={test_input}")

            args, kwargs = mock_co.call_args
            argv = args[0]
            assert len(argv) >= 2, f"argv list too short: {argv!r}"
            assert argv[0] == "echo", f"First element should be 'echo', got {argv[0]!r}"
            assert argv[1] == test_input, (
                f"User input should be argv[1], got {argv[1]!r}"
            )

    def test_injection_payload_passed_as_literal_argument(self, client):
        """
        Even a payload containing shell metacharacters must arrive at
        check_output as a single literal string in the argv list.
        """
        payload = "hello; rm -rf /"
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"hello; rm -rf /\n"
            client.get(f"/run?input={payload}")

            args, kwargs = mock_co.call_args
            argv = args[0]
            # The entire payload must be a single element — not split by shell
            assert payload in argv, (
                f"Payload {payload!r} should appear as one argv element"
            )
            # The shell metacharacter must not have caused argv to split
            assert len(argv) == 2, (
                f"argv should have exactly 2 elements [echo, payload], got {argv!r}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
