"""Platform-independent tests for the Windows Hello decision boundary."""

import pytest

from password_manager.broker.windows_hello import (
    WindowsHelloResult,
    WindowsHelloVerifier,
    result_explanation,
)


def test_non_windows_host_fails_closed() -> None:

    verifier = WindowsHelloVerifier(platform="linux")

    result = verifier.verify(123, "Verify one fake-data action")

    assert result is WindowsHelloResult.UNSUPPORTED_WINDOWS


def test_documented_windows_result_values_are_preserved() -> None:

    assert WindowsHelloResult.VERIFIED.value == 0
    assert WindowsHelloResult.NOT_CONFIGURED_FOR_USER.value == 2
    assert WindowsHelloResult.CANCELED.value == 6


@pytest.mark.parametrize("window", [0, -1])
def test_invalid_owner_window_fails_closed(window: int) -> None:

    verifier = WindowsHelloVerifier(platform="win32")

    assert verifier.verify(window, "Verify one fake-data action") is WindowsHelloResult.API_ERROR


def test_empty_or_oversized_message_fails_closed() -> None:
    verifier = WindowsHelloVerifier(platform="win32")

    assert verifier.verify(123, "") is WindowsHelloResult.API_ERROR
    assert verifier.verify(123, "x" * 257) is WindowsHelloResult.API_ERROR


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True])
def test_timeout_must_be_finite_and_positive(timeout: float) -> None:

    with pytest.raises(ValueError, match="positive"):
        WindowsHelloVerifier(timeout_seconds=timeout)


@pytest.mark.parametrize(
    "result",
    [
        WindowsHelloResult.CANCELED,
        WindowsHelloResult.NOT_CONFIGURED_FOR_USER,
        WindowsHelloResult.API_ERROR,
        WindowsHelloResult.TIMED_OUT,
    ],
)
def test_denial_explanations_never_claim_success(result: WindowsHelloResult) -> None:

    message = result_explanation(result)

    assert "No password was released" in message
    assert "verified" not in message.casefold()
