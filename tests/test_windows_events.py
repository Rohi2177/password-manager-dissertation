"""Pure policy checks for Windows power and session notifications."""

from password_manager.security.windows_events import lock_event_for_windows_message


def test_suspend_message_requests_power_lock() -> None:

    assert lock_event_for_windows_message(0x0218, 0x0004) == "vault_locked_power"


def test_lock_disconnect_and_logoff_request_session_lock() -> None:
    for parameter in (0x0002, 0x0004, 0x0006, 0x0007):
        assert lock_event_for_windows_message(0x02B1, parameter) == "vault_locked_session"


def test_resume_unlock_and_irrelevant_messages_do_not_request_lock() -> None:

    assert lock_event_for_windows_message(0x0218, 0x0007) is None
    assert lock_event_for_windows_message(0x02B1, 0x0008) is None
    assert lock_event_for_windows_message(0x1234, 0x0004) is None
