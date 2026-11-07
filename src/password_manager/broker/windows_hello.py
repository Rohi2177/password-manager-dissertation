"""Windows Hello confirms actions; it does not encrypt or unlock the vault."""

from __future__ import annotations

import ctypes
import math
import sys
import time
import uuid
from collections.abc import Callable
from enum import IntEnum
from typing import Any, Protocol

MINIMUM_WINDOWS_BUILD = 22_000
DEFAULT_TIMEOUT_SECONDS = 120.0


class WindowsHelloResult(IntEnum):
    """Documented ``UserConsentVerificationResult`` values plus local failures."""

    VERIFIED = 0
    DEVICE_NOT_PRESENT = 1
    NOT_CONFIGURED_FOR_USER = 2
    DISABLED_BY_POLICY = 3
    DEVICE_BUSY = 4
    RETRIES_EXHAUSTED = 5
    CANCELED = 6
    UNSUPPORTED_WINDOWS = 100
    API_ERROR = 101
    TIMED_OUT = 102


class UserVerifier(Protocol):
    """Small injectable boundary used by the trusted Broker approval dialog."""

    def verify(
        self,
        owner_window: int,
        message: str,
        *,
        pump_events: Callable[[], None] | None = None,
    ) -> WindowsHelloResult: ...


def result_explanation(result: WindowsHelloResult) -> str:

    explanations = {
        WindowsHelloResult.DEVICE_NOT_PRESENT: (
            "Windows Hello is not available on this device. No password was released."
        ),
        WindowsHelloResult.NOT_CONFIGURED_FOR_USER: (
            "Windows Hello is not configured for this Windows account. "
            "Set up a PIN, fingerprint, or face sign-in and try again. "
            "No password was released."
        ),
        WindowsHelloResult.DISABLED_BY_POLICY: (
            "Windows Hello is disabled by Windows policy. No password was released."
        ),
        WindowsHelloResult.DEVICE_BUSY: (
            "Windows Hello is busy. Wait a moment and try the request again."
        ),
        WindowsHelloResult.RETRIES_EXHAUSTED: (
            "Windows Hello stopped after too many unsuccessful attempts. No password was released."
        ),
        WindowsHelloResult.CANCELED: ("Windows Hello was canceled. No password was released."),
        WindowsHelloResult.UNSUPPORTED_WINDOWS: (
            "This feature requires Windows 11 build 22000 or newer. No password was released."
        ),
        WindowsHelloResult.TIMED_OUT: (
            "Windows Hello did not finish in time. No password was released."
        ),
        WindowsHelloResult.API_ERROR: (
            "Windows could not complete the Hello check. No password was released."
        ),
    }

    return explanations.get(
        result,
        "Windows Hello did not verify this request. No password was released.",
    )


class _Guid(ctypes.Structure):
    _fields_ = (
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    )

    @classmethod
    def parse(cls, value: str) -> _Guid:

        raw = uuid.UUID(value).bytes_le
        return cls(
            int.from_bytes(raw[0:4], "little"),
            int.from_bytes(raw[4:6], "little"),
            int.from_bytes(raw[6:8], "little"),
            (ctypes.c_ubyte * 8).from_buffer_copy(raw[8:]),
        )


_RUNTIME_CLASS = "Windows.Security.Credentials.UI.UserConsentVerifier"
_IID_USER_CONSENT_VERIFIER_INTEROP = _Guid.parse("39e050c3-4e74-441a-8dc0-b81104df949c")
_IID_ASYNC_OPERATION_RESULT = _Guid.parse("fd596ffd-2318-558f-9dbe-d21df43764a5")
_IID_ASYNC_INFO = _Guid.parse("00000036-0000-0000-c000-000000000046")

_S_OK = 0
_S_FALSE = 1
_RPC_E_CHANGED_MODE = -2147417850
_ASYNC_STARTED = 0
_ASYNC_COMPLETED = 1
_ASYNC_CANCELED = 2
_ASYNC_ERROR = 3


def _failed(hresult: int) -> bool:
    return hresult < 0


def _vtable_method(
    pointer: ctypes.c_void_p,
    index: int,
    result_type: Any,
    *argument_types: Any,
) -> Any:

    vtable = ctypes.cast(
        pointer,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
    ).contents
    prototype = ctypes.WINFUNCTYPE(  # type: ignore[attr-defined, unused-ignore]
        result_type,
        ctypes.c_void_p,
        *argument_types,
    )
    return prototype(vtable[index])


def _release(pointer: ctypes.c_void_p) -> None:
    if pointer.value:
        release = _vtable_method(pointer, 2, ctypes.c_ulong)
        release(pointer)
        pointer.value = None


def _query_interface(pointer: ctypes.c_void_p, interface_id: _Guid) -> ctypes.c_void_p:
    result = ctypes.c_void_p()
    query = _vtable_method(
        pointer,
        0,
        ctypes.c_int32,
        ctypes.POINTER(_Guid),
        ctypes.POINTER(ctypes.c_void_p),
    )
    hresult = query(pointer, ctypes.byref(interface_id), ctypes.byref(result))

    if _failed(hresult):
        raise OSError(f"QueryInterface failed (0x{hresult & 0xFFFFFFFF:08X}).")
    return result


class WindowsHelloVerifier:
    """Call Windows Hello from the Broker and deny safely on every failure."""

    def __init__(
        self,
        *,
        platform: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("Windows Hello timeout must be finite and positive.")
        self._platform = sys.platform if platform is None else platform
        self._timeout_seconds = timeout_seconds

    def verify(
        self,
        owner_window: int,
        message: str,
        *,
        pump_events: Callable[[], None] | None = None,
    ) -> WindowsHelloResult:

        if self._platform != "win32":
            return WindowsHelloResult.UNSUPPORTED_WINDOWS

        if owner_window <= 0 or not message or len(message) > 256:
            return WindowsHelloResult.API_ERROR

        try:
            windows_version = sys.getwindowsversion()  # type: ignore[attr-defined, unused-ignore]

            if windows_version.build < MINIMUM_WINDOWS_BUILD:
                return WindowsHelloResult.UNSUPPORTED_WINDOWS
            return self._verify_with_interop(owner_window, message, pump_events)

        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            return WindowsHelloResult.API_ERROR

    def _verify_with_interop(
        self,
        owner_window: int,
        message: str,
        pump_events: Callable[[], None] | None,
    ) -> WindowsHelloResult:

        combase = ctypes.WinDLL("combase", use_last_error=True)  # type: ignore[attr-defined, unused-ignore]
        hstring = ctypes.c_void_p()
        runtime_class = ctypes.c_void_p()
        factory = ctypes.c_void_p()
        operation = ctypes.c_void_p()
        async_info = ctypes.c_void_p()
        initialized = False

        ro_initialize = combase.RoInitialize
        ro_initialize.argtypes = [ctypes.c_uint32]
        ro_initialize.restype = ctypes.c_int32
        windows_create_string = combase.WindowsCreateString
        windows_create_string.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]

        windows_create_string.restype = ctypes.c_int32
        windows_delete_string = combase.WindowsDeleteString
        windows_delete_string.argtypes = [ctypes.c_void_p]
        windows_delete_string.restype = ctypes.c_int32
        ro_get_activation_factory = combase.RoGetActivationFactory
        ro_get_activation_factory.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_Guid),
            ctypes.POINTER(ctypes.c_void_p),
        ]

        ro_get_activation_factory.restype = ctypes.c_int32
        ro_uninitialize = combase.RoUninitialize
        ro_uninitialize.argtypes = []
        ro_uninitialize.restype = None

        try:
            # RO_INIT_SINGLETHREADED keeps the call on the Broker's Qt UI thread.
            init_result = ro_initialize(0)

            if init_result in (_S_OK, _S_FALSE):
                initialized = True

            elif init_result != _RPC_E_CHANGED_MODE:
                raise OSError("Windows Runtime initialization failed.")

            hresult = windows_create_string(
                _RUNTIME_CLASS,
                len(_RUNTIME_CLASS),
                ctypes.byref(runtime_class),
            )

            if _failed(hresult):
                raise OSError("Windows Runtime class name creation failed.")
            hresult = ro_get_activation_factory(
                runtime_class,
                ctypes.byref(_IID_USER_CONSENT_VERIFIER_INTEROP),
                ctypes.byref(factory),
            )

            if _failed(hresult):
                raise OSError("Windows Hello activation failed.")

            # Windows counts UTF-16 code units; Python counts Unicode characters.
            message_length = len(message.encode("utf-16-le")) // 2
            hresult = windows_create_string(message, message_length, ctypes.byref(hstring))

            if _failed(hresult):
                raise OSError("Windows Hello message creation failed.")
            request = _vtable_method(
                factory,
                6,
                ctypes.c_int32,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.POINTER(_Guid),
                ctypes.POINTER(ctypes.c_void_p),
            )

            hresult = request(
                factory,
                ctypes.c_void_p(owner_window),
                hstring,
                ctypes.byref(_IID_ASYNC_OPERATION_RESULT),
                ctypes.byref(operation),
            )

            if _failed(hresult) or not operation.value:
                raise OSError("Windows Hello request failed.")

            async_info = _query_interface(operation, _IID_ASYNC_INFO)
            get_status = _vtable_method(
                async_info,
                7,
                ctypes.c_int32,
                ctypes.POINTER(ctypes.c_int32),
            )

            cancel = _vtable_method(async_info, 9, ctypes.c_int32)
            close = _vtable_method(async_info, 10, ctypes.c_int32)
            deadline = time.monotonic() + self._timeout_seconds
            status = ctypes.c_int32(_ASYNC_STARTED)
            while time.monotonic() < deadline:
                hresult = get_status(async_info, ctypes.byref(status))

                if _failed(hresult):
                    raise OSError("Windows Hello status check failed.")

                if status.value != _ASYNC_STARTED:
                    break

                if pump_events is not None:
                    pump_events()
                time.sleep(0.05)

            else:
                cancel(async_info)
                return WindowsHelloResult.TIMED_OUT

            if status.value == _ASYNC_CANCELED:
                return WindowsHelloResult.CANCELED
            if status.value == _ASYNC_ERROR or status.value != _ASYNC_COMPLETED:
                return WindowsHelloResult.API_ERROR

            raw_result = ctypes.c_int32()
            get_results = _vtable_method(
                operation,
                8,
                ctypes.c_int32,
                ctypes.POINTER(ctypes.c_int32),
            )
            hresult = get_results(operation, ctypes.byref(raw_result))

            if _failed(hresult):
                raise OSError("Windows Hello result retrieval failed.")
            try:
                return WindowsHelloResult(raw_result.value)
            except ValueError:
                return WindowsHelloResult.API_ERROR

        finally:
            if async_info.value:
                try:
                    close = _vtable_method(async_info, 10, ctypes.c_int32)
                    close(async_info)
                except (OSError, TypeError, ValueError):
                    pass
            _release(async_info)
            _release(operation)
            _release(factory)
            if hstring.value:
                windows_delete_string(hstring)
            if runtime_class.value:
                windows_delete_string(runtime_class)
            if initialized:
                ro_uninitialize()
