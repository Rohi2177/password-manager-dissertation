"""Check that the local connection belongs to the same user."""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import sys
from multiprocessing.connection import _ConnectionBase
from typing import Literal

from password_manager.broker.exceptions import BrokerTransportError

PeerRole = Literal["client", "server"]


def _linux_peer_user_id(handle: int) -> int:

    address_family = getattr(socket, "AF_UNIX", None)
    peer_credentials_option = getattr(socket, "SO_PEERCRED", None)

    if not isinstance(address_family, int) or not isinstance(peer_credentials_option, int):
        raise BrokerTransportError("This platform cannot verify the local peer user.")
    duplicate = socket.fromfd(handle, address_family, socket.SOCK_STREAM)

    try:
        credentials = duplicate.getsockopt(
            socket.SOL_SOCKET,
            peer_credentials_option,
            struct.calcsize("3i"),
        )

    except OSError as error:
        raise BrokerTransportError("The local peer identity could not be read.") from error

    finally:
        duplicate.close()

    _process_id, user_id, _group_id = struct.unpack("3i", credentials)
    return int(user_id)


def _windows_peer_process_id(handle: int, peer_role: PeerRole) -> int:
    from ctypes import wintypes

    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        raise BrokerTransportError("The Windows API is unavailable.")

    kernel32 = windows_library("kernel32", use_last_error=True)

    function_name = (
        "GetNamedPipeClientProcessId" if peer_role == "client" else "GetNamedPipeServerProcessId"
    )

    get_peer_process_id = getattr(kernel32, function_name)
    get_peer_process_id.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    get_peer_process_id.restype = wintypes.BOOL
    process_id = wintypes.ULONG()

    if not get_peer_process_id(wintypes.HANDLE(handle), ctypes.byref(process_id)):
        raise BrokerTransportError("The Windows named-pipe peer could not be identified.")

    if process_id.value < 1:
        raise BrokerTransportError("The Windows named-pipe peer identity is invalid.")

    return int(process_id.value)


def _windows_process_user_sid(process_id: int) -> bytes:
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    token_query = 0x0008
    token_user_information_class = 1

    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        raise BrokerTransportError("The Windows API is unavailable.")

    kernel32 = windows_library("kernel32", use_last_error=True)
    advapi32 = windows_library("advapi32", use_last_error=True)

    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]

    open_process_token.restype = wintypes.BOOL
    get_token_information = advapi32.GetTokenInformation
    get_token_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]

    get_token_information.restype = wintypes.BOOL
    get_length_sid = advapi32.GetLengthSid
    get_length_sid.argtypes = [ctypes.c_void_p]
    get_length_sid.restype = wintypes.DWORD

    process_handle = open_process(
        process_query_limited_information,
        False,
        process_id,
    )

    if not process_handle:
        raise BrokerTransportError("The Windows peer process could not be inspected.")
    token_handle = wintypes.HANDLE()

    try:
        if not open_process_token(process_handle, token_query, ctypes.byref(token_handle)):
            raise BrokerTransportError("The Windows peer token could not be inspected.")

        required = wintypes.DWORD()
        get_token_information(
            token_handle,
            token_user_information_class,
            None,
            0,
            ctypes.byref(required),
        )

        if required.value < ctypes.sizeof(ctypes.c_void_p):
            raise BrokerTransportError("The Windows peer token is malformed.")

        buffer = ctypes.create_string_buffer(required.value)

        if not get_token_information(
            token_handle,
            token_user_information_class,
            buffer,
            required,
            ctypes.byref(required),
        ):
            raise BrokerTransportError("The Windows peer user SID could not be read.")

        class SidAndAttributes(ctypes.Structure):
            _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

        token_user = ctypes.cast(buffer, ctypes.POINTER(SidAndAttributes)).contents
        sid_length = get_length_sid(token_user.sid)

        if sid_length < 8 or sid_length > 68:
            raise BrokerTransportError("The Windows peer user SID is malformed.")
        return ctypes.string_at(token_user.sid, sid_length)

    finally:
        if token_handle:
            close_handle(token_handle)
        close_handle(process_handle)


def verify_same_user_peer(
    connection: _ConnectionBase[object, object],
    *,
    peer_role: PeerRole,
) -> None:
    """Reject the connection unless its peer belongs to the current user."""

    # Windows supplies PipeConnection and POSIX supplies Connection. Both are
    # legitimate multiprocessing connection types with an OS handle.
    if not isinstance(connection, _ConnectionBase):
        raise BrokerTransportError("The local Broker connection is invalid.")
    handle = connection.fileno()

    if sys.platform == "win32":
        peer_process_id = _windows_peer_process_id(handle, peer_role)
        if _windows_process_user_sid(peer_process_id) != _windows_process_user_sid(os.getpid()):
            raise BrokerTransportError("The Windows named-pipe peer belongs to another user.")
        return

    if sys.platform.startswith("linux"):
        if _linux_peer_user_id(handle) != os.getuid():
            raise BrokerTransportError("The local socket peer belongs to another user.")
        return
    raise BrokerTransportError("This platform has no implemented peer-identity verifier.")
