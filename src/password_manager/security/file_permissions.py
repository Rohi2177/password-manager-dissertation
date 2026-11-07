"""Restrict access to vaults and local security files."""

from __future__ import annotations

import ctypes
import os
import re
import stat
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any

_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_SDDL_REVISION_1 = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SID_PATTERN = re.compile(r"S-\d-\d+(?:-\d+)+\Z")


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return 0 if getter is None else int(getter())


def _windows_libraries() -> tuple[Any, Any]:

    windows_library = getattr(ctypes, "WinDLL", None)

    if windows_library is None:
        raise OSError("The Windows security API is unavailable.")

    return (
        windows_library("advapi32", use_last_error=True),
        windows_library("kernel32", use_last_error=True),
    )


def _current_windows_user_sid() -> str:

    advapi32, kernel32 = _windows_libraries()
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]

    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]

    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]

    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    process = kernel32.GetCurrentProcess()
    if not advapi32.OpenProcessToken(
        process,
        _TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise OSError(_last_error(), "Could not open the current user token.")
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            _TOKEN_USER_CLASS,
            None,
            0,
            ctypes.byref(required),
        )

        if _last_error() != _ERROR_INSUFFICIENT_BUFFER or required.value == 0:
            raise OSError(_last_error(), "Could not size the current user token.")
        buffer = ctypes.create_string_buffer(required.value)

        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_USER_CLASS,
            buffer,
            required,
            ctypes.byref(required),
        ):
            raise OSError(_last_error(), "Could not read the current user token.")
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        sid_pointer = wintypes.LPWSTR()

        if not advapi32.ConvertSidToStringSidW(
            token_user.user.sid,
            ctypes.byref(sid_pointer),
        ):
            raise OSError(_last_error(), "Could not encode the current user SID.")

        try:
            sid = sid_pointer.value
            if sid is None or _SID_PATTERN.fullmatch(sid) is None:
                raise OSError("Windows returned an invalid current user SID.")
            return sid

        finally:
            kernel32.LocalFree(ctypes.cast(sid_pointer, ctypes.c_void_p))

    finally:
        kernel32.CloseHandle(token)


def _harden_windows_file(path: Path) -> None:
    advapi32, kernel32 = _windows_libraries()
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]

    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.SetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]

    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    sid = _current_windows_user_sid()
    descriptor_text = f"D:P(A;;FA;;;SY)(A;;FA;;;{sid})"
    descriptor = ctypes.c_void_p()

    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        descriptor_text,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise OSError(_last_error(), "Could not create the private file ACL.")

    try:
        security_information = _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION
        if not advapi32.SetFileSecurityW(
            str(path),
            security_information,
            descriptor,
        ):
            raise OSError(_last_error(), "Could not apply the private file ACL.")
    finally:
        kernel32.LocalFree(descriptor)


def harden_private_file(path: str | Path) -> None:
    """Allow access only to the current user and Windows SYSTEM."""

    selected = Path(path)
    if not selected.is_file() or selected.is_symlink():
        raise OSError("Only an existing regular file can be made private.")

    if sys.platform == "win32":
        _harden_windows_file(selected)
        return
    os.chmod(selected, stat.S_IRUSR | stat.S_IWUSR)
