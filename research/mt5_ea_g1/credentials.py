"""Current-user DPAPI credential provisioning for the isolated G1 receiver."""
from __future__ import annotations

import ctypes
import hmac
import json
import os
import secrets
from ctypes import wintypes
from pathlib import Path
from typing import Any


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi():
    if os.name != "nt":
        raise OSError("DPAPI credentials are available only on Windows.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR, ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def _blob(data: bytes) -> tuple[DATA_BLOB, Any]:
    buffer = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    return DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def _protect(data: bytes) -> bytes:
    crypt32, kernel32 = _dpapi()
    source, _keepalive = _blob(data)
    output = DATA_BLOB()
    if not crypt32.CryptProtectData(
        ctypes.byref(source), "CheapTrader EA G1", None, None, None, 1, ctypes.byref(output)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


def _unprotect(data: bytes) -> bytes:
    crypt32, kernel32 = _dpapi()
    source, _keepalive = _blob(data)
    output = DATA_BLOB()
    description = wintypes.LPWSTR()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source), ctypes.byref(description), None, None, None, 1, ctypes.byref(output)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
        if description:
            kernel32.LocalFree(ctypes.cast(description, ctypes.c_void_p))


def default_credential_path() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    if not root:
        raise RuntimeError("LOCALAPPDATA is missing; specify --credential-file explicitly.")
    return Path(root) / "CheapTrader" / "EA-G1" / "credential.dpapi"


def provision(path: Path, login: int, server: str) -> str:
    if login <= 0 or not server or len(server.encode("utf-8")) > 128:
        raise ValueError("A positive account login and server name of at most 128 UTF-8 bytes are required.")
    key = secrets.token_bytes(32)
    cleartext = json.dumps({
        "version": 1, "login": login, "server": server, "key_hex": key.hex(),
    }, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    encrypted = _protect(cleartext)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(encrypted)
    os.replace(temporary, path)
    return key.hex()


def load(path: Path) -> dict[str, Any]:
    data = json.loads(_unprotect(path.read_bytes()).decode("utf-8"))
    if (data.get("version") != 1 or not isinstance(data.get("login"), int)
            or data["login"] <= 0 or not isinstance(data.get("server"), str)
            or len(bytes.fromhex(data.get("key_hex", ""))) != 32):
        raise ValueError("Credential file contents are invalid; refusing to start.")
    return data


def matches_current(path: Path, key: bytes, login: int, server: str) -> bool:
    """Recheck the protected credential so delete/rotation revokes live sessions."""
    try:
        current = load(path)
        return (
            current["login"] == login
            and current["server"] == server
            and hmac.compare_digest(bytes.fromhex(current["key_hex"]), key)
        )
    except (OSError, ValueError, ctypes.ArgumentError):
        return False


def revoke(path: Path) -> bool:
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True
