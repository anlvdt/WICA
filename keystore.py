# -*- coding: utf-8 -*-
"""Keystore - lưu trữ API key đã mã hóa (obfuscated).

Key được XOR với machine-independent salt rồi encode base64.
File .keys là binary, không đọc được bằng mắt thường.
Không phải crypto mạnh nhưng đủ ẩn khỏi người dùng thông thường.
"""
import base64
import json
import os

_SALT = b"W1CA_AnT1Gr4v1tY_2026!"  # XOR salt cố định

def _find_keyfile() -> str:
    """Tìm file .keys - thử nhiều vị trí (frozen vs dev)."""
    import sys
    candidates = []
    # 1. Cùng folder với __file__ (dev mode hoặc _internal/)
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".keys"))
    # 2. Folder cha của _internal (= folder chứa WICA.exe)
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        candidates.append(os.path.join(exe_dir, ".keys"))
        candidates.append(os.path.join(exe_dir, "_internal", ".keys"))
    # 3. CWD
    candidates.append(os.path.join(os.getcwd(), ".keys"))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return candidates[0]  # default

_KEYFILE = _find_keyfile()


def _xor(data: bytes, salt: bytes) -> bytes:
    """XOR data với salt (lặp salt nếu ngắn hơn)."""
    return bytes(d ^ salt[i % len(salt)] for i, d in enumerate(data))


def save_keys(keys: dict[str, str]) -> str:
    """Mã hóa và lưu dict {tên: giá_trị} vào file .keys."""
    raw = json.dumps(keys, ensure_ascii=False).encode("utf-8")
    encrypted = base64.b64encode(_xor(raw, _SALT))
    with open(_KEYFILE, "wb") as f:
        f.write(encrypted)
    return _KEYFILE


def load_keys() -> dict[str, str]:
    """Đọc và giải mã file .keys → dict {tên: giá_trị}."""
    if not os.path.isfile(_KEYFILE):
        return {}
    try:
        with open(_KEYFILE, "rb") as f:
            encrypted = f.read()
        raw = _xor(base64.b64decode(encrypted), _SALT)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def get_key(name: str) -> str:
    """Lấy 1 key theo tên."""
    return load_keys().get(name, "")
