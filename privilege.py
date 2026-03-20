# -*- coding: utf-8 -*-
"""Privilege detection — EDR-safe via ctypes (no subprocess).

Detect elevation level, run context, and current user information.
Used by tools.py, agent.py, main.py to adapt behavior based on privileges.
"""
import ctypes
import ctypes.wintypes
import os
import logging

logger = logging.getLogger("antigravity.privilege")


def is_elevated() -> bool:
    """Check nếu process đang chạy elevated (admin).

    Dùng Shell32.IsUserAnAdmin — EDR-safe, không spawn process.
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def current_username() -> str:
    """Username mà process đang chạy dưới.

    Khi Run-as-different-user, đây là user admin, KHÔNG phải user logged-in.
    """
    return os.environ.get("USERNAME", "unknown")


def logged_in_username() -> str:
    """Username đang login vào Windows session.

    Khi Run-as-different-user: trả về user đang ngồi trước máy.
    Khi Run-as-admin trực tiếp: trùng với current_username().
    """
    # Nếu có biến LOGNAME hoặc từ session info
    for var in ["LOGNAME", "USER"]:
        val = os.environ.get(var)
        if val:
            return val

    # Fallback: query session via WTS API
    try:
        wtsapi32 = ctypes.windll.wtsapi32
        kernel32 = ctypes.windll.kernel32

        WTS_CURRENT_SERVER_HANDLE = 0
        WTSUserName = 5

        # Get active console session ID
        session_id = kernel32.WTSGetActiveConsoleSessionId()
        if session_id == 0xFFFFFFFF:
            return current_username()

        buf = ctypes.wintypes.LPWSTR()
        bytes_returned = ctypes.wintypes.DWORD()

        if wtsapi32.WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            WTSUserName,
            ctypes.byref(buf),
            ctypes.byref(bytes_returned),
        ):
            username = buf.value or current_username()
            wtsapi32.WTSFreeMemory(buf)
            return username
    except Exception:
        pass

    return current_username()


def get_run_context() -> str:
    """Xác định context đang chạy.

    Returns:
        "admin"          — user hiện tại là admin, login trực tiếp
        "different_user" — Run as different user (admin khác login user)
        "user"           — user thường, không elevated
    """
    if not is_elevated():
        return "user"

    cur = current_username().lower()
    logged = logged_in_username().lower()

    if cur != logged:
        return "different_user"
    return "admin"


def enable_privilege(privilege_name: str) -> bool:
    """Enable một privilege cho process hiện tại (cần admin).

    Dùng cho SE_RESTORE_PRIVILEGE, SE_BACKUP_PRIVILEGE khi load NTUSER.DAT.
    EDR-safe: advapi32.dll là Windows system DLL chuẩn.

    Lưu ý: AdjustTokenPrivileges trả về True ngay cả khi privilege không được
    grant (ERROR_NOT_ALL_ASSIGNED). Phải check GetLastError() sau khi gọi.
    """
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008
        SE_PRIVILEGE_ENABLED = 0x00000002
        ERROR_NOT_ALL_ASSIGNED = 1300

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.wintypes.DWORD),
                        ("HighPart", ctypes.wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID),
                        ("Attributes", ctypes.wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        # Open process token
        token = ctypes.wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token),
        ):
            return False

        # Lookup privilege LUID
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(
            None, privilege_name, ctypes.byref(luid)
        ):
            kernel32.CloseHandle(token)
            return False

        # Enable it
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        result = advapi32.AdjustTokenPrivileges(
            token, False, ctypes.byref(tp),
            ctypes.sizeof(tp), None, None,
        )
        # CRITICAL: AdjustTokenPrivileges trả về True kể cả khi không grant được
        # Phải check GetLastError() để biết có thực sự được grant không
        last_err = kernel32.GetLastError()
        kernel32.CloseHandle(token)
        if not result or last_err == ERROR_NOT_ALL_ASSIGNED:
            logger.debug(f"enable_privilege({privilege_name}): not assigned (err={last_err})")
            return False
        return True
    except Exception as e:
        logger.debug(f"enable_privilege({privilege_name}) failed: {e}")
        return False
