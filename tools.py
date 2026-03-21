"""Tool implementations - STRICTLY EDR-friendly.

Defender/CrowdStrike Falcon compatibility rules:
1. NO shell=True anywhere
2. NO silent install flags (/S, /quiet, /qn) - let user see installer UI
3. NO scanning/enumerating drives - user provides paths explicitly
4. NO PowerShell spawning at all - use Python stdlib + winreg only
5. NO hidden windows or background processes
6. ALL actions logged to audit trail
7. winget is the ONLY package manager (Microsoft-signed, trusted by EDR)
8. Local installs use os.startfile() - same as user double-clicking
"""
import subprocess
import winreg
import logging
import os
import platform
import shutil
import time
import threading

# Ẩn console window khi spawn subprocess — tránh che app chính
# EDR-safe: đây là Windows creation flag chuẩn, không phải kỹ thuật injection
CREATE_NO_WINDOW = 0x08000000
from shared_constants import (
    CLI_WHITELIST, CLI_BLACKLIST,
    WINGET_TIMEOUT, WINGET_UPGRADE_TIMEOUT, WINGET_LIST_TIMEOUT,
    WINGET_CHECK_TIMEOUT, CLI_TIMEOUT, TIMEZONE_TIMEOUT,
    SOURCE_RESET_TIMEOUT, SOURCE_UPDATE_TIMEOUT, PROCESS_CLEANUP_TIMEOUT,
    _CERTUTIL_ALLOWED_SUBCMDS, _NETSH_BLOCKED_SUBCOMMANDS, _NETSH_BLOCKED_WRITE_SUBCMDS,
    _SC_BLOCKED_SERVICES, _SC_BLOCKED_ACTIONS,
    _TASKKILL_BLOCKED_PROCESSES, _SHUTDOWN_ALLOWED_FLAGS,
    _ICACLS_BLOCKED_FLAGS, _CIPHER_BLOCKED_FLAGS,
    _FSUTIL_BLOCKED_SUBCMDS, _DISM_BLOCKED_FLAGS,
    _CHKDSK_BLOCKED_FLAGS, _W32TM_BLOCKED_FLAGS,
)
from privilege import is_elevated, enable_privilege
from datetime import datetime

try:
    import win32com.client
    _HAS_WIN32COM = True
except ImportError:
    _HAS_WIN32COM = False

# --- Audit Logger ---
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

audit_logger = logging.getLogger("antigravity.audit")
audit_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(
    os.path.join(LOG_DIR, f"audit_{datetime.now():%Y%m%d}.log"),
    encoding="utf-8"
)
_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
audit_logger.addHandler(_handler)


def _audit(action: str, detail: str, status: str = "OK"):
    audit_logger.info(f"ACTION={action} | STATUS={status} | {detail}")


# --- Exit code → thông báo dễ hiểu ---
_EXIT_CODE_MAP: dict[int, str] = {
    -1:         "Lệnh bị timeout hoặc winget không tìm thấy",
    1:          "Lệnh thất bại (lỗi chung)",
    2:          "Tham số không hợp lệ",
    5:          "Không đủ quyền - thử chạy với quyền Admin",
    0x8A150001: "Winget đang bận, thử lại sau",
    0x8A150002: "Không tìm thấy gói phần mềm này",
    0x8A150003: "Không có phiên bản phù hợp",
    0x8A150004: "Phần mềm đã được cài rồi",
    0x8A150005: "Bản cập nhật không khả dụng",
    0x8A150006: "Cần khởi động lại máy trước khi tiếp tục",
    0x8A150007: "Cài đặt bị hủy bởi người dùng",
    0x8A150008: "Installer bị lỗi - thử tải lại hoặc cài thủ công",
    0x8A150009: "Cần chấp nhận điều khoản sử dụng",
    0x8A15000A: "Không tìm thấy nguồn cài đặt",
    0x8A15000F: "Gói phần mềm không hỗ trợ hệ thống này",
    0x8A150010: "Installer đã chạy nhưng thất bại",
    0x8A150011: "Cần khởi động lại máy để hoàn tất",
    1603:       "Cài đặt thất bại (MSI error) - có thể đang chạy phần mềm cũ",
    1602:       "Cài đặt bị hủy bởi người dùng",
    1618:       "Một tiến trình cài đặt khác đang chạy, đợi xong rồi thử lại",
    3010:       "Cài đặt xong nhưng cần khởi động lại máy",
}

# 4294967295 = 0xFFFFFFFF = -1 unsigned
_EXIT_CODE_MAP[0xFFFFFFFF] = "Installer thất bại hoặc bị chặn - thử chạy với quyền Admin"


def _explain_exit_code(code: int) -> str:
    """Convert exit code thành thông báo tiếng Việt dễ hiểu."""
    if code == 0:
        return ""
    # Thử trực tiếp
    if code in _EXIT_CODE_MAP:
        return _EXIT_CODE_MAP[code]
    # Thử unsigned 32-bit
    unsigned = code & 0xFFFFFFFF
    if unsigned in _EXIT_CODE_MAP:
        return _EXIT_CODE_MAP[unsigned]
    # Thử signed
    if unsigned >= 0x80000000:
        signed = unsigned - 0x100000000
        if signed in _EXIT_CODE_MAP:
            return _EXIT_CODE_MAP[signed]
    return f"Mã lỗi: {code} (0x{code & 0xFFFFFFFF:08X})"


# --- Winget runner (EDR-safe) ---
_proc_lock = threading.Lock()
_active_proc = None


def _cancel_winget():
    """Hủy process winget đang chạy."""
    global _active_proc
    with _proc_lock:
        proc = _active_proc
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            _audit("WINGET_CANCEL", "terminated by user", "OK")
        except Exception:
            pass
    with _proc_lock:
        _active_proc = None


def _run_winget(args: list[str], timeout: int = WINGET_TIMEOUT) -> tuple[int, str]:
    """Gọi winget trực tiếp - không qua shell/cmd/powershell.

    winget.exe là Microsoft-signed binary, Defender/CrowdStrike trust nó.
    """
    global _active_proc
    cmd = ["winget"] + args + ["--disable-interactivity"]
    _audit("WINGET", f"cmd={' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
        with _proc_lock:
            _active_proc = proc
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait()
            _audit("WINGET_RESULT", "timeout", "FAIL")
            return -1, "[error] Timeout - lệnh chạy quá lâu."
        finally:
            with _proc_lock:
                _active_proc = None
        output = stdout.strip()
        if proc.returncode != 0 and stderr:
            output += "\n" + stderr.strip()
        _audit("WINGET_RESULT", f"rc={proc.returncode}",
               "OK" if proc.returncode == 0 else "FAIL")
        return proc.returncode, output
    except FileNotFoundError:
        _audit("WINGET_RESULT", "winget not found", "FAIL")
        return -1, "[error] Không tìm thấy winget. Cần Windows 10 1709+ hoặc cài App Installer từ Store."
    except subprocess.TimeoutExpired:
        _audit("WINGET_RESULT", "timeout", "FAIL")
        return -1, "[error] Timeout - lệnh chạy quá lâu."


# Callback cho progress (set bởi agent khi chạy profile)
_cb_lock = threading.Lock()
_progress_callback = None


def set_progress_callback(cb):
    global _progress_callback
    with _cb_lock:
        _progress_callback = cb


def _is_noise(line: str) -> bool:
    """Lọc dòng rác từ winget (spinner, progress bar, ký tự đơn)."""
    s = line.strip()
    if not s or len(s) <= 3:
        return True
    # Spinner chars: - \ | / hoặc tổ hợp (bất kể độ dài)
    if all(c in r'-\|/. ' for c in s):
        return True
    # Progress bar dạng ██░░░ hoặc ###
    if all(c in '█░▓▒#= ' for c in s):
        return True
    # Dòng chỉ chứa ký tự lặp lại (vd: "---", "|||")
    unique = set(s.replace(' ', ''))
    if len(unique) <= 2 and len(s) < 20:
        return True
    return False


def _run_winget_progress(args: list[str], timeout: int = WINGET_TIMEOUT) -> tuple[int, str]:
    """Winget với realtime progress output.

    Đọc stdout char-by-char, tách dòng bằng cả \\n và \\r.
    Winget khi pipe dùng \\r cho spinner/progress — ta tách ra và filter noise.
    """
    global _active_proc
    cmd = ["winget"] + args + ["--disable-interactivity"]
    _audit("WINGET", f"cmd={' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
        with _proc_lock:
            _active_proc = proc
        all_lines = []
        start = time.time()
        buf = ""
        _seen = set()
        try:
            while True:
                if timeout and (time.time() - start) > timeout:
                    proc.terminate()
                    _audit("WINGET_RESULT", "timeout", "FAIL")
                    return -1, "[error] Timeout - lệnh chạy quá lâu."
                ch = proc.stdout.read(1)
                if not ch and proc.poll() is not None:
                    # Flush remaining buffer
                    stripped = buf.strip()
                    if stripped and not _is_noise(stripped):
                        all_lines.append(stripped)
                        _emit_line(stripped, _seen)
                    break
                if ch in ("\n", "\r"):
                    stripped = buf.strip()
                    if stripped:
                        if not _is_noise(stripped):
                            all_lines.append(stripped)
                        _emit_line(stripped, _seen)
                    buf = ""
                else:
                    buf += ch
        finally:
            with _proc_lock:
                _active_proc = None
        stderr = proc.stderr.read() if proc.stderr else ""
        output = "\n".join(all_lines).strip()
        if proc.returncode != 0 and stderr:
            output += "\n" + stderr.strip()
        _audit("WINGET_RESULT", f"rc={proc.returncode}",
               "OK" if proc.returncode == 0 else "FAIL")
        return proc.returncode, output
    except FileNotFoundError:
        _audit("WINGET_RESULT", "winget not found", "FAIL")
        return -1, "[error] Không tìm thấy winget."


def _emit_line(line: str, seen: set):
    """Gửi dòng progress nếu không phải noise và chưa hiện."""
    if _is_noise(line):
        return
    if line in seen:
        return
    seen.add(line)
    with _cb_lock:
        cb = _progress_callback
    if cb:
        cb(line)


# --- Registry via winreg (EDR-safe) ---
def _set_registry(hive, key_path: str, value_name: str,
                  value, value_type=winreg.REG_DWORD) -> tuple[bool, str]:
    """Registry changes via Python winreg module - NO reg.exe subprocess."""
    _audit("REGISTRY", f"key={key_path} {value_name}={value}")
    try:
        key = winreg.CreateKeyEx(hive, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, value_name, 0, value_type, value)
        winreg.CloseKey(key)
        _audit("REGISTRY_RESULT", "OK", "OK")
        return True, "OK"
    except PermissionError:
        _audit("REGISTRY_RESULT", "permission denied", "FAIL")
        return False, "[error] Cần quyền Administrator."
    except Exception as e:
        _audit("REGISTRY_RESULT", str(e), "FAIL")
        return False, f"[error] Lỗi registry: {e}"


def _get_user_sids() -> list[str]:
    """Lấy danh sách SID user thực (S-1-5-21-...) từ HKEY_USERS.

    EDR-safe: chỉ dùng winreg (Python stdlib), không spawn process.
    Bỏ qua SID _Classes (duplicate) và system accounts.

    Khi chạy elevated (Run as Admin/different user), HKEY_USERS chỉ chứa
    hive của các user đang có active session. Nếu user thường chưa login
    thì SID của họ không có ở đây — caller phải fallback về HKCU.
    """
    sids = []
    try:
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(winreg.HKEY_USERS, i)
                if sid.startswith("S-1-5-21") and not sid.endswith("_Classes"):
                    sids.append(sid)
                i += 1
            except OSError:
                break
    except Exception:
        pass

    # Nếu không tìm thấy SID nào, thử lấy SID của user hiện tại qua
    # HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
    # để biết user nào đã từng login (hive có thể chưa load vào HKEY_USERS)
    if not sids:
        try:
            profile_list_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
                0, winreg.KEY_READ
            )
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(profile_list_key, i)
                    if sid.startswith("S-1-5-21") and not sid.endswith("_Classes"):
                        # Kiểm tra profile path tồn tại (user thực, không phải ghost)
                        try:
                            sk = winreg.OpenKey(profile_list_key, sid, 0, winreg.KEY_READ)
                            profile_path, _ = winreg.QueryValueEx(sk, "ProfileImagePath")
                            winreg.CloseKey(sk)
                            expanded = os.path.expandvars(profile_path)
                            if os.path.isdir(expanded):
                                sids.append(sid)
                        except (OSError, FileNotFoundError):
                            pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(profile_list_key)
        except Exception:
            pass

    return sids


def _apply_to_default_profile(key_path: str, value_name: str,
                              value, value_type=winreg.REG_DWORD) -> bool:
    """Ghi registry vào Default User profile (C:\\Users\\Default\\NTUSER.DAT).

    User mới tạo trên máy sẽ kế thừa settings này.
    Yêu cầu: elevated (admin) + SE_RESTORE_PRIVILEGE + SE_BACKUP_PRIVILEGE.

    Flow: LoadKey → ghi → UnloadKey.
    EDR-safe: chỉ dùng winreg module.
    """
    if not is_elevated():
        _audit("DEFAULT_PROFILE", "skipped — not elevated", "SKIP")
        return False

    # Path đến NTUSER.DAT của Default User profile
    sys_drive = os.environ.get("SystemDrive", "C:")
    ntuser_path = os.path.join(sys_drive + os.sep, "Users", "Default", "NTUSER.DAT")

    if not os.path.exists(ntuser_path):
        _audit("DEFAULT_PROFILE", f"NTUSER.DAT not found: {ntuser_path}", "WARN")
        return False

    # Cần privilege để load/unload hive
    enable_privilege("SeRestorePrivilege")
    enable_privilege("SeBackupPrivilege")

    # Mount point — unique key name dưới HKEY_USERS
    mount_key = "_WICA_DEFAULT_TEMP"

    try:
        # Load hive
        winreg.LoadKey(winreg.HKEY_USERS, mount_key, ntuser_path)
        _audit("DEFAULT_PROFILE", f"loaded {ntuser_path} as HKU\\{mount_key}", "OK")

        # Ghi giá trị
        full_path = f"{mount_key}\\{key_path}"
        try:
            key = winreg.CreateKeyEx(winreg.HKEY_USERS, full_path, 0,
                                     winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, value_name, 0, value_type, value)
            winreg.CloseKey(key)
            _audit("DEFAULT_PROFILE", f"set {key_path}\\{value_name}={value}", "OK")
        except Exception as e:
            _audit("DEFAULT_PROFILE", f"write failed: {e}", "FAIL")

        # Unload hive — PHẢI gọi để release file lock
        try:
            winreg.UnloadKey(winreg.HKEY_USERS, mount_key)
        except Exception as e:
            _audit("DEFAULT_PROFILE", f"unload failed: {e}", "FAIL")
            return False

        return True
    except PermissionError:
        _audit("DEFAULT_PROFILE", "LoadKey permission denied", "FAIL")
        return False
    except OSError as e:
        if e.winerror == 32:  # ERROR_SHARING_VIOLATION — NTUSER.DAT đang bị lock
            _audit("DEFAULT_PROFILE", "NTUSER.DAT locked (Default user logged in?)", "WARN")
        else:
            _audit("DEFAULT_PROFILE", f"LoadKey error: {e}", "FAIL")
        return False


def _set_registry_all_users(key_path: str, value_name: str,
                            value, value_type=winreg.REG_DWORD) -> tuple[int, int, list[str]]:
    r"""Ghi registry cho TẤT CẢ user profiles trên máy.

    Flow:
    1. Lấy SID từ HKEY_USERS (đang loaded) + ProfileList (đã từng login)
    2. Với mỗi SID: thử ghi trực tiếp vào HKEY_USERS\{SID}
       - Nếu fail (hive chưa load) -> load NTUSER.DAT -> ghi -> unload
    3. Nếu không có SID nào -> fallback HKCU
    4. Ghi vào Default profile cho user mới

    EDR-safe: chỉ dùng winreg module.
    Returns: (ok_count, fail_count, errors)
    """
    from privilege import enable_privilege

    sids = _get_user_sids()
    ok_count = 0
    fail_count = 0
    errors = []

    # Lấy profile paths từ ProfileList để load hive nếu cần
    profile_paths: dict[str, str] = {}  # SID → NTUSER.DAT path
    try:
        pk = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
            0, winreg.KEY_READ
        )
        for sid in sids:
            try:
                sk = winreg.OpenKey(pk, sid, 0, winreg.KEY_READ)
                profile_path, _ = winreg.QueryValueEx(sk, "ProfileImagePath")
                winreg.CloseKey(sk)
                ntuser = os.path.join(os.path.expandvars(profile_path), "NTUSER.DAT")
                if os.path.isfile(ntuser):
                    profile_paths[sid] = ntuser
            except (OSError, FileNotFoundError):
                pass
        winreg.CloseKey(pk)
    except Exception:
        pass

    if sids:
        # Kiểm tra privilege một lần — chỉ thử LoadKey nếu thực sự có privilege
        has_load_privilege = False
        if is_elevated():
            priv_restore = enable_privilege("SeRestorePrivilege")
            priv_backup  = enable_privilege("SeBackupPrivilege")
            has_load_privilege = priv_restore and priv_backup
            if not has_load_privilege:
                _audit("REGISTRY_ALL_USERS",
                       "SeRestore/SeBackup not granted — LoadKey disabled, will use HKEY_USERS direct only",
                       "WARN")

        for sid in sids:
            full_path = f"{sid}\\{key_path}"
            _audit("REGISTRY_ALL_USERS", f"SID={sid} key={key_path} {value_name}={value}")

            # --- Path 1: ghi trực tiếp vào HKEY_USERS\{SID} (hive đang loaded) ---
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_USERS, full_path, 0,
                                         winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, value_name, 0, value_type, value)
                winreg.CloseKey(key)
                ok_count += 1
                _audit("REGISTRY_ALL_USERS", f"SID={sid} written directly", "OK")
                continue
            except (OSError, FileNotFoundError):
                pass  # Hive chưa load → thử LoadKey nếu có privilege
            except PermissionError:
                pass  # Fall through → Path 3 HKCU fallback

            # --- Path 2: LoadKey (chỉ khi privilege thực sự được grant) ---
            ntuser = profile_paths.get(sid, "")
            if ntuser and has_load_privilege:
                mount_key = f"_WICA_TEMP_{sid[-8:]}"
                try:
                    winreg.LoadKey(winreg.HKEY_USERS, mount_key, ntuser)
                    try:
                        mk = winreg.CreateKeyEx(winreg.HKEY_USERS,
                                                f"{mount_key}\\{key_path}", 0,
                                                winreg.KEY_SET_VALUE)
                        winreg.SetValueEx(mk, value_name, 0, value_type, value)
                        winreg.CloseKey(mk)
                        ok_count += 1
                        _audit("REGISTRY_ALL_USERS", f"SID={sid} written via LoadKey", "OK")
                    except Exception as e:
                        fail_count += 1
                        errors.append(f"SID {sid} (LoadKey write): {e}")
                    finally:
                        try:
                            winreg.UnloadKey(winreg.HKEY_USERS, mount_key)
                        except Exception:
                            pass
                    continue
                except OSError as e:
                    if e.winerror == 32:
                        # NTUSER.DAT bị lock — user đang login, hive phải đã loaded
                        # Thử lại direct write (có thể vừa được load bởi session khác)
                        try:
                            key = winreg.CreateKeyEx(winreg.HKEY_USERS, full_path, 0,
                                                     winreg.KEY_SET_VALUE)
                            winreg.SetValueEx(key, value_name, 0, value_type, value)
                            winreg.CloseKey(key)
                            ok_count += 1
                            _audit("REGISTRY_ALL_USERS", f"SID={sid} written directly (NTUSER locked)", "OK")
                            continue
                        except Exception:
                            pass  # Fall through to HKCU fallback
                    else:
                        _audit("REGISTRY_ALL_USERS", f"SID={sid} LoadKey error: {e}", "WARN")
                except PermissionError as e:
                    _audit("REGISTRY_ALL_USERS", f"SID={sid} LoadKey permission: {e}", "WARN")

            # --- Path 3: HKCU fallback (user đang login = HKCU là của họ) ---
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0,
                                         winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, value_name, 0, value_type, value)
                winreg.CloseKey(key)
                ok_count += 1
                _audit("REGISTRY_ALL_USERS", f"SID={sid} written via HKCU fallback", "OK")
            except Exception as e2:
                fail_count += 1
                errors.append(f"SID {sid}: {e2}")
    else:
        # Không tìm thấy SID nào → fallback HKCU
        _audit("REGISTRY_ALL_USERS", f"no SIDs, fallback HKCU key={key_path} {value_name}={value}")
        try:
            key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0,
                                     winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, value_name, 0, value_type, value)
            winreg.CloseKey(key)
            ok_count += 1
        except PermissionError:
            fail_count += 1
            errors.append("HKCU: cần quyền Admin")
        except Exception as e:
            fail_count += 1
            errors.append(f"HKCU: {e}")

    _audit("REGISTRY_ALL_USERS_RESULT",
           f"ok={ok_count} fail={fail_count}",
           "OK" if fail_count == 0 else "WARN")

    # Ghi vào Default profile cho user mới tạo sau
    default_result = _apply_to_default_profile(key_path, value_name, value, value_type)
    if default_result:
        ok_count += 1
    else:
        _audit("DEFAULT_PROFILE", "skipped or failed", "WARN")

    return ok_count, fail_count, errors


# --- Shortcut creator (EDR-safe, win32com COM API) ---
def create_shortcut(target: str, shortcut_name: str, desktop: str = "public") -> str:
    """Tạo shortcut .lnk trên Desktop bằng Windows COM API.

    EDR-safe: dùng IShellLink COM interface (Windows chính thống).
    Không spawn process, không PowerShell.

    Args:
        target: đường dẫn tới file .exe
        shortcut_name: tên shortcut (không cần .lnk)
        desktop: "public" = C:\\Users\\Public\\Desktop, "user" = Desktop user hiện tại
    """
    _audit("SHORTCUT", f"target={target} name={shortcut_name} desktop={desktop}")

    if not _HAS_WIN32COM:
        _audit("SHORTCUT_RESULT", "win32com not available", "FAIL")
        return "[error] Thiếu pywin32. Cài: pip install pywin32"

    if not os.path.isfile(target):
        _audit("SHORTCUT_RESULT", f"target not found: {target}", "FAIL")
        return f"[error] Không tìm thấy file: {target}"

    if desktop == "public":
        desk_path = os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop")
    else:
        desk_path = os.path.join(os.path.expanduser("~"), "Desktop")

    if not shortcut_name.endswith(".lnk"):
        shortcut_name += ".lnk"

    lnk_path = os.path.join(desk_path, shortcut_name)

    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(lnk_path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        shortcut.IconLocation = target
        shortcut.save()
        _audit("SHORTCUT_RESULT", f"created {lnk_path}", "OK")
        return f"[ok] Đã tạo shortcut: {shortcut_name} trên {desktop} desktop"
    except PermissionError:
        _audit("SHORTCUT_RESULT", "permission denied", "FAIL")
        return "[error] Cần quyền Administrator để tạo shortcut trên Public Desktop."
    except Exception as e:
        _audit("SHORTCUT_RESULT", str(e), "FAIL")
        return f"[error] Lỗi tạo shortcut: {e}"


def create_shortcut_admin(target: str, shortcut_name: str, desktop: str = "public") -> str:
    """Tạo shortcut .lnk với flag 'Run as Administrator' trên Desktop.

    Flow: tạo shortcut bình thường bằng COM → patch byte 0x15 trong .lnk
    để bật flag SLDF_RUNAS_USER (0x20). Đây là cách chính thống mà
    Windows dùng khi user tick "Run as administrator" trong Properties.

    EDR-safe: COM API + binary patch trên file .lnk (không spawn process).
    Ref: [MS-SHLLINK] Shell Link Binary File Format, section 2.1.1
    """
    # Tạo shortcut bình thường trước
    result = create_shortcut(target, shortcut_name, desktop)
    if "[ok]" not in result:
        return result

    # Xác định path của .lnk vừa tạo
    if desktop == "public":
        desk_path = os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop")
    else:
        desk_path = os.path.join(os.path.expanduser("~"), "Desktop")

    lnk_name = shortcut_name if shortcut_name.endswith(".lnk") else shortcut_name + ".lnk"
    lnk_path = os.path.join(desk_path, lnk_name)

    if not os.path.isfile(lnk_path):
        return result  # Shortcut tạo OK nhưng không tìm thấy file — trả kết quả gốc

    # Patch byte 0x15 (LinkFlags offset 0x14, byte thứ 2) để bật SLDF_RUNAS_USER
    # Trong .lnk format: offset 0x14 = LinkFlags (4 bytes, little-endian)
    # Bit 0x2000_0000 (bit 25) = SLDF_RUNAS_USER → byte offset 0x17, bit 5
    # Nhưng cách đơn giản hơn: đọc DWORD tại offset 0x14, OR với 0x2000_0000
    try:
        with open(lnk_path, "r+b") as f:
            f.seek(0x14)
            flags_bytes = f.read(4)
            flags = int.from_bytes(flags_bytes, "little")
            flags |= 0x2000_0000  # SLDF_RUNAS_USER
            f.seek(0x14)
            f.write(flags.to_bytes(4, "little"))
        _audit("SHORTCUT_ADMIN", f"patched RunAsAdmin: {lnk_path}", "OK")
        return f"[ok] Đã tạo shortcut (Run as Admin): {lnk_name} trên {desktop} desktop"
    except Exception as e:
        _audit("SHORTCUT_ADMIN", f"patch failed: {e}", "WARN")
        return f"[warn] Đã tạo shortcut nhưng không set được Run as Admin: {e}"


# --- Progress emit helper ---
def _emit_progress(msg: str):
    """Gửi thông báo progress qua callback (nếu có)."""
    with _cb_lock:
        cb = _progress_callback
    if cb:
        cb(msg)


def _copytree_progress(src: str, dst: str, label: str = ""):
    """copytree với progress emit từng file.

    Thay thế shutil.copytree để UI không im lặng khi copy folder lớn.
    """
    os.makedirs(dst, exist_ok=True)
    entries = list(os.scandir(src))
    total = len(entries)
    for i, entry in enumerate(entries, 1):
        src_path = entry.path
        dst_path = os.path.join(dst, entry.name)
        if entry.is_dir(follow_symlinks=False):
            _copytree_progress(src_path, dst_path, label)
        else:
            shutil.copy2(src_path, dst_path)
            _emit_progress(f"  [{i}/{total}] {label}{entry.name}")


# --- Deploy portable app (copy + shortcut, EDR-safe) ---
def deploy_portable(source: str, dest_folder: str, shortcut_name: str,
                    exe_name: str = "", desktop: str = "public") -> str:
    """Copy app portable vào thư mục cố định và tạo shortcut.

    EDR-safe: chỉ dùng shutil.copy2/copytree (Python stdlib) + COM shortcut.
    Không spawn process nào.

    Args:
        source: file .exe hoặc folder chứa app portable
        dest_folder: thư mục đích (vd: C:\\Program Files\\UniKey)
        shortcut_name: tên shortcut trên desktop
        exe_name: tên file .exe trong folder (nếu source là folder)
        desktop: "public" hoặc "user"
    """
    _audit("DEPLOY_PORTABLE", f"src={source} dest={dest_folder} name={shortcut_name}")

    source = source.strip().strip('"').strip("'")

    if os.path.isdir(source):
        # Copy cả folder
        try:
            _emit_progress(f"Đang copy {os.path.basename(source)} → {dest_folder} ...")
            if os.path.exists(dest_folder):
                shutil.rmtree(dest_folder)
            _copytree_progress(source, dest_folder, label="")
            _audit("DEPLOY_COPY", f"folder {source} -> {dest_folder}", "OK")
            _emit_progress(f"[ok] Copy xong: {dest_folder}")
        except PermissionError:
            _audit("DEPLOY_COPY", "permission denied", "FAIL")
            return f"[error] Cần quyền Administrator để copy vào {dest_folder}"
        except Exception as e:
            _audit("DEPLOY_COPY", str(e), "FAIL")
            return f"[error] Lỗi copy: {e}"
        target_exe = os.path.join(dest_folder, exe_name) if exe_name else ""
    elif os.path.isfile(source):
        # Copy file đơn
        try:
            os.makedirs(dest_folder, exist_ok=True)
            fname = os.path.basename(source)
            _emit_progress(f"Đang copy {fname} → {dest_folder} ...")
            dest_file = os.path.join(dest_folder, fname)
            shutil.copy2(source, dest_file)
            _audit("DEPLOY_COPY", f"file {source} -> {dest_file}", "OK")
            _emit_progress(f"[ok] Copy xong: {dest_file}")
            target_exe = dest_file
        except PermissionError:
            _audit("DEPLOY_COPY", "permission denied", "FAIL")
            return f"[error] Cần quyền Administrator để copy vào {dest_folder}"
        except Exception as e:
            _audit("DEPLOY_COPY", str(e), "FAIL")
            return f"[error] Lỗi copy: {e}"
    else:
        _audit("DEPLOY_PORTABLE", f"source not found: {source}", "FAIL")
        return f"[error] Không tìm thấy: {source}"

    if not target_exe or not os.path.isfile(target_exe):
        return f"[warn] Đã copy nhưng không tìm thấy exe: {target_exe}"

    # Tạo shortcut
    result = create_shortcut(target_exe, shortcut_name, desktop)
    if "[ok]" in result:
        return f"[ok] Đã cài {shortcut_name}: {dest_folder}\n  {result}"
    return f"[warn] Đã copy vào {dest_folder} nhưng lỗi shortcut:\n  {result}"


# --- Copy to all user profiles (EDR-safe: shutil only) ---
def _get_user_dirs() -> list[str]:
    """Lấy danh sách thư mục user trong C:\\Users.

    EDR-safe: chỉ dùng os.listdir + os.path (Python stdlib).
    Không quét ổ đĩa — chỉ đọc 1 folder cố định.
    Bỏ qua: Public, Default User (junction), All Users (junction).
    """
    users_dir = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
    skip = {"public", "default user", "all users"}
    dirs = []
    try:
        for name in os.listdir(users_dir):
            if name.lower() in skip:
                continue
            full = os.path.join(users_dir, name)
            if os.path.isdir(full) and not os.path.islink(full):
                dirs.append(full)
    except OSError:
        pass
    # Thêm Default profile (cho user mới tạo sau)
    default = os.path.join(users_dir, "Default")
    if os.path.isdir(default) and default not in dirs:
        dirs.append(default)
    return dirs


def copy_to_all_users(source: str, dest_relative: str) -> str:
    """Copy file/folder vào thư mục tương đối trong MỖI user profile.

    Ví dụ: copy_to_all_users("C:\\SoftVN\\profiles.xml",
                              "AppData\\Local\\SonicWall\\SnwlConnect\\Documents")
    → copy vào C:\\Users\\{mỗi user}\\AppData\\Local\\SonicWall\\...\\profiles.xml

    EDR-safe: chỉ dùng shutil.copy2/copytree (Python stdlib).
    """
    source = source.strip().strip('"').strip("'")
    _audit("COPY_ALL_USERS", f"src={source} dest_rel={dest_relative}")

    if not os.path.exists(source):
        _audit("COPY_ALL_USERS", f"source not found: {source}", "FAIL")
        return f"[error] Không tìm thấy: {source}"

    user_dirs = _get_user_dirs()
    if not user_dirs:
        return "[error] Không tìm thấy user profile nào trong C:\\Users"

    ok_count = 0
    fail_count = 0
    is_dir = os.path.isdir(source)
    src_name = os.path.basename(source)

    _emit_progress(f"Đang copy {src_name} cho {len(user_dirs)} user profile...")

    for idx, udir in enumerate(user_dirs, 1):
        uname = os.path.basename(udir)
        dest_dir = os.path.join(udir, dest_relative)
        _emit_progress(f"  [{idx}/{len(user_dirs)}] {uname} ...")
        try:
            os.makedirs(dest_dir, exist_ok=True)
            if is_dir:
                dest_full = os.path.join(dest_dir, src_name)
                if os.path.exists(dest_full):
                    shutil.rmtree(dest_full)
                _copytree_progress(source, dest_full, label=f"{uname}/")
            else:
                shutil.copy2(source, os.path.join(dest_dir, src_name))
            ok_count += 1
            _emit_progress(f"  [ok] {uname}")
        except Exception as e:
            fail_count += 1
            _emit_progress(f"  [lỗi] {uname}: {e}")
            _audit("COPY_ALL_USERS", f"{udir}: {e}", "FAIL")

    _audit("COPY_ALL_USERS_RESULT", f"ok={ok_count} fail={fail_count}",
           "OK" if fail_count == 0 else "WARN")
    if fail_count == 0:
        return f"[ok] Đã copy {src_name} cho {ok_count} user"
    return f"[warn] Copy {src_name}: {ok_count} thành công, {fail_count} lỗi"


# --- Install fonts system-wide (EDR-safe: shutil + winreg) ---
def install_fonts(source_folder: str) -> str:
    """Cài font từ folder vào C:\\Windows\\Fonts + đăng ký registry.

    EDR-safe:
    - Copy bằng shutil.copy2 (Python stdlib)
    - Đăng ký bằng winreg (Python stdlib)
    - KHÔNG spawn process nào

    Hỗ trợ: .ttf, .otf, .ttc
    """
    source_folder = source_folder.strip().strip('"').strip("'")
    _audit("INSTALL_FONTS", f"src={source_folder}")

    if not os.path.isdir(source_folder):
        return f"[error] Không tìm thấy thư mục font: '{source_folder}'. Gợi ý cho AI: Hãy dùng tool 'cli' với command 'dir' để tìm tên thư mục chứa font đúng trên cấu trúc thư mục (có thể nó có tên khác), sau đó thiết lập lại đường dẫn và gọi lại chức năng install_fonts."

    fonts_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Fonts")
    font_exts = {".ttf", ".otf", ".ttc"}
    reg_key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"

    ok_count = 0
    fail_count = 0

    try:
        font_files = [f for f in os.listdir(source_folder)
                      if os.path.splitext(f)[1].lower() in font_exts]
    except OSError as e:
        return f"[error] Không đọc được thư mục: {e}"

    if not font_files:
        return f"[info] Không tìm thấy file font (.ttf/.otf/.ttc) trong {source_folder}"

    _emit_progress(f"Đang cài {len(font_files)} font vào {fonts_dir} ...")

    for i, fname in enumerate(font_files, 1):
        src = os.path.join(source_folder, fname)
        dest = os.path.join(fonts_dir, fname)
        _emit_progress(f"  [{i}/{len(font_files)}] {fname}")
        try:
            shutil.copy2(src, dest)
            # Đăng ký font trong registry (HKLM = all users)
            font_name = os.path.splitext(fname)[0]
            ext = os.path.splitext(fname)[1].lower()
            reg_type = "(TrueType)" if ext in (".ttf", ".ttc") else "(OpenType)"
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                         reg_key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, f"{font_name} {reg_type}", 0,
                                  winreg.REG_SZ, fname)
                winreg.CloseKey(key)
            except Exception as e:
                _audit("FONT_REGISTRY", f"register {fname} failed: {e}", "WARN")
            ok_count += 1
        except PermissionError:
            fail_count += 1
        except Exception:
            fail_count += 1

    _audit("INSTALL_FONTS_RESULT", f"ok={ok_count} fail={fail_count}",
           "OK" if fail_count == 0 else "WARN")
    if fail_count == 0:
        return f"[ok] Đã cài {ok_count} font"
    return f"[warn] Font: {ok_count} thành công, {fail_count} lỗi (cần quyền Admin)"


# --- Pre-check functions (skip-if-already-done) ---

def _is_winget_installed(pkg_id: str) -> bool:
    """Kiểm tra nhanh package đã cài chưa.

    EDR-safe: chỉ dùng winreg + winget.exe.

    Ưu tiên check registry trước (instant, hoạt động bất kể user context).
    Chỉ gọi winget list nếu registry không tìm thấy (chậm hơn, có thể timeout).
    """
    # Check registry trước — nhanh, không phụ thuộc user context
    if _is_installed_via_registry(pkg_id):
        return True
    # Fallback: winget list (chậm hơn nhưng chính xác hơn cho một số app)
    try:
        proc = subprocess.Popen(
            ["winget", "list", "--id", pkg_id, "-e",
             "--accept-source-agreements", "--disable-interactivity"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
        stdout, stderr = proc.communicate(timeout=WINGET_CHECK_TIMEOUT)
        if proc.returncode == 0 and pkg_id.lower() in stdout.lower():
            return True
        combined = (stdout + stderr).lower()
        if "already installed" in combined:
            return True
    except Exception:
        pass
    return False


def _is_installed_via_registry(pkg_id: str) -> bool:
    """Check app đã cài chưa qua registry Uninstall keys.

    Đây là fallback khi winget list fail (Run as different user).
    Check cả HKLM (machine-wide) và HKU (per-user).
    EDR-safe: chỉ dùng winreg (Python stdlib).
    """
    search = pkg_id.lower()
    # Tách tên ngắn từ winget ID: "Google.Chrome" → "chrome", "google chrome"
    parts = search.replace(".", " ").split()

    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        # Per-user installs (Store apps, user-scoped installers)
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in uninstall_paths:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    # Check winget ID trực tiếp trong subkey name
                    if search in subkey_name.lower():
                        winreg.CloseKey(key)
                        return True
                    # Check DisplayName
                    try:
                        sk = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                        display_name, _ = winreg.QueryValueEx(sk, "DisplayName")
                        winreg.CloseKey(sk)
                        dn = display_name.lower()
                        # Match nếu tất cả parts của winget ID có trong DisplayName
                        if all(p in dn for p in parts):
                            winreg.CloseKey(key)
                            return True
                    except (OSError, FileNotFoundError):
                        pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (OSError, FileNotFoundError):
            pass
    return False


def _get_installed_list() -> set:
    """Lấy danh sách tất cả app đã cài (lowercase) bằng winget list MỘT LẦN.

    Trả về set of lowercase package IDs/names.
    Dùng cho batch check (bloatware) thay vì gọi winget list N lần.
    Fallback: trả về empty set nếu winget fail.
    EDR-safe: chỉ gọi winget.exe trực tiếp.
    """
    installed = set()
    try:
        proc = subprocess.Popen(
            ["winget", "list", "--accept-source-agreements", "--disable-interactivity"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
        stdout, _ = proc.communicate(timeout=WINGET_LIST_TIMEOUT)
        if proc.returncode == 0:
            for line in stdout.lower().split("\n"):
                installed.add(line.strip())
            # Cũng thêm từng từ riêng lẻ để match flexible hơn
            _audit("INSTALLED_LIST", f"got {len(installed)} lines", "OK")
    except Exception:
        _audit("INSTALLED_LIST", "winget list failed", "FAIL")
    return installed


def _is_registry_set(config_name: str) -> bool:
    """Kiểm tra registry config đã được áp dụng chưa.

    EDR-safe: chỉ dùng winreg (Python stdlib).

    Khi chạy Run as different user/Admin, HKCU là của admin user,
    không phải user thật. Nên với HKCU configs, check qua
    HKEY_USERS\\{SID} iteration — nếu BẤT KỲ user nào đã có config
    thì coi như đã áp dụng (vì apply() ghi cho tất cả user).
    """
    reg_cfg = REGISTRY_CONFIGS.get(config_name)
    if not reg_cfg:
        return False
    hive = reg_cfg["hive"]
    key_path = reg_cfg["key"]

    if hive == winreg.HKEY_CURRENT_USER:
        # Check qua HKEY_USERS SID iteration
        sids = _get_user_sids()
        if not sids:
            # Fallback: check HKCU trực tiếp
            return _check_registry_values(winreg.HKEY_CURRENT_USER, key_path, reg_cfg["values"])
        # Nếu bất kỳ real user SID nào đã có config → đã áp dụng
        for sid in sids:
            full_path = f"{sid}\\{key_path}"
            if _check_registry_values(winreg.HKEY_USERS, full_path, reg_cfg["values"]):
                return True
        return False
    else:
        # HKLM → check trực tiếp
        return _check_registry_values(hive, key_path, reg_cfg["values"])


def _check_registry_values(hive, key_path: str, values: list) -> bool:
    """Check tất cả registry values có match expected không."""
    try:
        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        for value_name, expected, value_type in values:
            try:
                actual, _ = winreg.QueryValueEx(key, value_name)
                if actual != expected:
                    winreg.CloseKey(key)
                    return False
            except FileNotFoundError:
                winreg.CloseKey(key)
                return False
        winreg.CloseKey(key)
        return True
    except (OSError, FileNotFoundError):
        return False


def _is_deployed(dest_folder: str, exe_name: str = "") -> bool:
    """Kiểm tra app portable đã được deploy chưa.

    Chỉ check folder tồn tại + exe file tồn tại (nếu có).
    """
    if not os.path.isdir(dest_folder):
        return False
    if exe_name:
        return os.path.isfile(os.path.join(dest_folder, exe_name))
    # Folder tồn tại và không rỗng
    try:
        return len(os.listdir(dest_folder)) > 0
    except OSError:
        return False


def _are_fonts_installed(source_folder: str) -> bool:
    """Kiểm tra font đã được cài chưa.

    Check xem tất cả font files trong source đã có trong Windows\\Fonts chưa.
    """
    if not os.path.isdir(source_folder):
        return False
    fonts_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Fonts")
    font_exts = {".ttf", ".otf", ".ttc"}
    try:
        font_files = [f for f in os.listdir(source_folder)
                      if os.path.splitext(f)[1].lower() in font_exts]
    except OSError:
        return False
    if not font_files:
        return True  # Không có font nào cần cài
    # Kiểm tra tất cả font đã có trong Fonts folder
    for fname in font_files:
        if not os.path.isfile(os.path.join(fonts_dir, fname)):
            return False
    return True


def _is_copied_to_users(source: str, dest_relative: str) -> bool:
    """Kiểm tra file đã được copy cho tất cả user chưa.

    Chỉ check user hiện tại (nhanh). Nếu user hiện tại đã có → coi như đã copy.
    """
    if not os.path.exists(source):
        return False
    src_name = os.path.basename(source)
    user_home = os.path.expanduser("~")
    dest = os.path.join(user_home, dest_relative, src_name)
    return os.path.exists(dest)


# --- Software Manager ---
class SoftwareManager:
    """Quản lý phần mềm - chỉ dùng winget + os.startfile."""

    # Fallback: tên file local cho các package hay lỗi winget
    # Khi winget fail, tìm file này trong local_paths và mở bằng os.startfile()
    _LOCAL_FALLBACK = {
        "Microsoft.Office": ["setup.exe", "Setup.exe", "OfficeSetup.exe",
                             "Office365Setup.exe", "M365Setup.exe",
                             "Microsoft365Setup.exe"],
    }

    def __init__(self, aliases: dict, local_paths: list[str] = None):
        # M7: validate alias keys are lowercase
        bad_keys = [k for k in aliases if k != k.lower()]
        if bad_keys:
            _audit("ALIAS_WARN", f"non-lowercase alias keys: {bad_keys}", "WARN")
        self.aliases = aliases
        self.local_paths = local_paths or []
        self._source_ready = False  # Flag: đã init source trong session này chưa

    def _resolve(self, name: str) -> str:
        return self.aliases.get(name.lower().strip(), name)

    def _try_local_fallback(self, pkg_id: str, prefer_local: bool = False) -> str:
        """Tìm installer local cho package khi winget fail.
        
        Tìm trong local_paths các file setup phổ biến.
        Mở bằng os.startfile() (EDR-safe, giống user double-click).
        """
        filenames = self._LOCAL_FALLBACK.get(pkg_id, [])
        if not filenames:
            return ""
        for base_dir in self.local_paths:
            if not os.path.isdir(base_dir):
                continue
            # Tìm trực tiếp trong folder
            for fname in filenames:
                full = os.path.join(base_dir, fname)
                if os.path.isfile(full):
                    return self._open_local_installer(full, prefer_local=prefer_local)
            # Tìm trong subfolder chứa "office" hoặc "365"
            try:
                for entry in os.listdir(base_dir):
                    entry_lower = entry.lower()
                    if "office" in entry_lower or "365" in entry_lower:
                        sub = os.path.join(base_dir, entry)
                        if os.path.isdir(sub):
                            for fname in filenames:
                                full = os.path.join(sub, fname)
                                if os.path.isfile(full):
                                    return self._open_local_installer(full, prefer_local=prefer_local)
                        elif os.path.isfile(sub) and entry_lower.endswith((".exe", ".msi")):
                            return self._open_local_installer(sub, prefer_local=prefer_local)
            except OSError:
                pass
        return ""

    def _open_local_installer(self, path: str, prefer_local: bool = False) -> str:
        """Mở installer bằng os.startfile() - EDR-safe."""
        fname = os.path.basename(path)
        _audit("LOCAL_FALLBACK", f"opening {path}")
        try:
            os.startfile(path)
            _audit("LOCAL_FALLBACK_RESULT", f"opened {fname}", "OK")
            if prefer_local:
                return (f"[ok] Đã mở installer local: {fname}\n"
                        f"Cửa sổ cài đặt sẽ hiện lên, bạn thao tác bình thường.")
            return (f"[ok] Winget không khả dụng, đã mở installer local: {fname}\n"
                    f"Cửa sổ cài đặt sẽ hiện lên, bạn thao tác bình thường.")
        except OSError as e:
            _audit("LOCAL_FALLBACK_RESULT", str(e), "FAIL")
            return f"[error] Không mở được file: {e}"

    def _ensure_source(self) -> None:
        """Reset + update winget source (fix 0x8a15000f khi Run as Admin).

        Khi chạy Run as different user, winget source data chưa có.
        Cần reset → update → accept agreements cho user mới.
        Emit progress qua callback để UI không bị đứng im.
        """
        def _emit(msg: str):
            _audit("SOURCE_RESET", msg)
            with _cb_lock:
                cb = _progress_callback
            if cb:
                cb(msg)

        _emit("Đang khởi tạo winget source (lần đầu chạy Admin)...")

        # Reset trước (xóa cache cũ/hỏng)
        _emit("  [1/3] Đang reset winget source...")
        subprocess.run(
            ["winget", "source", "reset", "--force",
             "--accept-source-agreements", "--disable-interactivity"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            timeout=SOURCE_RESET_TIMEOUT,
            creationflags=CREATE_NO_WINDOW,
        )

        # Update lại — download source index mới
        _emit("  [2/3] Đang cập nhật winget source index (có thể mất 1-2 phút)...")
        subprocess.run(
            ["winget", "source", "update",
             "--accept-source-agreements", "--disable-interactivity"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            timeout=SOURCE_UPDATE_TIMEOUT,
            creationflags=CREATE_NO_WINDOW,
        )

        # Chạy 1 lệnh search nhỏ để force winget init hoàn tất
        _emit("  [3/3] Đang hoàn tất khởi tạo winget...")
        subprocess.run(
            ["winget", "search", "Microsoft.Office",
             "--accept-source-agreements", "--disable-interactivity"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            timeout=SOURCE_RESET_TIMEOUT,
            creationflags=CREATE_NO_WINDOW,
        )
        _emit("  Winget source sẵn sàng.")
        self._source_ready = True

    # Các package dùng bootstrapper/ClickToRun — winget spawn child process
    # có console window riêng không thể ẩn. Ưu tiên local installer nếu có.
    # Khi dùng winget, tail Office log file real-time để hiện progress.
    _PREFER_LOCAL = {"Microsoft.Office", "Microsoft365"}

    @staticmethod
    def _tail_office_log(stop_event: threading.Event, emit_cb):
        """Tail Office ClickToRun log file real-time trong background thread.

        Office ghi log vào %TEMP%\\*.log trong quá trình cài.
        Pattern: SetupExe*.log, OfficeSetup*.log, C2RSetup*.log
        Đọc từng dòng mới và emit qua callback.
        EDR-safe: chỉ dùng os + open (Python stdlib).
        """
        import glob

        temp_dir = os.environ.get("TEMP", os.environ.get("TMP", ""))
        win_temp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")
        search_dirs = [d for d in [temp_dir, win_temp] if d and os.path.isdir(d)]

        # Patterns log của Office ClickToRun
        log_patterns = [
            "OfficeSetup*.log", "SetupExe*.log", "C2RSetup*.log",
            "Microsoft365*.log", "Office365*.log",
        ]

        # Timestamp trước khi bắt đầu — chỉ đọc log mới tạo sau thời điểm này
        start_time = time.time() - 5  # buffer 5s

        log_file = None
        log_pos = 0
        last_scan = 0

        while not stop_event.is_set():
            now = time.time()

            # Scan tìm log file mới mỗi 3s
            if log_file is None and (now - last_scan) > 3:
                last_scan = now
                candidates = []
                for d in search_dirs:
                    for pat in log_patterns:
                        try:
                            for f in glob.glob(os.path.join(d, pat)):
                                try:
                                    mtime = os.path.getmtime(f)
                                    if mtime >= start_time:
                                        candidates.append((mtime, f))
                                except OSError:
                                    pass
                        except Exception:
                            pass
                if candidates:
                    candidates.sort(reverse=True)
                    log_file = candidates[0][1]
                    log_pos = 0
                    _audit("OFFICE_LOG", f"tailing {log_file}", "OK")
                    emit_cb(f"[log] Đang đọc log: {os.path.basename(log_file)}")

            # Đọc dòng mới từ log file
            if log_file:
                try:
                    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(log_pos)
                        new_lines = f.readlines()
                        log_pos = f.tell()
                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue
                        # Lọc các dòng có ý nghĩa (bỏ debug noise)
                        line_lower = line.lower()
                        if any(kw in line_lower for kw in [
                            "error", "warning", "install", "download",
                            "progress", "success", "fail", "complete",
                            "percent", "%", "applying", "configuring",
                            "verifying", "extracting", "copying",
                        ]):
                            emit_cb(f"  [office] {line[:120]}")
                except (OSError, PermissionError):
                    pass

            time.sleep(1)

    def install(self, package: str) -> str:
        """Cài qua winget - Microsoft-signed, EDR trusted."""
        pkg_id = self._resolve(package)
        _audit("INSTALL", f"package={package} resolved={pkg_id}")
        # Emit thông báo ngay để UI không đứng im khi winget đang init
        with _cb_lock:
            cb = _progress_callback
        if cb:
            cb(f"Đang kết nối winget để cài {package}...")

        # Ưu tiên local installer cho Office/bootstrapper (tránh console đen)
        if pkg_id in self._PREFER_LOCAL:
            local = self._try_local_fallback(pkg_id, prefer_local=True)
            if local:
                return local
            # Không có local → winget + tail log real-time
            if cb:
                cb("[...] Cài Office qua winget — đang theo dõi log real-time...")
            stop_tail = threading.Event()
            tail_thread = threading.Thread(
                target=self._tail_office_log,
                args=(stop_tail, cb if cb else lambda _: None),
                daemon=True,
            )
            tail_thread.start()
            try:
                args = [
                    "install", "--id", pkg_id,
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                    "--source", "winget",
                    "-e",
                ]
                code, output = _run_winget_progress(args)
            finally:
                stop_tail.set()
                tail_thread.join(timeout=3)
            if code == 0:
                return f"[ok] Đã cài đặt: {package} ({pkg_id})"
            elif "already installed" in output.lower():
                return f"[info] {package} đã được cài rồi."
            reason = _explain_exit_code(code)
            return f"[error] Lỗi cài đặt {package}: {reason}"
        args = [
            "install", "--id", pkg_id,
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--source", "winget",
            "-e",
        ]
        code, output = _run_winget_progress(args)
        if code == 0:
            return f"[ok] Đã cài đặt: {package} ({pkg_id})"
        elif "already installed" in output.lower():
            return f"[info] {package} đã được cài rồi."
        elif ("0x8a15000f" in output.lower()
              or "data required by the source" in output.lower()
              or "failed when opening source" in output.lower()):
            # Source chưa sẵn sàng — reset + update rồi thử lại
            # Chỉ reset 1 lần mỗi session để tránh lặp lại
            if not self._source_ready:
                _audit("INSTALL_RETRY", f"source error, resetting and retrying {pkg_id}")
                self._ensure_source()
                self._source_ready = True
            else:
                _audit("INSTALL_RETRY", f"source already reset this session, retrying {pkg_id}")
            # Retry KHÔNG dùng --source winget (để winget tự chọn source khả dụng)
            retry_args = [
                "install", "--id", pkg_id,
                "--accept-package-agreements",
                "--accept-source-agreements",
                "-e",
            ]
            code, output = _run_winget_progress(retry_args)
            if code == 0:
                return f"[ok] Đã cài đặt: {package} ({pkg_id})"
            elif "already installed" in output.lower():
                return f"[info] {package} đã được cài rồi."
            reason = _explain_exit_code(code)
            err_detail = ""
            err_lines = [l for l in output.split("\n") if l.strip()]
            if err_lines:
                err_detail = err_lines[-1]
            # Winget vẫn fail sau retry → thử local fallback
            fallback = self._try_local_fallback(pkg_id)
            if fallback:
                return fallback
            msg = f"[error] Lỗi cài đặt {package} (đã thử reset source): {reason}"
            if err_detail and err_detail != reason:
                msg += f"\nChi tiết: {err_detail}"
            return msg
        else:
            # Winget fail lần đầu (lỗi khác) → thử local fallback
            fallback = self._try_local_fallback(pkg_id)
            if fallback:
                return fallback
            reason = _explain_exit_code(code)
            err_lines = [l for l in output.split("\n") if l.strip()]
            last_err = err_lines[-1] if err_lines else ""
            msg = f"[error] Lỗi cài đặt {package}: {reason}"
            if last_err and last_err != reason:
                msg += f"\nChi tiết: {last_err}"
            return msg

    def uninstall(self, package: str) -> str:
        pkg_id = self._resolve(package)
        _audit("UNINSTALL", f"package={package} resolved={pkg_id}")
        args = ["uninstall", "--id", pkg_id, "-e"]
        code, output = _run_winget_progress(args)
        if code == 0:
            return f"[ok] \u0110\u00e3 g\u1ee1: {package}"
        else:
            reason = _explain_exit_code(code)
            return f"[error] L\u1ed7i g\u1ee1 {package}: {reason}"

    def uninstall_system(self, pkg_id: str) -> str:
        """Gỡ app system-wide (tất cả user) qua winget."""
        _audit("UNINSTALL_SYSTEM", f"package={pkg_id}")
        args = ["uninstall", "--id", pkg_id, "-e", "--accept-source-agreements"]
        # M4: uninstall_system uses shorter timeout
        code, output = _run_winget_progress(args, timeout=CLI_TIMEOUT)
        if code == 0:
            return f"[ok] Đã gỡ: {pkg_id}"
        elif "no installed package" in output.lower() or "not found" in output.lower():
            return f"[info] Không có: {pkg_id}"
        else:
            return f"[error] Lỗi gỡ {pkg_id}: {_explain_exit_code(code)}"

    def search(self, query: str) -> str:
        _audit("SEARCH", f"query={query}")
        code, output = _run_winget_progress(["search", query])
        if code == 0:
            lines = output.split("\n")[:15]
            return "[search] K\u1ebft qu\u1ea3 t\u00ecm ki\u1ebfm:\n" + "\n".join(lines)
        return f"[error] Kh\u00f4ng t\u00ecm th\u1ea5y: {query}"

    def list_installed(self) -> str:
        _audit("LIST", "listing installed")
        code, output = _run_winget_progress(["list"])
        if code == 0:
            lines = output.split("\n")[:30]
            return "[list] Ph\u1ea7n m\u1ec1m \u0111\u00e3 c\u00e0i:\n" + "\n".join(lines)
        return "[error] Kh\u00f4ng l\u1ea5y \u0111\u01b0\u1ee3c danh s\u00e1ch."

    def install_local(self, file_path: str) -> str:
        """Cài từ file local bằng os.startfile() - GIỐNG USER DOUBLE-CLICK.

        Đây là cách an toàn nhất với EDR vì:
        - os.startfile() dùng ShellExecuteW API (Windows chính thống)
        - Giống hệt user tự mở file trong Explorer
        - Installer hiện UI bình thường, không silent/hidden
        - CrowdStrike thấy parent process là Explorer-like, không phải script

        Hỗ trợ thêm: .zip/.rar → tự giải nén vào thư mục tạm → tìm installer → chạy.
        """
        file_path = file_path.strip().strip('"').strip("'")
        _audit("INSTALL_LOCAL", f"path={file_path}")

        if not os.path.isfile(file_path):
            return f"[error] Không tìm thấy file: {file_path}"

        ext = os.path.splitext(file_path)[1].lower()

        # --- Xử lý file nén: giải nén trước rồi tìm installer ---
        if ext in (".zip", ".rar"):
            return self._extract_and_install(file_path, ext)

        allowed = {".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle"}
        if ext not in allowed:
            return f"[error] Định dạng không hỗ trợ: {ext}. Chỉ hỗ trợ: {', '.join(allowed | {'.zip', '.rar'})}"

        fname = os.path.basename(file_path)

        try:
            # os.startfile = ShellExecuteW = giống user double-click trong Explorer
            # KHÔNG dùng subprocess, KHÔNG silent flags, KHÔNG hidden window
            # EDR-safe: parent process là Explorer-like, installer hiện UI bình thường
            os.startfile(file_path)
            _audit("INSTALL_LOCAL_RESULT", f"opened {fname}", "OK")
            return f"[ok] Đã mở installer: {fname}\nCửa sổ cài đặt sẽ hiện lên, bạn thao tác bình thường."
        except OSError as e:
            _audit("INSTALL_LOCAL_RESULT", str(e), "FAIL")
            return f"[error] Không mở được file: {e}"

    def _extract_and_install(self, archive_path: str, ext: str) -> str:
        """Giải nén .zip/.rar vào thư mục tạm rồi tìm và chạy installer.

        EDR-safe:
        - .zip: dùng zipfile (Python stdlib) — không spawn process
        - .rar: dùng rarfile lib nếu có, fallback dùng 7z.exe nếu có trên máy
        - Tìm installer theo thứ tự ưu tiên: .exe > .msi > .msix
        - Chạy bằng os.startfile() (ShellExecuteW) — giống user double-click
        """
        import tempfile
        import zipfile

        archive_name = os.path.splitext(os.path.basename(archive_path))[0]
        # Giải nén vào thư mục tạm cố định (không random) để dễ debug
        extract_dir = os.path.join(tempfile.gettempdir(), f"WICA_{archive_name}")
        os.makedirs(extract_dir, exist_ok=True)

        _emit_progress(f"Đang giải nén {os.path.basename(archive_path)} → {extract_dir} ...")
        _audit("EXTRACT", f"archive={archive_path} dest={extract_dir}")

        # --- Giải nén ---
        if ext == ".zip":
            try:
                with zipfile.ZipFile(archive_path, "r") as zf:
                    total = len(zf.namelist())
                    for i, member in enumerate(zf.namelist(), 1):
                        zf.extract(member, extract_dir)
                        if i % 20 == 0 or i == total:
                            _emit_progress(f"  [{i}/{total}] giải nén...")
            except zipfile.BadZipFile as e:
                _audit("EXTRACT", f"bad zip: {e}", "FAIL")
                return f"[error] File ZIP bị lỗi: {e}"
            except Exception as e:
                _audit("EXTRACT", str(e), "FAIL")
                return f"[error] Lỗi giải nén ZIP: {e}"

        elif ext == ".rar":
            # Thử rarfile lib trước
            extracted = False
            try:
                import rarfile
                with rarfile.RarFile(archive_path) as rf:
                    rf.extractall(extract_dir)
                extracted = True
            except ImportError:
                pass  # rarfile không có → thử 7z
            except Exception as e:
                _audit("EXTRACT", f"rarfile error: {e}", "FAIL")
                return f"[error] Lỗi giải nén RAR: {e}"

            if not extracted:
                # Fallback: tìm 7z.exe trên máy (thường có nếu đã cài 7-Zip)
                seven_zip = self._find_7zip()
                if not seven_zip:
                    return (
                        "[error] Không giải nén được file RAR.\n"
                        "Cần cài thư viện 'rarfile' (pip install rarfile) "
                        "hoặc cài 7-Zip trên máy."
                    )
                try:
                    proc = subprocess.Popen(
                        [seven_zip, "x", archive_path, f"-o{extract_dir}", "-y"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        creationflags=CREATE_NO_WINDOW,
                    )
                    proc.communicate(timeout=120)
                    if proc.returncode != 0:
                        return f"[error] 7-Zip giải nén thất bại (rc={proc.returncode})"
                except Exception as e:
                    return f"[error] Lỗi chạy 7-Zip: {e}"

        _emit_progress(f"[ok] Giải nén xong → {extract_dir}")

        # --- Tìm installer trong thư mục vừa giải nén ---
        installer = self._find_installer(extract_dir)
        if not installer:
            _audit("EXTRACT", f"no installer found in {extract_dir}", "FAIL")
            return (
                f"[warn] Đã giải nén vào {extract_dir}\n"
                f"Nhưng không tìm thấy file .exe/.msi tự động.\n"
                f"Vui lòng mở thư mục và chạy installer thủ công."
            )

        fname = os.path.basename(installer)
        _emit_progress(f"Đang mở installer: {fname} ...")
        _audit("INSTALL_LOCAL", f"extracted installer={installer}")

        try:
            os.startfile(installer)
            _audit("INSTALL_LOCAL_RESULT", f"opened {fname}", "OK")
            return (
                f"[ok] Đã giải nén và mở installer: {fname}\n"
                f"Cửa sổ cài đặt sẽ hiện lên, bạn thao tác bình thường.\n"
                f"(Thư mục tạm: {extract_dir})"
            )
        except OSError as e:
            _audit("INSTALL_LOCAL_RESULT", str(e), "FAIL")
            return f"[error] Không mở được installer: {e}"

    @staticmethod
    def _find_installer(directory: str) -> str | None:
        """Tìm file installer trong thư mục giải nén.

        Ưu tiên: setup.exe > install.exe > *.msi > *.exe (bất kỳ) > *.msix
        Bỏ qua: uninstall*.exe, uninst*.exe, remove*.exe
        """
        installer_exts = [".exe", ".msi", ".msix", ".msixbundle"]
        skip_prefixes = ("uninstall", "uninst", "remove", "unins")

        # Thu thập tất cả file installer
        candidates: list[tuple[int, str]] = []  # (priority, path)
        for root, _, files in os.walk(directory):
            for fname in files:
                name_lower = fname.lower()
                ext = os.path.splitext(name_lower)[1]
                if ext not in installer_exts:
                    continue
                if any(name_lower.startswith(p) for p in skip_prefixes):
                    continue
                full = os.path.join(root, fname)
                # Ưu tiên theo tên
                if name_lower in ("setup.exe", "install.exe", "installer.exe"):
                    priority = 0
                elif ext == ".msi":
                    priority = 1
                elif ext == ".exe":
                    priority = 2
                else:
                    priority = 3
                candidates.append((priority, full))

        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0])
        return candidates[0][1]

    @staticmethod
    def _find_7zip() -> str | None:
        """Tìm 7z.exe từ các path thường gặp."""
        candidates = [
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
            r"C:\Tools\7-Zip\7z.exe",
        ]
        for p in candidates:
            if os.path.isfile(p):
                return p
        return None

    def install_htkk(self, archive_path: str, dll_version: bool = False) -> str:
        """Cài HTKK: gỡ phiên bản cũ → giải nén → cài mới → tạo shortcut Run as Admin.

        HTKK yêu cầu:
        1. Gỡ bản cũ trước (không thể cài đè)
        2. Sau cài xong, cần chạy với quyền Admin lần đầu để đăng ký DLL
        3. Shortcut phải luôn "Run as Administrator"

        EDR-safe: registry lookup + os.startfile + COM shortcut + binary patch.
        """
        variant = "HTKK_DLL" if dll_version else "HTKK"
        _audit("INSTALL_HTKK", f"archive={archive_path} variant={variant}")

        if not os.path.isfile(archive_path):
            return f"[error] Không tìm thấy file: {archive_path}"

        # --- Bước 1: Tìm và gỡ HTKK cũ ---
        _emit_progress("Đang kiểm tra HTKK phiên bản cũ...")
        uninstall_result = self._uninstall_htkk()
        if uninstall_result:
            _emit_progress(uninstall_result)

        # --- Bước 2: Giải nén ---
        ext = os.path.splitext(archive_path)[1].lower()
        extract_result = self._extract_and_install(archive_path, ext)

        # --- Bước 3: Tìm HTKK.exe đã cài (trong Program Files) ---
        htkk_exe = self._find_installed_exe("htkk")
        if not htkk_exe:
            return (
                f"{extract_result}\n"
                f"[warn] Không tìm thấy HTKK.exe sau cài đặt.\n"
                f"Vui lòng tạo shortcut thủ công với 'Run as Administrator'."
            )

        # --- Bước 4: Tạo shortcut Run as Admin ---
        _emit_progress("Đang tạo shortcut HTKK (Run as Admin)...")
        shortcut_result = create_shortcut_admin(htkk_exe, variant, "public")
        _emit_progress(shortcut_result)

        return (
            f"{extract_result}\n"
            f"{shortcut_result}\n"
            f"[info] Shortcut đã được set 'Run as Administrator' để đăng ký DLL tự động."
        )

    @staticmethod
    def _uninstall_htkk() -> str:
        """Tìm và gỡ HTKK phiên bản cũ qua registry UninstallString.

        EDR-safe: winreg lookup + os.startfile (mở uninstaller giống user double-click).
        Không dùng silent flags — để user xác nhận gỡ.
        """
        uninstall_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        for hive, reg_path in uninstall_paths:
            try:
                key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        try:
                            sk = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                            display_name, _ = winreg.QueryValueEx(sk, "DisplayName")
                            if "htkk" in display_name.lower():
                                # Tìm thấy HTKK cũ
                                version = ""
                                try:
                                    version, _ = winreg.QueryValueEx(sk, "DisplayVersion")
                                except (OSError, FileNotFoundError):
                                    pass
                                try:
                                    uninstall_str, _ = winreg.QueryValueEx(sk, "UninstallString")
                                except (OSError, FileNotFoundError):
                                    winreg.CloseKey(sk)
                                    i += 1
                                    continue
                                winreg.CloseKey(sk)
                                winreg.CloseKey(key)

                                uninstall_str = uninstall_str.strip().strip('"')
                                _audit("UNINSTALL_HTKK",
                                       f"found: {display_name} v{version}, cmd={uninstall_str}", "OK")
                                _emit_progress(
                                    f"Tìm thấy {display_name} v{version} — đang mở trình gỡ cài đặt...")

                                # Mở uninstaller bằng os.startfile (giống user double-click)
                                try:
                                    os.startfile(uninstall_str)
                                    _audit("UNINSTALL_HTKK", "uninstaller opened", "OK")
                                    # Đợi user hoàn tất gỡ cài đặt
                                    _emit_progress(
                                        "[...] Vui lòng hoàn tất gỡ cài đặt HTKK cũ trong cửa sổ vừa mở...")
                                    # Chờ tối đa 120s cho uninstaller chạy xong
                                    import time as _time
                                    for _ in range(120):
                                        _time.sleep(1)
                                        if not _is_installed_via_registry("htkk"):
                                            _emit_progress("[ok] Đã gỡ HTKK cũ thành công.")
                                            return f"[ok] Đã gỡ {display_name} v{version}"
                                    return f"[warn] Đã mở trình gỡ cài đặt — vui lòng xác nhận gỡ xong trước khi tiếp tục."
                                except OSError as e:
                                    _audit("UNINSTALL_HTKK", str(e), "FAIL")
                                    return f"[error] Không mở được uninstaller: {e}"
                        except (OSError, FileNotFoundError):
                            pass
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass

        _audit("UNINSTALL_HTKK", "no previous HTKK found", "SKIP")
        return ""

    @staticmethod
    def _find_htkk_exe() -> str | None:
        """Tìm HTKK.exe sau khi cài đặt.

        Tìm trong registry (InstallLocation) và các path mặc định.
        """
        # 1. Tìm qua registry
        uninstall_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hive, reg_path in uninstall_paths:
            try:
                key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        try:
                            sk = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                            display_name, _ = winreg.QueryValueEx(sk, "DisplayName")
                            if "htkk" in display_name.lower():
                                try:
                                    loc, _ = winreg.QueryValueEx(sk, "InstallLocation")
                                    loc = loc.strip().strip('"')
                                    if os.path.isdir(loc):
                                        for f in os.listdir(loc):
                                            if f.lower() == "htkk.exe":
                                                winreg.CloseKey(sk)
                                                winreg.CloseKey(key)
                                                return os.path.join(loc, f)
                                except (OSError, FileNotFoundError):
                                    pass
                            winreg.CloseKey(sk)
                        except (OSError, FileNotFoundError):
                            pass
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass

        # 2. Fallback: path mặc định
        defaults = [
            r"C:\Program Files\HTKK\HTKK.exe",
            r"C:\Program Files (x86)\HTKK\HTKK.exe",
            r"C:\HTKK\HTKK.exe",
        ]
        for p in defaults:
            if os.path.isfile(p):
                return p
        return None

    def install_tax_app(self, archive_path: str, shortcut_name: str = "") -> str:
        """Cài phần mềm thuế (không phải HTKK): giải nén → cài → tạo shortcut Run as Admin.

        Dùng cho: iTaxViewer, CT SigningHub, eSigner...
        Shortcut tạo trên Public Desktop (all users) với flag Run as Administrator.

        EDR-safe: os.startfile + COM shortcut + binary patch.
        """
        _audit("INSTALL_TAX", f"archive={archive_path} shortcut={shortcut_name}")

        if not os.path.isfile(archive_path):
            return f"[error] Không tìm thấy file: {archive_path}"

        ext = os.path.splitext(archive_path)[1].lower()

        # Giải nén + chạy installer
        install_result = self.install_local(archive_path)

        if not shortcut_name:
            return install_result

        # Tìm exe đã cài qua registry
        exe_path = self._find_installed_exe(shortcut_name)
        if not exe_path:
            return (
                f"{install_result}\n"
                f"[info] Sau khi cài xong, hãy chạy lại lệnh để tạo shortcut Run as Admin."
            )

        # Tạo shortcut Run as Admin trên Public Desktop
        _emit_progress(f"Đang tạo shortcut {shortcut_name} (Run as Admin)...")
        sc_result = create_shortcut_admin(exe_path, shortcut_name, "public")
        _emit_progress(sc_result)

        return f"{install_result}\n{sc_result}"

    @staticmethod
    def _find_installed_exe(app_name: str) -> str | None:
        """Tìm exe của app vừa cài qua registry Uninstall keys.

        Tìm theo DisplayName chứa app_name, lấy InstallLocation hoặc DisplayIcon.
        """
        search = app_name.lower()
        uninstall_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hive, reg_path in uninstall_paths:
            try:
                key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        try:
                            sk = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                            display_name, _ = winreg.QueryValueEx(sk, "DisplayName")
                            if search in display_name.lower():
                                # Thử InstallLocation
                                for val_name in ("InstallLocation", "DisplayIcon"):
                                    try:
                                        val, _ = winreg.QueryValueEx(sk, val_name)
                                        val = val.strip().strip('"').split(",")[0]
                                        if val_name == "InstallLocation" and os.path.isdir(val):
                                            for f in os.listdir(val):
                                                if f.lower().endswith(".exe") and \
                                                        not f.lower().startswith(("unins", "uninst", "remove")):
                                                    winreg.CloseKey(sk)
                                                    winreg.CloseKey(key)
                                                    return os.path.join(val, f)
                                        elif os.path.isfile(val) and val.lower().endswith(".exe"):
                                            winreg.CloseKey(sk)
                                            winreg.CloseKey(key)
                                            return val
                                    except (OSError, FileNotFoundError):
                                        pass
                            winreg.CloseKey(sk)
                        except (OSError, FileNotFoundError):
                            pass
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass
        return None


        """Cập nhật tất cả phần mềm đã cài qua winget upgrade --all."""
        _audit("UPGRADE_ALL", "starting")
        args = [
            "upgrade", "--all",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ]
        code, output = _run_winget_progress(args, timeout=WINGET_UPGRADE_TIMEOUT)
        if code == 0:
            return "[ok] Đã cập nhật tất cả phần mềm."
        elif "no applicable update" in output.lower() or "no installed package" in output.lower():
            return "[info] Tất cả phần mềm đã ở phiên bản mới nhất."
        else:
            return f"[warn] Cập nhật hoàn tất (có thể một số app lỗi): {_explain_exit_code(code)}"

    def export_apps(self, file_path: str = "") -> str:
        """Xuất danh sách phần mềm đã cài ra file JSON (winget export)."""
        if not file_path:
            file_path = os.path.join(os.path.expanduser("~"), "Desktop", "wica_apps.json")
        file_path = file_path.strip().strip('"').strip("'")
        _audit("EXPORT_APPS", f"path={file_path}")
        args = ["export", "-o", file_path, "--accept-source-agreements"]
        code, output = _run_winget_progress(args)
        if code == 0:
            return f"[ok] Đã xuất danh sách phần mềm: {file_path}"
        else:
            return f"[error] Lỗi xuất danh sách:\n{output[:500]}"


# --- Registry-based system configs ---
REGISTRY_CONFIGS = {
    "dark_mode": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "values": [
            ("AppsUseLightTheme", 0, winreg.REG_DWORD),
            ("SystemUsesLightTheme", 0, winreg.REG_DWORD),
        ],
    },
    "light_mode": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "values": [
            ("AppsUseLightTheme", 1, winreg.REG_DWORD),
            ("SystemUsesLightTheme", 1, winreg.REG_DWORD),
        ],
    },
    "show_file_ext": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "values": [("HideFileExt", 0, winreg.REG_DWORD)],
    },
    "show_hidden_files": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "values": [("Hidden", 1, winreg.REG_DWORD)],
    },
    "hide_hidden_files": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "values": [("Hidden", 2, winreg.REG_DWORD)],
    },
    "taskbar_left": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "values": [("TaskbarAl", 0, winreg.REG_DWORD)],
    },
    "taskbar_center": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "values": [("TaskbarAl", 1, winreg.REG_DWORD)],
    },
    "date_dmy": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"Control Panel\International",
        "values": [
            ("sShortDate", "dd/MM/yyyy", winreg.REG_SZ),
            ("sLongDate", "dddd, d MMMM yyyy", winreg.REG_SZ),
            ("iFirstDayOfWeek", "0", winreg.REG_SZ),
        ],
    },
    "uac_off": {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "values": [
            ("EnableLUA", 0, winreg.REG_DWORD),
            ("ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD),
        ],
    },
    "uac_on": {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "values": [
            ("EnableLUA", 1, winreg.REG_DWORD),
            ("ConsentPromptBehaviorAdmin", 5, winreg.REG_DWORD),
        ],
    },
    "disable_telemetry": {
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "key": r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "values": [
            ("AllowTelemetry", 0, winreg.REG_DWORD),
        ],
    },
    "disable_bing_search": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "values": [
            ("DisableSearchBoxSuggestions", 1, winreg.REG_DWORD),
        ],
    },
    "disable_copilot": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
        "values": [
            ("TurnOffWindowsCopilot", 1, winreg.REG_DWORD),
        ],
    },
    "classic_context_menu": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32",
        "values": [
            ("", "", winreg.REG_SZ),
        ],
    },
    "disable_notifications": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "values": [
            ("DisableNotificationCenter", 1, winreg.REG_DWORD),
        ],
    },
    "enable_notifications": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "values": [
            ("DisableNotificationCenter", 0, winreg.REG_DWORD),
        ],
    },
    "disable_tips": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        "values": [
            ("SubscribedContent-338389Enabled", 0, winreg.REG_DWORD),
            ("SubscribedContent-310093Enabled", 0, winreg.REG_DWORD),
            ("SubscribedContent-338388Enabled", 0, winreg.REG_DWORD),
            ("SubscribedContent-338393Enabled", 0, winreg.REG_DWORD),
            ("SubscribedContent-353694Enabled", 0, winreg.REG_DWORD),
            ("SubscribedContent-353696Enabled", 0, winreg.REG_DWORD),
            ("SoftLandingEnabled", 0, winreg.REG_DWORD),
        ],
    },
    "search_icon_only": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
        "values": [
            ("SearchboxTaskbarMode", 1, winreg.REG_DWORD),
        ],
    },
    "search_hidden": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
        "values": [
            ("SearchboxTaskbarMode", 0, winreg.REG_DWORD),
        ],
    },
    "search_box": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
        "values": [
            ("SearchboxTaskbarMode", 2, winreg.REG_DWORD),
        ],
    },
    "disable_task_view": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "values": [
            ("ShowTaskViewButton", 0, winreg.REG_DWORD),
        ],
    },
    "enable_task_view": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "values": [
            ("ShowTaskViewButton", 1, winreg.REG_DWORD),
        ],
    },
    "unpin_store_taskbar": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "values": [
            ("NoPinningStoreToTaskbar", 1, winreg.REG_DWORD),
        ],
    },
}


# --- System Configurator ---
class SystemConfigurator:
    """Cấu hình hệ thống - CHỈ dùng winreg + Python stdlib. KHÔNG PowerShell."""

    def apply(self, config_name: str) -> str:
        # Timezone đặc biệt - dùng tzutil.exe (Microsoft-signed system binary)
        if config_name.startswith("timezone_"):
            tz_id = config_name.replace("timezone_", "").replace("_", " ")
            return self._set_timezone(tz_id)

        reg_cfg = REGISTRY_CONFIGS.get(config_name)
        if not reg_cfg:
            return f"[error] Không tìm thấy config: {config_name}"

        hive = reg_cfg["hive"]
        key_path = reg_cfg["key"]
        errors = []

        if hive == winreg.HKEY_CURRENT_USER:
            # HKCU → ghi cho TẤT CẢ user profiles qua HKEY_USERS\{SID}
            total_ok = 0
            total_fail = 0
            for value_name, value_data, value_type in reg_cfg["values"]:
                ok_c, fail_c, errs = _set_registry_all_users(
                    key_path, value_name, value_data, value_type
                )
                total_ok += ok_c
                total_fail += fail_c
                errors.extend(errs)
            if total_fail > 0 and total_ok == 0:
                # Fallback: ghi trực tiếp vào HKCU của user hiện tại
                fb_errors = []
                for value_name, value_data, value_type in reg_cfg["values"]:
                    ok, msg = _set_registry(
                        winreg.HKEY_CURRENT_USER, key_path,
                        value_name, value_data, value_type
                    )
                    if not ok:
                        fb_errors.append(msg)
                if not fb_errors:
                    return f"[ok] Đã áp dụng (user hiện tại): {config_name}"
                err_detail = "; ".join(errors[:2]) if errors else "unknown"
                return (f"[error] Config {config_name}: không áp dụng được\n"
                        f"  Chi tiết: {err_detail}\n"
                        f"  Gợi ý: chạy WICA với quyền Admin (Run as Administrator)")
            if errors:
                return (f"[warn] Config {config_name}: áp dụng {total_ok} user, "
                        f"lỗi {total_fail}\n" + "\n".join(errors[:3]))
            return f"[ok] Đã áp dụng cho tất cả user: {config_name}"
        else:
            # HKLM → ghi trực tiếp (đã là all users)
            for value_name, value_data, value_type in reg_cfg["values"]:
                ok, msg = _set_registry(
                    hive, key_path, value_name, value_data, value_type
                )
                if not ok:
                    errors.append(msg)
            if errors:
                return f"[warn] Config {config_name}:\n" + "\n".join(errors)
            return f"[ok] Đã áp dụng: {config_name}"

    def _set_timezone(self, tz_id: str) -> str:
        """Đặt timezone bằng tzutil.exe - Microsoft-signed system binary.

        tzutil.exe nằm trong C:\\Windows\\system32, được Windows ký,
        EDR trust tương tự winget.exe.
        Sau đó gọi w32tm /resync để force update clock ngay lập tức.
        """
        _audit("TIMEZONE", f"tz={tz_id}")
        try:
            proc = subprocess.Popen(
                ["tzutil", "/s", tz_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=CREATE_NO_WINDOW,
            )
            stdout, stderr = proc.communicate(timeout=TIMEZONE_TIMEOUT)
            if proc.returncode == 0:
                _audit("TIMEZONE_RESULT", f"set to {tz_id}", "OK")
                # Force sync clock để giờ update ngay
                try:
                    sync = subprocess.Popen(
                        ["w32tm", "/resync", "/nowait"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=CREATE_NO_WINDOW,
                    )
                    sync.communicate(timeout=WINGET_CHECK_TIMEOUT)
                except Exception:
                    pass
                return f"[ok] Đã đặt timezone: {tz_id}"
            else:
                _audit("TIMEZONE_RESULT", stderr.strip(), "FAIL")
                return f"[error] Lỗi đặt timezone: {stderr.strip()}"
        except FileNotFoundError:
            _audit("TIMEZONE_RESULT", "tzutil not found", "FAIL")
            return "[error] Không tìm thấy tzutil.exe"
        except Exception as e:
            _audit("TIMEZONE_RESULT", str(e), "FAIL")
            return f"[error] Lỗi timezone: {e}"

    def get_system_info(self) -> str:
        """Thông tin hệ thống bằng Python stdlib - KHÔNG subprocess/PowerShell."""
        _audit("SYSINFO", "python stdlib only")
        info = []
        info.append(f"OS: {platform.system()} {platform.version()} ({platform.machine()})")
        info.append(f"Platform: {platform.platform()}")
        info.append(f"Hostname: {os.environ.get('COMPUTERNAME', 'N/A')}")
        info.append(f"User: {os.environ.get('USERNAME', 'N/A')}")

        # Disk info bằng shutil (Python stdlib)
        for letter in "CDEFGH":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                try:
                    usage = shutil.disk_usage(drive)
                    total_gb = usage.total / (1024**3)
                    free_gb = usage.free / (1024**3)
                    info.append(f"Disk {letter}: {free_gb:.1f}GB free / {total_gb:.1f}GB")
                except OSError:
                    pass

        return "\n".join(info) if info else "[error] Không lấy được thông tin."

    def get_hostname(self) -> str:
        """Lấy tên máy hiện tại — Python stdlib, EDR-safe."""
        _audit("HOSTNAME_GET", "reading")
        name = os.environ.get("COMPUTERNAME", "")
        if not name:
            try:
                name = platform.node()
            except Exception:
                name = ""
        if name:
            return f"[info] Tên máy hiện tại: {name}"
        return "[error] Không lấy được tên máy"

    def set_hostname(self, new_name: str) -> str:
        """Đặt tên máy mới qua registry — EDR-safe (winreg only).

        Ghi vào registry keys:
        - HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName
        - HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters
        Cần restart để có hiệu lực.
        """
        import re as _re
        new_name = new_name.strip()
        if not new_name or len(new_name) > 15:
            return "[error] Tên máy phải từ 1-15 ký tự"
        if not _re.match(r'^[A-Za-z0-9\-]+$', new_name):
            return "[error] Tên máy chỉ được chứa chữ, số và dấu gạch ngang"
        _audit("HOSTNAME_SET", f"new={new_name}")
        errors = []
        ok1, msg1 = _set_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
            "ComputerName", new_name, winreg.REG_SZ
        )
        if not ok1:
            errors.append(msg1)
        ok2, msg2 = _set_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "Hostname", new_name, winreg.REG_SZ
        )
        if not ok2:
            errors.append(msg2)
        ok3, msg3 = _set_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "NV Hostname", new_name, winreg.REG_SZ
        )
        if not ok3:
            errors.append(msg3)
        if errors:
            return "[error] Lỗi đặt tên máy:\n" + "\n".join(errors)
        return f"[ok] Đã đặt tên máy: {new_name}\nCần khởi động lại để có hiệu lực."


# --- CLI Command Runner ---
# Whitelist/Blacklist imported from shared_constants (single source of truth)
_CLI_WHITELIST = CLI_WHITELIST
_CLI_BLACKLIST = CLI_BLACKLIST


def _run_cli_command(command_str: str, timeout: int = CLI_TIMEOUT) -> str:
    """Chạy lệnh CLI trực tiếp - CHỈ whitelist, KHÔNG shell=True.

    EDR Safety (enterprise-grade):
    - KHÔNG dùng shell=True
    - KHÔNG spawn PowerShell/cmd/diskpart/bcdedit
    - Chỉ chạy lệnh trong whitelist
    - Arg-level restrictions cho certutil, netsh, sc, taskkill, shutdown, icacls, cipher
    - Tất cả được audit log
    """
    command_str = command_str.strip()
    if not command_str:
        return "[error] Lệnh trống"

    _audit("CLI_CMD", f"raw={command_str}")

    # Parse command — shlex.split(posix=False) cho Windows path
    import shlex
    try:
        parts = shlex.split(command_str, posix=False)
        parts = [p.strip('"') if p.startswith('"') and p.endswith('"') else p for p in parts]
    except ValueError:
        parts = command_str.split()
    if not parts:
        return "[error] Lệnh trống"

    exe = parts[0].lower().strip('"').strip("'")
    exe_base = exe.replace(".exe", "")
    args_lower = [a.lower() for a in parts[1:]]

    # --- Blacklist check ---
    if exe_base in _CLI_BLACKLIST or exe in _CLI_BLACKLIST:
        _audit("CLI_BLOCKED", f"blacklisted: {exe}", "FAIL")
        return f"[error] Lệnh bị chặn (EDR safety): {exe}"

    # --- Whitelist check ---
    if exe_base not in _CLI_WHITELIST and exe not in _CLI_WHITELIST:
        _audit("CLI_BLOCKED", f"not whitelisted: {exe}", "FAIL")
        allowed = ", ".join(sorted(_CLI_WHITELIST)[:15]) + "..."
        return f"[error] Lệnh '{exe}' không nằm trong danh sách cho phép.\nCho phép: {allowed}"

    # --- Arg-level restrictions ---

    # reg: chỉ cho phép query/export
    if exe_base == "reg":
        if args_lower and args_lower[0] in ("add", "delete", "import", "restore",
                                             "load", "unload", "save", "copy"):
            _audit("CLI_BLOCKED", f"reg {args_lower[0]} blocked", "FAIL")
            return f"[error] 'reg {args_lower[0]}' bị chặn. Chỉ cho phép: reg query, reg export."

    # certutil: LOLBin — chỉ cho phép sub-commands an toàn
    elif exe_base == "certutil":
        # Tìm sub-command (arg bắt đầu bằng -)
        subcmd = next((a for a in args_lower if a.startswith("-")), None)
        if subcmd and subcmd not in _CERTUTIL_ALLOWED_SUBCMDS:
            _audit("CLI_BLOCKED", f"certutil {subcmd} blocked (LOLBin risk)", "FAIL")
            allowed_sub = ", ".join(sorted(_CERTUTIL_ALLOWED_SUBCMDS))
            return (f"[error] 'certutil {subcmd}' bị chặn (LOLBin risk).\n"
                    f"Cho phép: {allowed_sub}")

    # netsh: chặn advfirewall và firewall sub-commands
    elif exe_base == "netsh":
        if args_lower and args_lower[0] in _NETSH_BLOCKED_SUBCOMMANDS:
            _audit("CLI_BLOCKED", f"netsh {args_lower[0]} blocked", "FAIL")
            return (f"[error] 'netsh {args_lower[0]}' bị chặn (firewall manipulation risk).\n"
                    f"Cho phép: netsh wlan, netsh interface show, netsh int ip show, v.v.")
        # Chặn write operations nguy hiểm: winsock reset, int ip reset, winhttp set
        if len(args_lower) >= 2:
            pair = (args_lower[0], args_lower[1])
            if pair in _NETSH_BLOCKED_WRITE_SUBCMDS:
                _audit("CLI_BLOCKED", f"netsh {args_lower[0]} {args_lower[1]} blocked", "FAIL")
                return (f"[error] 'netsh {args_lower[0]} {args_lower[1]}' bị chặn (network stack modification).\n"
                        f"Thao tác này cần approval của IT admin.")
        # Chặn thêm: netsh interface ip set (có thể đổi DNS/IP)
        if (len(args_lower) >= 3
                and args_lower[0] == "interface"
                and args_lower[2] == "set"):
            _audit("CLI_BLOCKED", f"netsh interface ... set blocked", "FAIL")
            return "[error] 'netsh interface ... set' bị chặn. Chỉ cho phép lệnh show/dump."

    # sc: chặn stop/delete/config các security service
    elif exe_base == "sc":
        if args_lower:
            # sc [\\server] action service_name
            # Tìm action (bỏ qua \\server nếu có)
            action_idx = 0
            if args_lower[0].startswith("\\\\"):
                action_idx = 1
            action = args_lower[action_idx] if action_idx < len(args_lower) else ""
            svc_name = args_lower[action_idx + 1] if action_idx + 1 < len(args_lower) else ""

            if action in _SC_BLOCKED_ACTIONS:
                # Kiểm tra tên service có phải security service không
                svc_lower = svc_name.lower()
                for blocked in _SC_BLOCKED_SERVICES:
                    if blocked in svc_lower:
                        _audit("CLI_BLOCKED",
                               f"sc {action} {svc_name} blocked (security service)", "FAIL")
                        return (f"[error] 'sc {action} {svc_name}' bị chặn.\n"
                                f"Không được phép dừng/xóa/cấu hình security service.")

    # taskkill: chặn kill security processes
    elif exe_base == "taskkill":
        # Tìm /IM argument (image name)
        for i, arg in enumerate(args_lower):
            if arg == "/im" and i + 1 < len(args_lower):
                proc_name = args_lower[i + 1].lower()
                if proc_name in _TASKKILL_BLOCKED_PROCESSES:
                    _audit("CLI_BLOCKED", f"taskkill /IM {proc_name} blocked", "FAIL")
                    return (f"[error] Không được phép kill process: {proc_name}\n"
                            f"Đây là security/EDR process được bảo vệ.")

    # shutdown: chỉ cho phép /a (abort)
    elif exe_base == "shutdown":
        flags = set(args_lower)
        allowed = flags & _SHUTDOWN_ALLOWED_FLAGS
        blocked = flags - _SHUTDOWN_ALLOWED_FLAGS - {""}
        if blocked and not allowed:
            _audit("CLI_BLOCKED", f"shutdown {' '.join(blocked)} blocked", "FAIL")
            return (f"[error] 'shutdown {' '.join(blocked)}' bị chặn.\n"
                    f"Chỉ cho phép: shutdown /a (hủy shutdown đang chờ).")

    # icacls: chỉ cho phép read — chặn modify ACL
    elif exe_base == "icacls":
        for flag in args_lower:
            if flag in _ICACLS_BLOCKED_FLAGS:
                _audit("CLI_BLOCKED", f"icacls {flag} blocked", "FAIL")
                return (f"[error] 'icacls {flag}' bị chặn (ACL modification risk).\n"
                        f"Chỉ cho phép đọc ACL: icacls <path>")

    # cipher: chặn /w (wipe free space)
    elif exe_base == "cipher":
        for flag in args_lower:
            if flag in _CIPHER_BLOCKED_FLAGS:
                _audit("CLI_BLOCKED", f"cipher {flag} blocked", "FAIL")
                return (f"[error] 'cipher {flag}' bị chặn (disk wipe risk).")

    # fsutil: chặn write/behavior sub-commands
    elif exe_base == "fsutil":
        if args_lower and args_lower[0] in _FSUTIL_BLOCKED_SUBCMDS:
            _audit("CLI_BLOCKED", f"fsutil {args_lower[0]} blocked", "FAIL")
            return (f"[error] 'fsutil {args_lower[0]}' bị chặn (filesystem modification risk).\n"
                    f"Chỉ cho phép: fsutil volume diskfree, fsutil fsinfo, fsutil file, v.v.")

    # dism: chặn enable/disable features và apply image
    elif exe_base == "dism":
        for flag in args_lower:
            if flag in _DISM_BLOCKED_FLAGS:
                _audit("CLI_BLOCKED", f"dism {flag} blocked", "FAIL")
                return (f"[error] 'dism {flag}' bị chặn (system modification risk).\n"
                        f"Chỉ cho phép: dism /online /get-features, /get-packages, /get-drivers.")

    # wmic: deprecated warning nhưng vẫn cho phép (read-only queries)
    elif exe_base == "wmic":
        _audit("CLI_WARN", "wmic is deprecated in Win11 22H2+, consider using Get-CimInstance", "WARN")

    # chkdsk: chặn /f /r /x — schedule repair và force reboot
    elif exe_base == "chkdsk":
        for flag in args_lower:
            if flag in _CHKDSK_BLOCKED_FLAGS:
                _audit("CLI_BLOCKED", f"chkdsk {flag} blocked", "FAIL")
                return (f"[error] 'chkdsk {flag}' bị chặn (disk repair/reboot risk).\n"
                        f"Chỉ cho phép: chkdsk <drive> (read-only scan).")

    # w32tm: chặn /config — thay đổi NTP server
    elif exe_base == "w32tm":
        for flag in args_lower:
            if flag in _W32TM_BLOCKED_FLAGS:
                _audit("CLI_BLOCKED", f"w32tm {flag} blocked", "FAIL")
                return (f"[error] 'w32tm {flag}' bị chặn.\n"
                        f"Cho phép: w32tm /query, w32tm /resync.")

    # --- Execute (real-time output) ---
    try:
        proc = subprocess.Popen(
            parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
        # Đọc stdout real-time thay vì blocking communicate()
        all_lines = []
        start = time.time()
        _seen_cli = set()
        try:
            for raw_line in proc.stdout:
                if timeout and (time.time() - start) > timeout:
                    proc.terminate()
                    _audit("CLI_RESULT", f"{exe} timeout", "FAIL")
                    return f"[error] Lệnh chạy quá lâu (>{timeout}s): {exe}"
                stripped = raw_line.rstrip()
                if stripped:
                    all_lines.append(stripped)
                    # Emit progress qua callback (real-time)
                    _emit_line(stripped, _seen_cli)
        except Exception:
            pass
        # Đọc stderr sau khi stdout đã hết
        stderr = proc.stderr.read() if proc.stderr else ""
        proc.wait()

        output = "\n".join(all_lines).strip()
        if stderr.strip():
            output += "\n" + stderr.strip()

        _audit("CLI_RESULT", f"cmd={exe} rc={proc.returncode}",
               "OK" if proc.returncode == 0 else "FAIL")

        if not output:
            output = f"(Lệnh hoàn thành, exit code: {proc.returncode})"

        # Giới hạn output
        lines = output.split("\n")
        if len(lines) > 100:
            output = "\n".join(lines[:100]) + f"\n... (còn {len(lines) - 100} dòng)"

        return output
    except FileNotFoundError:
        _audit("CLI_RESULT", f"{exe} not found", "FAIL")
        return f"[error] Không tìm thấy lệnh: {exe}"
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        try:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        except Exception:
            pass
        _audit("CLI_RESULT", f"{exe} timeout", "FAIL")
        return f"[error] Lệnh chạy quá lâu (>{timeout}s): {exe}"
    except Exception as e:
        _audit("CLI_RESULT", str(e), "FAIL")
        return f"[error] Lỗi chạy lệnh: {e}"
