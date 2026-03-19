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


def _run_winget(args: list[str], timeout: int = 600) -> tuple[int, str]:
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
            # Đảm bảo cleanup hoàn toàn — đóng pipe handles + wait
            try:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                proc.wait(timeout=5)
            except Exception:
                pass
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


def _run_winget_progress(args: list[str], timeout: int = 600) -> tuple[int, str]:
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
        # Cleanup hoàn toàn — đóng pipe handles + wait
        try:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.wait(timeout=5)
        except Exception:
            pass
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
    return sids


def _set_registry_all_users(key_path: str, value_name: str,
                            value, value_type=winreg.REG_DWORD) -> tuple[int, int, list[str]]:
    """Ghi registry cho TẤT CẢ user profiles trên máy.

    Duyệt HKEY_USERS\\{SID}\\<key_path> cho mỗi user SID.
    Cũng ghi vào HKU\\.DEFAULT (cho user mới tạo sau này).

    EDR-safe: chỉ dùng winreg module.

    Returns: (ok_count, fail_count, errors)
    """
    sids = _get_user_sids()
    # Thêm .DEFAULT để user mới tạo sau cũng có config
    targets = sids + [".DEFAULT"]
    ok_count = 0
    fail_count = 0
    errors = []
    for sid in targets:
        full_path = f"{sid}\\{key_path}"
        _audit("REGISTRY_ALL_USERS", f"SID={sid} key={key_path} {value_name}={value}")
        try:
            key = winreg.CreateKeyEx(winreg.HKEY_USERS, full_path, 0,
                                     winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, value_name, 0, value_type, value)
            winreg.CloseKey(key)
            ok_count += 1
        except PermissionError:
            fail_count += 1
            errors.append(f"SID {sid}: cần quyền Admin")
        except Exception as e:
            fail_count += 1
            errors.append(f"SID {sid}: {e}")
    _audit("REGISTRY_ALL_USERS_RESULT",
           f"ok={ok_count} fail={fail_count}",
           "OK" if fail_count == 0 else "WARN")
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
            if os.path.exists(dest_folder):
                shutil.rmtree(dest_folder)
            shutil.copytree(source, dest_folder)
            _audit("DEPLOY_COPY", f"folder {source} -> {dest_folder}", "OK")
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
            dest_file = os.path.join(dest_folder, os.path.basename(source))
            shutil.copy2(source, dest_file)
            _audit("DEPLOY_COPY", f"file {source} -> {dest_file}", "OK")
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
    users_dir = os.path.join(os.environ.get("SystemDrive", "C:"), os.sep, "Users")
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

    for udir in user_dirs:
        dest_dir = os.path.join(udir, dest_relative)
        try:
            os.makedirs(dest_dir, exist_ok=True)
            if is_dir:
                dest_full = os.path.join(dest_dir, src_name)
                if os.path.exists(dest_full):
                    shutil.rmtree(dest_full)
                shutil.copytree(source, dest_full)
            else:
                shutil.copy2(source, os.path.join(dest_dir, src_name))
            ok_count += 1
        except Exception as e:
            fail_count += 1
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
        return f"[error] Không tìm thấy thư mục font: {source_folder}"

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

    for fname in font_files:
        src = os.path.join(source_folder, fname)
        dest = os.path.join(fonts_dir, fname)
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
            except Exception:
                pass  # Font đã copy, registry fail không critical
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
        self.aliases = aliases
        self.local_paths = local_paths or []

    def _resolve(self, name: str) -> str:
        return self.aliases.get(name.lower().strip(), name)

    def _try_local_fallback(self, pkg_id: str) -> str:
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
                    return self._open_local_installer(full)
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
                                    return self._open_local_installer(full)
                        elif os.path.isfile(sub) and entry_lower.endswith((".exe", ".msi")):
                            return self._open_local_installer(sub)
            except OSError:
                pass
        return ""

    def _open_local_installer(self, path: str) -> str:
        """Mở installer bằng os.startfile() - EDR-safe."""
        fname = os.path.basename(path)
        _audit("LOCAL_FALLBACK", f"opening {path}")
        try:
            os.startfile(path)
            _audit("LOCAL_FALLBACK_RESULT", f"opened {fname}", "OK")
            return (f"[ok] Winget không khả dụng, đã mở installer local: {fname}\n"
                    f"Cửa sổ cài đặt sẽ hiện lên, bạn thao tác bình thường.")
        except OSError as e:
            _audit("LOCAL_FALLBACK_RESULT", str(e), "FAIL")
            return f"[error] Không mở được file: {e}"

    def _ensure_source(self) -> None:
        """Reset + update winget source (fix 0x8a15000f khi Run as Admin).
        
        Khi chạy Run as different user, winget source data chưa có.
        Cần reset → update → accept agreements cho user mới.
        """
        _audit("SOURCE_RESET", "resetting winget source for current user")
        # Reset trước (xóa cache cũ/hỏng)
        subprocess.run(
            ["winget", "source", "reset", "--force",
             "--accept-source-agreements", "--disable-interactivity"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120
        )
        # Update lại — download source index mới
        _audit("SOURCE_UPDATE", "updating winget source")
        subprocess.run(
            ["winget", "source", "update",
             "--accept-source-agreements", "--disable-interactivity"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=180
        )
        # Chạy 1 lệnh search nhỏ để force winget init hoàn tất
        subprocess.run(
            ["winget", "search", "Microsoft.Office",
             "--accept-source-agreements", "--disable-interactivity"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120
        )

    def install(self, package: str) -> str:
        """Cài qua winget - Microsoft-signed, EDR trusted."""
        pkg_id = self._resolve(package)
        _audit("INSTALL", f"package={package} resolved={pkg_id}")
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
            _audit("INSTALL_RETRY", f"source error, resetting and retrying {pkg_id}")
            self._ensure_source()
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
        code, output = _run_winget(args)
        if code == 0:
            return f"[ok] \u0110\u00e3 g\u1ee1: {package}"
        else:
            reason = _explain_exit_code(code)
            return f"[error] L\u1ed7i g\u1ee1 {package}: {reason}"

    def uninstall_system(self, pkg_id: str) -> str:
        """Gỡ app system-wide (tất cả user) qua winget."""
        _audit("UNINSTALL_SYSTEM", f"package={pkg_id}")
        args = ["uninstall", "--id", pkg_id, "-e", "--accept-source-agreements"]
        code, output = _run_winget(args, timeout=60)
        if code == 0:
            return f"[ok] Đã gỡ: {pkg_id}"
        elif "no installed package" in output.lower() or "not found" in output.lower():
            return f"[info] Không có: {pkg_id}"
        else:
            return f"[error] Lỗi gỡ {pkg_id}: {_explain_exit_code(code)}"

    def search(self, query: str) -> str:
        _audit("SEARCH", f"query={query}")
        code, output = _run_winget(["search", query])
        if code == 0:
            lines = output.split("\n")[:15]
            return "[search] K\u1ebft qu\u1ea3 t\u00ecm ki\u1ebfm:\n" + "\n".join(lines)
        return f"[error] Kh\u00f4ng t\u00ecm th\u1ea5y: {query}"

    def list_installed(self) -> str:
        _audit("LIST", "listing installed")
        code, output = _run_winget(["list"])
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
        """
        file_path = file_path.strip().strip('"').strip("'")
        _audit("INSTALL_LOCAL", f"path={file_path}")

        if not os.path.isfile(file_path):
            return f"[error] Không tìm thấy file: {file_path}"

        ext = os.path.splitext(file_path)[1].lower()
        allowed = {".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle"}
        if ext not in allowed:
            return f"[error] \u0110\u1ecbnh d\u1ea1ng kh\u00f4ng h\u1ed7 tr\u1ee3: {ext}. Ch\u1ec9 h\u1ed7 tr\u1ee3: {', '.join(allowed)}"

        fname = os.path.basename(file_path)

        try:
            # os.startfile = ShellExecuteW = giống user double-click trong Explorer
            # KHÔNG dùng subprocess, KHÔNG silent flags, KHÔNG hidden window
            os.startfile(file_path)
            _audit("INSTALL_LOCAL_RESULT", f"opened {fname}", "OK")
            return f"[ok] \u0110\u00e3 m\u1edf installer: {fname}\nC\u1eeda s\u1ed5 c\u00e0i \u0111\u1eb7t s\u1ebd hi\u1ec7n l\u00ean, b\u1ea1n thao t\u00e1c b\u00ecnh th\u01b0\u1eddng."
        except OSError as e:
            _audit("INSTALL_LOCAL_RESULT", str(e), "FAIL")
            return f"[error] Không mở được file: {e}"

    def upgrade_all(self) -> str:
        """Cập nhật tất cả phần mềm đã cài qua winget upgrade --all."""
        _audit("UPGRADE_ALL", "starting")
        args = [
            "upgrade", "--all",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ]
        code, output = _run_winget_progress(args, timeout=1200)
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
        code, output = _run_winget(args)
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
    "disable_weather": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds",
        "values": [
            ("ShellFeedsTaskbarViewMode", 2, winreg.REG_DWORD),
        ],
    },
    "disable_widgets": {
        "hive": winreg.HKEY_CURRENT_USER,
        "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "values": [
            ("TaskbarDa", 0, winreg.REG_DWORD),
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
                return f"[error] Config {config_name}: không áp dụng được cho user nào\n" + "\n".join(errors)
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
            )
            stdout, stderr = proc.communicate(timeout=30)
            try:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                proc.wait(timeout=5)
            except Exception:
                pass
            if proc.returncode == 0:
                _audit("TIMEZONE_RESULT", f"set to {tz_id}", "OK")
                # Force sync clock để giờ update ngay
                try:
                    sync = subprocess.Popen(
                        ["w32tm", "/resync", "/nowait"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    sync.communicate(timeout=10)
                    try:
                        if sync.stdout:
                            sync.stdout.close()
                        if sync.stderr:
                            sync.stderr.close()
                        sync.wait(timeout=5)
                    except Exception:
                        pass
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
# Whitelist các lệnh an toàn cho phép chạy trực tiếp
# KHÔNG có powershell, cmd, hoặc bất kỳ shell nào
_CLI_WHITELIST = {
    # Network
    "ipconfig", "ping", "tracert", "nslookup", "netstat", "arp",
    "route", "pathping", "nbtstat", "getmac",
    # System info
    "hostname", "whoami", "systeminfo", "ver", "wmic",
    "tasklist", "taskkill", "sc",
    # File operations (read-only / safe)
    "dir", "type", "where", "tree", "attrib", "icacls",
    "certutil", "cipher",
    # Winget
    "winget",
    # Disk
    "chkdsk", "diskpart", "fsutil",
    # Network config
    "netsh",
    # DNS
    "ipconfig",
    # Other safe tools
    "sfc", "dism", "gpresult", "gpupdate",
    "bcdedit", "shutdown", "tzutil",
    "reg",  # registry query (read)
}

# Lệnh CẤM TUYỆT ĐỐI - không bao giờ chạy
_CLI_BLACKLIST = {
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "cmd", "cmd.exe",
    "wscript", "wscript.exe", "cscript", "cscript.exe",
    "mshta", "mshta.exe",
    "rundll32", "rundll32.exe",
    "regsvr32", "regsvr32.exe",
    "format",  # format disk
}


def _run_cli_command(command_str: str, timeout: int = 60) -> str:
    """Chạy lệnh CLI trực tiếp - CHỈ whitelist, KHÔNG shell=True.
    
    EDR Safety:
    - KHÔNG dùng shell=True
    - KHÔNG spawn PowerShell/cmd
    - Chỉ chạy lệnh trong whitelist
    - Tất cả được audit log
    """
    command_str = command_str.strip()
    if not command_str:
        return "[error] Lệnh trống"
    
    _audit("CLI_CMD", f"raw={command_str}")
    
    # Parse command - tách thành list args
    # Xử lý đặc biệt cho Windows path (không dùng shlex vì nó xử lý \ sai)
    parts = command_str.split()
    if not parts:
        return "[error] Lệnh trống"
    
    exe = parts[0].lower().strip('"').strip("'")
    # Bỏ .exe nếu có để so sánh
    exe_base = exe.replace(".exe", "")
    
    # Kiểm tra blacklist trước
    if exe_base in _CLI_BLACKLIST or exe in _CLI_BLACKLIST:
        _audit("CLI_BLOCKED", f"blacklisted: {exe}", "FAIL")
        return f"[error] Lệnh bị chặn (EDR safety): {exe}\nKhông được phép chạy shell/script interpreter."
    
    # Kiểm tra whitelist
    if exe_base not in _CLI_WHITELIST and exe not in _CLI_WHITELIST:
        _audit("CLI_BLOCKED", f"not whitelisted: {exe}", "FAIL")
        allowed = ", ".join(sorted(_CLI_WHITELIST)[:15]) + "..."
        return f"[error] Lệnh '{exe}' không nằm trong danh sách cho phép.\nCho phép: {allowed}"
    
    try:
        proc = subprocess.Popen(
            parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        # Cleanup pipe handles
        try:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.wait(timeout=5)
        except Exception:
            pass
        output = stdout.strip()
        if stderr.strip():
            output += "\n" + stderr.strip()
        
        _audit("CLI_RESULT", f"cmd={exe} rc={proc.returncode}",
               "OK" if proc.returncode == 0 else "FAIL")
        
        if not output:
            output = f"(Lệnh hoàn thành, exit code: {proc.returncode})"
        
        # Giới hạn output để không tràn chat
        lines = output.split("\n")
        if len(lines) > 50:
            output = "\n".join(lines[:50]) + f"\n... (còn {len(lines) - 50} dòng)"
        
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
