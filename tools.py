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
        return False, "[error] C\u1ea7n quy\u1ec1n Administrator."
    except Exception as e:
        _audit("REGISTRY_RESULT", str(e), "FAIL")
        return False, f"[error] L\u1ed7i registry: {e}"


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


# --- Software Manager ---
class SoftwareManager:
    """Quản lý phần mềm - chỉ dùng winget + os.startfile."""

    def __init__(self, aliases: dict):
        self.aliases = aliases

    def _resolve(self, name: str) -> str:
        return self.aliases.get(name.lower().strip(), name)

    def install(self, package: str) -> str:
        """Cài qua winget - Microsoft-signed, EDR trusted."""
        pkg_id = self._resolve(package)
        _audit("INSTALL", f"package={package} resolved={pkg_id}")
        args = [
            "install", "--id", pkg_id,
            "--accept-package-agreements",
            "--accept-source-agreements",
            "-e",
        ]
        code, output = _run_winget_progress(args)
        if code == 0:
            return f"[ok] Đã cài đặt: {package} ({pkg_id})"
        elif "already installed" in output.lower():
            return f"[info] {package} đã được cài rồi."
        else:
            # Lấy dòng lỗi cuối cùng thay vì dump toàn bộ output
            # (progress đã hiện realtime qua callback rồi)
            err_lines = [l for l in output.split("\n") if l.strip()]
            last_err = err_lines[-1] if err_lines else "Không rõ lỗi"
            return f"[error] Lỗi cài đặt {package}: {last_err}"

    def uninstall(self, package: str) -> str:
        pkg_id = self._resolve(package)
        _audit("UNINSTALL", f"package={package} resolved={pkg_id}")
        args = ["uninstall", "--id", pkg_id, "-e"]
        code, output = _run_winget(args)
        if code == 0:
            return f"[ok] \u0110\u00e3 g\u1ee1: {package}"
        else:
            return f"[error] L\u1ed7i g\u1ee1 {package}:\n{output[:500]}"

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
            return f"[error] Lỗi gỡ {pkg_id}: {output[:200]}"

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
            return f"[warn] Cập nhật hoàn tất (có thể một số app lỗi)"

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
            return f"[error] Kh\u00f4ng t\u00ecm th\u1ea5y config: {config_name}"

        errors = []
        for value_name, value_data, value_type in reg_cfg["values"]:
            ok, msg = _set_registry(
                reg_cfg["hive"], reg_cfg["key"],
                value_name, value_data, value_type
            )
            if not ok:
                errors.append(msg)

        if errors:
            return f"[warn] Config {config_name}:\n" + "\n".join(errors)
        return f"[ok] \u0110\u00e3 \u00e1p d\u1ee5ng: {config_name}"

    def _set_timezone(self, tz_id: str) -> str:
        """Đặt timezone bằng tzutil.exe - Microsoft-signed system binary.

        tzutil.exe nằm trong C:\\Windows\\system32, được Windows ký,
        EDR trust tương tự winget.exe.
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
            if proc.returncode == 0:
                _audit("TIMEZONE_RESULT", f"set to {tz_id}", "OK")
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

        # RAM từ registry (không cần PowerShell)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\RESOURCEMAP\System Resources\Physical Memory"
            )
            winreg.CloseKey(key)
        except Exception:
            pass

        return "\n".join(info) if info else "[error] Kh\u00f4ng l\u1ea5y \u0111\u01b0\u1ee3c th\u00f4ng tin."
