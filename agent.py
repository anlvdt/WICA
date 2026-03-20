# -*- coding: utf-8 -*-
"""Core agent logic - Fast path + LLM fallback.

Lệnh rõ ràng (cài X, gỡ Y, bật dark mode) -> xử lý NGAY bằng regex.
Lệnh phức tạp/mơ hồ -> mới gọi LLM.
"""
import json
import sys
import yaml
import os
import threading
from openai import OpenAI
from tools import SoftwareManager, SystemConfigurator, REGISTRY_CONFIGS, _audit, create_shortcut, deploy_portable, set_progress_callback, _run_cli_command, copy_to_all_users, install_fonts, _is_winget_installed, _is_registry_set, _is_deployed, _are_fonts_installed, _is_copied_to_users, _get_installed_list
from fast_commands import parse_fast
from privilege import is_elevated
from keystore import get_key

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
MAX_HISTORY = 20

SYSTEM_PROMPT = """Bạn là WICA — Windows Install & Config Agent. Bạn là agent HÀNH ĐỘNG, không phải chatbot tư vấn.

## NGUYÊN TẮC CỐT LÕI
- **LÀM NGAY** — mọi yêu cầu đều phải có actions. Không bao giờ chỉ giải thích.
- **AGENTIC LOOP** — sau khi nhận kết quả thực thi, phân tích và tiếp tục hành động cho đến khi vấn đề được giải quyết hoàn toàn.
- **DONE khi thực sự xong** — chỉ trả `"done": true` khi đã hoàn thành hoặc không còn action nào khả thi.

## FORMAT BẮT BUỘC
Luôn trả lời JSON (không có text ngoài JSON):
{{
  "message": "Mô tả ngắn gọn bước hiện tại",
  "actions": [...],
  "done": false
}}

Khi hoàn thành hoặc không cần thêm actions:
{{
  "message": "Tóm tắt kết quả",
  "actions": [],
  "done": true
}}

## ACTION TYPES
{{ "type": "install", "package": "tên/alias" }}
{{ "type": "install_local", "path": "tên_file.exe" }}
{{ "type": "uninstall", "package": "tên/alias" }}
{{ "type": "search", "query": "từ_khóa" }}
{{ "type": "list_installed" }}
{{ "type": "system_config", "config": "tên_config" }}
{{ "type": "system_info" }}
{{ "type": "get_hostname" }}
{{ "type": "set_hostname", "name": "TÊN-MÁY" }}
{{ "type": "upgrade_all" }}
{{ "type": "export_apps" }}
{{ "type": "deploy_portable", "source": "file", "dest": "C:\\\\Tools\\\\App", "name": "App" }}
{{ "type": "copy_to_all_users", "source": "file", "dest_relative": "path" }}
{{ "type": "install_fonts", "source": "thư_mục" }}
{{ "type": "remove_bloatware" }}
{{ "type": "run_profile", "name": "mac_dinh" }}
{{ "type": "cli", "command": "lệnh" }}

## AGENTIC PATTERNS — PHẢI THỰC HIỆN

### Chẩn đoán mạng
User: "mạng chậm / không có mạng / không vào được web"
→ Round 1: Thu thập dữ liệu
```json
{{"actions": [
  {{"type":"cli","command":"ipconfig /all"}},
  {{"type":"cli","command":"ping 8.8.8.8 -n 4"}},
  {{"type":"cli","command":"nslookup google.com"}},
  {{"type":"cli","command":"netstat -rn"}}
], "done": false}}
```
→ Round 2 (sau khi có kết quả): Phân tích và báo cáo
- Nếu ping 8.8.8.8 fail → DNS/gateway issue → `ipconfig /flushdns`
- Nếu IP là 169.254.x.x → DHCP fail → báo user liên hệ IT để reset DHCP
- Nếu ping ok nhưng nslookup fail → DNS fail → báo user liên hệ IT để đổi DNS
- KHÔNG tự ý thay đổi network config (netsh set bị chặn — cần IT approval)

### Chẩn đoán máy chậm/lag
→ Round 1: Thu thập
```json
{{"actions": [
  {{"type":"cli","command":"tasklist /FI \"MEMUSAGE gt 150000\" /FO TABLE"}},
  {{"type":"cli","command":"wmic cpu get loadpercentage"}},
  {{"type":"system_info"}}
], "done": false}}
```
→ Round 2: Dựa vào kết quả — báo cáo process ngốn RAM, gợi ý user tắt startup thủ công

### Chẩn đoán ổ đĩa
→ Round 1: `fsutil volume diskfree C:`, `reg query "HKLM\\HARDWARE\\DEVICEMAP\\Scsi" /s /v Identifier`
→ Round 2: Báo cáo kết quả, gợi ý dọn dẹp thủ công nếu đầy

### Lỗi Windows Update
→ Round 1: `sc query wuauserv`, `sc query bits`
→ Round 2: Nếu service stopped → `sc start wuauserv`, `sc start bits`
→ Round 3: Nếu vẫn lỗi → báo user liên hệ IT (reset update cache cần quyền cao hơn)

### Cài phần mềm thất bại
→ Nếu install lỗi → thử search winget để tìm đúng ID → thử lại với ID chính xác

### Xem thông tin WiFi/mạng
→ `netsh wlan show profiles` → nếu user muốn password → `netsh wlan show profile name="TÊN" key=clear`

### Kiểm tra service/process
→ `sc query TÊN_SERVICE` → nếu stopped → `sc start TÊN_SERVICE`

### Dọn dẹp hệ thống
→ `fsutil volume diskfree C:` → báo cáo dung lượng còn trống

## CẤM TUYỆT ĐỐI (EDR ENTERPRISE RULES)
- KHÔNG dùng: `netsh advfirewall`, `netsh firewall`, `netsh winsock reset`, `netsh int ip reset`
- KHÔNG dùng: `netsh interface ip set` (thay đổi DNS/IP — cần IT approval)
- KHÔNG dùng: `net stop/start` (dùng `sc stop/start` thay thế, và chỉ với non-security services)
- KHÔNG dùng: `del /f /s /q` (xóa file — không có trong whitelist)
- KHÔNG dùng: `diskpart`, `bcdedit`, `format` (bị blacklist hoàn toàn)
- KHÔNG dùng: `certutil -urlcache`, `certutil -decode` (LOLBin risk)
- KHÔNG dùng: `dism /enable-feature`, `dism /disable-feature`
- KHÔNG dùng: `fsutil behavior set`
- KHÔNG tự ý thay đổi network config, firewall, DNS — báo user liên hệ IT

## QUY TẮC AGENTIC LOOP
Khi nhận được kết quả thực thi:
1. **Phân tích kết quả** — xác định thành công/thất bại/cần thêm thông tin
2. **Nếu có lỗi** → tạo actions để fix lỗi đó
3. **Đặc biệt: Nếu có lỗi không tìm thấy file/thư mục (Not Found)** → LUÔN DÙNG tool `cli` với lệnh `dir` để dò tìm cấu trúc thư mục thực sự, tìm tên đúng rồi gọi lại công cụ. 
4. **Nếu cần thêm thông tin** → tạo actions để thu thập
5. **Nếu đã xong** → `"done": true` với tóm tắt
6. **KHÔNG bao giờ** dừng giữa chừng khi vẫn còn vấn đề chưa giải quyết

## CẤM TUYỆT ĐỐI (GENERAL)
- Trả lời chỉ có text, không có actions (trừ khi `done: true`)
- Đề xuất "bạn có thể thử..." thay vì tạo actions
- Đề xuất PowerShell, download file từ internet
- Dừng loop khi vấn đề chưa được giải quyết

## CONTEXT
ALIASES: {aliases}
SYSTEM CONFIGS: {configs}
QUICK COMMANDS: {quick_commands}
PROFILES: {profiles}
THÔNG TIN MÁY: {system_context}
FILE/FOLDER CÓ SẴN TRONG LOCAL_PATHS (dùng ĐÚNG tên này cho install_fonts, deploy_portable, install_local, copy_to_all_users):
{local_files}

PHẦN MỀM ĐÃ CÀI — PATH THỰC TẾ (dùng cho deploy_portable, create_shortcut, run_profile):
{discovered_tools}

## QUY TẮC CHUNG
- Trả lời tiếng Việt có dấu
- Dùng alias nếu có, không thì dùng tên gốc cho winget
- Nhiều phần mềm → nhiều actions riêng biệt
- install_local/install_fonts/deploy_portable: dùng ĐÚNG tên file/folder từ danh sách LOCAL_PATHS ở trên
"""


class AntiGravityAgent:
    def __init__(self):
        # try/except cho config load
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except Exception as e:
            _audit("CONFIG_LOAD", f"error: {e}", "FAIL")
            self.config = {}
        self.aliases = self.config.get("aliases", {})
        self.providers = self.config.get("llm_providers", [])
        self.local_paths = self.config.get("local_paths", [])
        # Tự động copy SoftVN từ USB vào C:\ trong background (không block UI)
        self._softvn_copy_status = "pending"
        self._softvn_copy_cb = None  # callback để notify UI khi xong
        threading.Thread(target=self._auto_copy_softvn_bg, daemon=True).start()
        # Tự động phát hiện path UniKey, TeamViewer QS từ registry
        # và thêm vào local_paths nếu chưa có
        self._discovered_tools = self._discover_installed_tools()
        for tool_path in self._discovered_tools.values():
            folder = os.path.dirname(tool_path)
            if folder and folder not in self.local_paths and os.path.isdir(folder):
                self.local_paths.append(folder)
        self.client = None
        self.model = None
        self.provider_name = None
        self._connect_llm()
        self._cancel_event = threading.Event()
        self.sw = SoftwareManager(self.aliases, self.local_paths)
        self.sys_cfg = SystemConfigurator()
        self.history = [
            {"role": "system", "content": SYSTEM_PROMPT.format(
                aliases=json.dumps(self.aliases, indent=2, ensure_ascii=False),
                configs=json.dumps(list(REGISTRY_CONFIGS.keys()), ensure_ascii=False),
                quick_commands=json.dumps(
                    list(self.config.get("quick_commands", {}).keys()),
                    ensure_ascii=False,
                ),
                profiles=json.dumps(
                    {k: v.get("name", k) for k, v in self.config.get("profiles", {}).items()},
                    ensure_ascii=False,
                ),
                system_context=self._get_system_context(),
                local_files=self._scan_local_paths(self.local_paths),
                discovered_tools=self._format_discovered_tools(self._discovered_tools),
            )}
        ]

    @staticmethod
    def _get_system_context() -> str:
        """Lấy thông tin cơ bản về máy để LLM có context."""
        import platform
        parts = [
            f"OS: {platform.system()} {platform.release()} ({platform.version()})",
            f"Hostname: {platform.node()}",
            f"Arch: {platform.machine()}",
        ]
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
                name, _ = winreg.QueryValueEx(k, "ProductName")
                parts[0] = f"OS: {name} ({platform.version()})"
        except Exception:
            pass
        return " | ".join(parts)

    def _auto_copy_softvn(self) -> str:
        r"""Sync thư mục SoftVN từ USB vào C:\SoftVN.

        Logic:
        - Tìm SoftVN cạnh WICA.exe hoặc thư mục cha (USB root)
        - Nếu C:\SoftVN chưa có -> copy toàn bộ
        - Nếu đã có -> sync: chỉ copy file mới hơn hoặc chưa có trên C:\
          (không xóa file cũ trên C:\, không overwrite file mới hơn)
        - Thêm C:\SoftVN vào local_paths

        EDR-safe: chỉ dùng shutil + os (Python stdlib).
        """
        import shutil

        if getattr(sys, 'frozen', False):
            app_dir = os.path.dirname(sys.executable)
        else:
            app_dir = os.path.dirname(os.path.abspath(__file__))

        candidates = [
            os.path.join(app_dir, "SoftVN"),
            os.path.join(os.path.dirname(app_dir), "SoftVN"),
        ]
        src = next((p for p in candidates if os.path.isdir(p)), None)

        dest = r"C:\SoftVN"
        if dest not in self.local_paths:
            self.local_paths.append(dest)

        if src is None:
            _audit("AUTO_COPY_SOFTVN", "SoftVN not found near app", "WARN")
            return "not_found"

        # --- Sync: copy file mới hơn hoặc chưa có ---
        copied = 0
        skipped = 0
        errors = 0
        try:
            for root, dirs, files in os.walk(src):
                # Tính relative path từ src
                rel_root = os.path.relpath(root, src)
                dest_root = os.path.join(dest, rel_root) if rel_root != "." else dest
                os.makedirs(dest_root, exist_ok=True)
                for fname in files:
                    src_file = os.path.join(root, fname)
                    dst_file = os.path.join(dest_root, fname)
                    # Copy nếu: chưa có, hoặc USB mới hơn
                    if not os.path.exists(dst_file) or \
                            os.path.getmtime(src_file) > os.path.getmtime(dst_file):
                        try:
                            shutil.copy2(src_file, dst_file)
                            copied += 1
                        except Exception:
                            errors += 1
                    else:
                        skipped += 1
        except PermissionError:
            _audit("AUTO_COPY_SOFTVN", f"permission denied: {dest}", "FAIL")
            return "permission_denied"
        except Exception as e:
            _audit("AUTO_COPY_SOFTVN", f"error: {e}", "FAIL")
            return f"error:{e}"

        if copied == 0 and errors == 0:
            _audit("AUTO_COPY_SOFTVN", f"already up-to-date ({skipped} files)", "SKIP")
            return "up_to_date"

        _audit("AUTO_COPY_SOFTVN",
               f"synced {src} -> {dest}: copied={copied} skipped={skipped} errors={errors}",
               "OK" if errors == 0 else "WARN")
        return f"synced:{copied}:{errors}"

    def _auto_copy_softvn_bg(self):
        """Chạy _auto_copy_softvn trong background thread, emit progress real-time."""
        from tools import _progress_callback, _cb_lock

        def _emit(msg: str):
            with _cb_lock:
                cb = _progress_callback
            if cb:
                cb(msg)
            # Cũng notify qua softvn_copy_cb nếu có (set bởi ChatApp)
            notify = self._softvn_copy_cb
            if notify:
                notify(msg)

        # Tìm src
        if getattr(sys, 'frozen', False):
            app_dir = os.path.dirname(sys.executable)
        else:
            app_dir = os.path.dirname(os.path.abspath(__file__))

        candidates = [
            os.path.join(app_dir, "SoftVN"),
            os.path.join(os.path.dirname(app_dir), "SoftVN"),
        ]
        src = next((p for p in candidates if os.path.isdir(p)), None)
        dest = r"C:\SoftVN"
        if dest not in self.local_paths:
            self.local_paths.append(dest)

        if src is None:
            _audit("AUTO_COPY_SOFTVN", "SoftVN not found near app", "WARN")
            self._softvn_copy_status = "not_found"
            return

        # Đếm tổng file để hiện progress
        total = sum(len(files) for _, _, files in os.walk(src))
        _emit(f"Đang sync SoftVN từ USB → C:\\SoftVN ({total} file)...")

        copied = skipped = errors = 0
        try:
            for root, dirs, files in os.walk(src):
                rel_root = os.path.relpath(root, src)
                dest_root = os.path.join(dest, rel_root) if rel_root != "." else dest
                os.makedirs(dest_root, exist_ok=True)
                for fname in files:
                    src_file = os.path.join(root, fname)
                    dst_file = os.path.join(dest_root, fname)
                    if not os.path.exists(dst_file) or \
                            os.path.getmtime(src_file) > os.path.getmtime(dst_file):
                        try:
                            import shutil
                            shutil.copy2(src_file, dst_file)
                            copied += 1
                            _emit(f"  [{copied}/{total}] {fname}")
                        except Exception:
                            errors += 1
                    else:
                        skipped += 1
        except PermissionError:
            _audit("AUTO_COPY_SOFTVN", f"permission denied: {dest}", "FAIL")
            self._softvn_copy_status = "permission_denied"
            _emit("[x] Không sync được SoftVN — cần quyền Admin")
            return
        except Exception as e:
            _audit("AUTO_COPY_SOFTVN", f"error: {e}", "FAIL")
            self._softvn_copy_status = f"error:{e}"
            _emit(f"[x] Lỗi sync SoftVN: {e}")
            return

        if copied == 0 and errors == 0:
            _audit("AUTO_COPY_SOFTVN", f"already up-to-date ({skipped} files)", "SKIP")
            self._softvn_copy_status = "up_to_date"
            _emit(f"[ok] SoftVN đã up-to-date ({skipped} file)")
            return

        _audit("AUTO_COPY_SOFTVN",
               f"synced {src} -> {dest}: copied={copied} skipped={skipped} errors={errors}",
               "OK" if errors == 0 else "WARN")
        self._softvn_copy_status = f"synced:{copied}:{errors}"
        if errors == 0:
            _emit(f"[ok] SoftVN sync xong: {copied} file mới → C:\\SoftVN")
        else:
            _emit(f"[~] SoftVN sync: {copied} file mới, {errors} lỗi")

    @staticmethod
    def _scan_local_paths(local_paths: list[str], max_depth: int = 2) -> str:
        """Scan cấu trúc thư mục local_paths để LLM biết tên file/folder thực tế.

        Trả về dạng tree text, ví dụ:
          F:\\SoftVN\\
            Fonts\\          (folder)
            Chrome.exe       (file)
            Office\\         (folder)
              setup.exe      (file)

        Giới hạn depth=2 để tránh output quá dài.
        EDR-safe: chỉ dùng os.scandir (Python stdlib).
        """
        if not local_paths:
            return "(chưa cấu hình local_paths trong config.yaml)"

        lines = []
        font_exts = {".ttf", ".otf", ".ttc"}
        installer_exts = {".exe", ".msi", ".msix", ".msixbundle", ".appx"}

        def _scan(path: str, indent: int, depth: int):
            if depth < 0:
                return
            try:
                entries = sorted(os.scandir(path), key=lambda e: (not e.is_dir(), e.name.lower()))
                for entry in entries:
                    if entry.name.startswith("."):
                        continue
                    prefix = "  " * indent
                    if entry.is_dir():
                        lines.append(f"{prefix}{entry.name}\\  (folder)")
                        _scan(entry.path, indent + 1, depth - 1)
                    else:
                        ext = os.path.splitext(entry.name)[1].lower()
                        if ext in font_exts or ext in installer_exts:
                            lines.append(f"{prefix}{entry.name}")
            except PermissionError:
                pass

        for base in local_paths:
            if not os.path.isdir(base):
                lines.append(f"{base}  (không tồn tại)")
                continue
            lines.append(f"{base}\\")
            _scan(base, indent=1, depth=max_depth - 1)

        return "\n".join(lines) if lines else "(local_paths trống hoặc không có file)"

    @staticmethod
    def _discover_installed_tools() -> dict[str, str]:
        """Tìm path thực tế của UniKey và TeamViewer QS từ registry.

        EDR-safe: chỉ dùng winreg (Python stdlib), KHÔNG subprocess.
        Tìm trong:
        - HKLM/HKCU Uninstall keys (InstallLocation, DisplayIcon)
        - Các path cố định thường gặp (fallback)

        Returns: dict {"UniKey": "C:\\Tools\\UniKey\\UniKeyNT.exe", ...}
        """
        import winreg

        # Định nghĩa các tool cần tìm: tên → (search_keywords, fallback_paths)
        TOOLS = {
            "UniKey": (
                ["unikey"],
                [
                    r"C:\Program Files\UniKey\UniKeyNT.exe",
                    r"C:\Program Files (x86)\UniKey\UniKeyNT.exe",
                    r"C:\Tools\UniKey\UniKeyNT.exe",
                    os.path.join(os.environ.get("LOCALAPPDATA", ""), "UniKey", "UniKeyNT.exe"),
                ],
            ),
            "TeamViewer QS": (
                ["teamviewerqs", "teamviewer_qs", "teamviewer qs", "quicksupport"],
                [
                    r"C:\Tools\TeamViewerQS\TeamViewerQS.exe",
                    r"C:\Tools\TeamViewerQS\TeamViewerQS_x64.exe",
                    r"C:\Program Files\TeamViewerQS\TeamViewerQS.exe",
                    os.path.join(os.environ.get("APPDATA", ""), "TeamViewerQS", "TeamViewerQS.exe"),
                ],
            ),
        }

        results = {}

        # Registry Uninstall paths để tìm
        uninstall_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        for tool_name, (keywords, fallbacks) in TOOLS.items():
            found_path = ""

            # 1. Tìm qua registry Uninstall keys
            for hive, reg_path in uninstall_paths:
                if found_path:
                    break
                try:
                    key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey_lower = subkey_name.lower()
                            if any(kw in subkey_lower for kw in keywords):
                                try:
                                    sk = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                                    # Thử InstallLocation trước
                                    for val_name in ("InstallLocation", "DisplayIcon", "UninstallString"):
                                        try:
                                            val, _ = winreg.QueryValueEx(sk, val_name)
                                            val = val.strip().strip('"').split(",")[0]
                                            if val_name == "InstallLocation":
                                                # Tìm exe trong folder
                                                if os.path.isdir(val):
                                                    for fname in os.listdir(val):
                                                        if fname.lower().endswith(".exe"):
                                                            candidate = os.path.join(val, fname)
                                                            if os.path.isfile(candidate):
                                                                found_path = candidate
                                                                break
                                            elif os.path.isfile(val) and val.lower().endswith(".exe"):
                                                found_path = val
                                            if found_path:
                                                break
                                        except (OSError, FileNotFoundError):
                                            pass
                                    winreg.CloseKey(sk)
                                except OSError:
                                    pass
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except (OSError, FileNotFoundError):
                    pass

            # 2. Fallback: kiểm tra path cố định
            if not found_path:
                for fb in fallbacks:
                    if os.path.isfile(fb):
                        found_path = fb
                        break

            if found_path:
                results[tool_name] = found_path
                _audit("DISCOVER_TOOL", f"{tool_name} -> {found_path}", "OK")
            else:
                _audit("DISCOVER_TOOL", f"{tool_name} not found", "WARN")

        return results

    @staticmethod
    def _format_discovered_tools(tools: dict[str, str]) -> str:
        """Format discovered tools thành text cho SYSTEM_PROMPT."""
        if not tools:
            return "(không tìm thấy UniKey / TeamViewer QS trên máy này)"
        lines = []
        for name, path in tools.items():
            folder = os.path.dirname(path)
            lines.append(f"- {name}: {path}  (folder: {folder})")
        return "\n".join(lines)

    def _resolve_api_key(self, raw_key: str) -> str:
        """Resolve API key: nếu bắt đầu bằng 'env:' thì đọc từ biến môi trường.
        
        Khi chạy Run as Admin/different user, env var của user gốc không có.
        Fallback: đọc trực tiếp từ registry HKCU\\Environment của user gốc.
        """
        if not raw_key:
            return ""
        if raw_key.startswith("env:"):
            env_name = raw_key[4:]
            # Thử env var trước (hoạt động khi chạy bình thường)
            val = os.environ.get(env_name, "")
            if val:
                return val
            # Fallback: đọc từ registry user environment
            # (hoạt động khi Run as Admin/different user)
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Environment") as key:
                    val, _ = winreg.QueryValueEx(key, env_name)
                    if val:
                        return val
            except (OSError, FileNotFoundError):
                pass
            # Fallback 2: thử HKEY_USERS với SID của user đang login
            try:
                import winreg
                # Lấy tất cả SID trong HKEY_USERS
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(winreg.HKEY_USERS, i)
                        if sid.startswith("S-1-5-21") and not sid.endswith("_Classes"):
                            try:
                                with winreg.OpenKey(winreg.HKEY_USERS,
                                                    f"{sid}\\Environment") as key:
                                    val, _ = winreg.QueryValueEx(key, env_name)
                                    if val:
                                        return val
                            except (OSError, FileNotFoundError):
                                pass
                        i += 1
                    except OSError:
                        break
            except Exception:
                pass
            # Fallback 3: đọc từ file .keys (mã hóa, đi kèm USB/ZIP)
            val = get_key(env_name)
            if val:
                return val
            return ""
        return raw_key

    def _connect_llm(self):
        for p in self.providers:
            name = p.get("name", "unknown")
            api_key = self._resolve_api_key(p.get("api_key", ""))
            base_url = p.get("base_url", "")
            model = p.get("model", "")
            if not api_key and name != "ollama":
                continue
            try:
                client = OpenAI(base_url=base_url, api_key=api_key or "ollama")
                # timeout 5s cho health check
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": "hi"}],
                    max_tokens=5, temperature=0,
                    timeout=5,
                )
                if resp.choices:
                    self.client = client
                    self.model = model
                    self.provider_name = name
                    _audit("LLM_CONNECT", f"provider={name} model={model}", "OK")
                    return
            except Exception:
                _audit("LLM_CONNECT", f"provider={name} failed", "FAIL")
                continue
        _audit("LLM_CONNECT", "no provider available", "FAIL")

    def cancel(self):
        self._cancel_event.set()

    @property
    def _cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def _trim_history(self):
        if len(self.history) > MAX_HISTORY + 1:
            self.history = self.history[:1] + self.history[-(MAX_HISTORY):]

    def get_status(self) -> str:
        if self.client:
            return f"[connected] Đã kết nối: {self.provider_name} ({self.model})"
        return "[offline] Chưa kết nối LLM. Kiểm tra config.yaml."

    def _extract_json(self, text: str) -> dict:
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(text[start:end])
            if not isinstance(data, dict):
                raise ValueError("JSON root is not an object")
            # Chấp nhận cả format cũ (không có done) và mới (có done)
            if "message" not in data and "actions" not in data:
                raise ValueError("JSON missing 'message' or 'actions' keys")
            # Normalize: đảm bảo luôn có done field
            if "done" not in data:
                data["done"] = not bool(data.get("actions"))
            return data
        raise ValueError("No JSON found")

    def _resolve_local_path(self, path: str) -> str:
        path = path.strip().strip('"').strip("'")
        if os.path.isabs(path):
            return path
        # Tự động thêm app directory + parent (USB root) vào search paths
        app_dir = os.path.dirname(os.path.abspath(__file__))
        if getattr(sys, 'frozen', False):
            app_dir = os.path.dirname(sys.executable)
        parent_dir = os.path.dirname(app_dir)
        search_paths = list(self.local_paths)
        if app_dir not in search_paths:
            search_paths.insert(0, app_dir)
        # Thêm parent dir (USB root) — USB layout: USB/WICA.exe + USB/SoftVN/Fonts/
        if parent_dir and parent_dir not in search_paths and os.path.isdir(parent_dir):
            search_paths.insert(1, parent_dir)
        # 1. Thử ghép trực tiếp base + path (nhanh nhất)
        for base in search_paths:
            full = os.path.join(base, path)
            if os.path.exists(full):
                return full
        # 2. Tìm trong thư mục con (max 3 cấp) — chỉ trong search_paths whitelist
        target_name = os.path.basename(path).lower()
        for base in search_paths:
            # Tìm file
            found = self._find_in_subfolders(base, target_name, max_depth=3)
            if found:
                _audit("RESOLVE_PATH", f"found in subfolder: {found}", "OK")
                return found
            # Tìm folder (install_fonts, deploy_portable truyền folder path)
            found_dir = self._find_dir_in_subfolders(base, target_name, max_depth=3)
            if found_dir:
                _audit("RESOLVE_PATH", f"found dir in subfolder: {found_dir}", "OK")
                return found_dir
        tried = ", ".join(search_paths) if search_paths else "(chưa cấu hình local_paths)"
        _audit("RESOLVE_PATH", f"not found: {path} in {tried}", "FAIL")
        return path

    @staticmethod
    def _find_dir_in_subfolders(base: str, dirname_lower: str, max_depth: int = 3) -> str:
        """Tìm folder theo tên trong thư mục con (giới hạn depth).

        Tương tự _find_in_subfolders nhưng tìm directory thay vì file.
        Dùng cho install_fonts, deploy_portable khi source là folder.
        """
        if not os.path.isdir(base):
            return ""
        try:
            for entry in os.scandir(base):
                if entry.is_dir() and entry.name.lower() == dirname_lower:
                    return entry.path
            if max_depth > 0:
                for entry in os.scandir(base):
                    if entry.is_dir() and not entry.name.startswith("."):
                        found = AntiGravityAgent._find_dir_in_subfolders(
                            entry.path, dirname_lower, max_depth - 1
                        )
                        if found:
                            return found
        except PermissionError:
            pass
        return ""

    @staticmethod
    def _find_in_subfolders(base: str, filename_lower: str, max_depth: int = 3) -> str:
        """Tìm file theo tên trong thư mục con (giới hạn depth).

        CHỈ tìm trong local_paths whitelist, KHÔNG quét ổ đĩa.
        Dùng os.scandir (không dùng os.walk) để kiểm soát chính xác depth.
        """
        if not os.path.isdir(base):
            return ""
        try:
            for entry in os.scandir(base):
                if entry.is_file() and entry.name.lower() == filename_lower:
                    return entry.path
            if max_depth > 0:
                for entry in os.scandir(base):
                    if entry.is_dir() and not entry.name.startswith("."):
                        found = AntiGravityAgent._find_in_subfolders(
                            entry.path, filename_lower, max_depth - 1
                        )
                        if found:
                            return found
        except PermissionError:
            pass
        return ""

    def _is_safe_path(self, path: str) -> bool:
        """Kiểm tra path nằm trong local_paths hoặc app directory cho phép (chống path traversal)."""
        app_dir = os.path.dirname(os.path.abspath(__file__))
        if getattr(sys, 'frozen', False):
            app_dir = os.path.dirname(sys.executable)
        allowed = list(self.local_paths) + [app_dir]
        if not allowed:
            return False
        real = os.path.realpath(path)
        for base in allowed:
            if real.startswith(os.path.realpath(base) + os.sep) or real == os.path.realpath(base):
                return True
        return False

    # Thư mục đích cho phép deploy portable (whitelist)
    SAFE_DEPLOY_DIRS = [
        r"C:\Tools",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
    ]

    def _is_safe_dest(self, dest: str) -> bool:
        """Kiểm tra dest folder nằm trong whitelist (chống LLM ghi vào System32...)."""
        real = os.path.realpath(dest)
        for base in self.SAFE_DEPLOY_DIRS:
            rb = os.path.realpath(base)
            if real.startswith(rb + os.sep) or real == rb:
                return True
        return False

    def _find_profile(self, name: str):
        profiles = self.config.get("profiles", {})
        profile = profiles.get(name.lower().replace(" ", "_"))
        if profile:
            return profile
        for k, p in profiles.items():
            if name.lower() in p.get("name", "").lower() or name.lower() in k:
                return p
        return None

    def _check_skip(self, action: dict) -> str | None:
        """Kiểm tra action đã hoàn thành chưa. Trả về lý do skip hoặc None.

        Được gọi bởi _execute_action — áp dụng TOÀN DIỆN cho mọi flow.
        """
        t = action.get("type", "")
        if t == "install":
            pkg = action.get("package", "")
            pkg_id = self.sw._resolve(pkg)
            if _is_winget_installed(pkg_id):
                return "đã cài rồi"
        elif t == "uninstall":
            pkg = action.get("package", "")
            pkg_id = self.sw._resolve(pkg)
            if not _is_winget_installed(pkg_id):
                return "không có trên máy"
        elif t == "system_config":
            cfg = action.get("config", "")
            # Timezone check riêng
            if cfg.startswith("timezone_"):
                return None  # Luôn chạy timezone (nhanh, khó check)
            if _is_registry_set(cfg):
                return "đã cấu hình"
        elif t == "set_hostname":
            import platform
            new_name = action.get("name", "").strip()
            if new_name and platform.node().lower() == new_name.lower():
                return "tên máy đã đúng"
        elif t == "deploy_portable":
            dest = action.get("dest", "")
            exe = action.get("exe", "")
            if dest and _is_deployed(dest, exe):
                return "đã cài"
        elif t == "install_fonts":
            src = self._resolve_local_path(action.get("source", ""))
            if _are_fonts_installed(src):
                return "đã cài font"
        elif t == "copy_to_all_users":
            src = self._resolve_local_path(action.get("source", ""))
            dest_rel = action.get("dest_relative", "")
            if _is_copied_to_users(src, dest_rel):
                return "đã copy"
        elif t == "remove_bloatware":
            bloatware = self.config.get("bloatware", [])
            if not bloatware:
                return "danh sách trống"
            from tools import _is_installed_via_registry
            still_installed = [p for p in bloatware if _is_installed_via_registry(p)]
            if not still_installed:
                return "đã gỡ hết"
        elif t == "install_local":
            path_lower = action.get("path", "").lower()
            from tools import _is_installed_via_registry
            if "trendmicro" in path_lower or "officescan" in path_lower:
                if _is_installed_via_registry("Trend Micro") or _is_installed_via_registry("Apex One"):
                    return "đã cài rồi"
            elif "localoffice" in path_lower or "desktopcentral" in path_lower or "uems" in path_lower or "manageengine" in path_lower:
                if _is_installed_via_registry("ManageEngine") or _is_installed_via_registry("Desktop Central") or _is_installed_via_registry("UEMS"):
                    return "đã cài rồi"
        return None

    def _execute_action(self, action: dict, from_llm: bool = False) -> str:
        """Execute action với tích hợp smart skip toàn diện.

        Mọi action loại install/uninstall/config/deploy/copy/fonts/bloatware
        đều tự động check skip TRƯỚC KHI chạy. Caller không cần check riêng.
        Nếu skip, trả về "[skip] ..." để caller hiện thông báo phù hợp.
        """
        t = action.get("type", "")

        # === SMART SKIP — áp dụng toàn diện cho mọi flow ===
        skip_types = {"install", "uninstall", "system_config", "set_hostname",
                      "deploy_portable", "install_fonts", "copy_to_all_users",
                      "remove_bloatware", "install_local"}
        if t in skip_types:
            skip_reason = self._check_skip(action)
            if skip_reason:
                short = self._describe_action_short(action)
                _audit("SKIP", f"{t}: {skip_reason}", "OK")
                return f"[skip] {short} -- {skip_reason}"

        # === EXECUTE ===
        if t == "install":
            return self.sw.install(action.get("package", ""))
        elif t == "install_local":
            path = self._resolve_local_path(action.get("path", ""))
            if from_llm and not self._is_safe_path(path):
                _audit("PATH_BLOCKED", f"unsafe path from LLM: {path}", "FAIL")
                return f"[error] Đường dẫn không được phép: {path}"
            return self.sw.install_local(path)
        elif t == "uninstall":
            return self.sw.uninstall(action.get("package", ""))
        elif t == "search":
            return self.sw.search(action.get("query", ""))
        elif t == "list_installed":
            return self.sw.list_installed()
        elif t == "system_config":
            return self.sys_cfg.apply(action.get("config", ""))
        elif t == "system_info":
            return self.sys_cfg.get_system_info()
        elif t == "get_hostname":
            return self.sys_cfg.get_hostname()
        elif t == "set_hostname":
            return self.sys_cfg.set_hostname(action.get("name", ""))
        elif t == "upgrade_all":
            return self.sw.upgrade_all()
        elif t == "export_apps":
            path = action.get("path", "")
            if from_llm and path:
                real = os.path.realpath(path)
                desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                if not real.startswith(os.path.realpath(desktop)):
                    _audit("PATH_BLOCKED", f"unsafe export path from LLM: {path}", "FAIL")
                    return f"[error] Chỉ được xuất ra Desktop: {path}"
            return self.sw.export_apps(path)
        elif t == "create_shortcut":
            target = action.get("target", "")
            if from_llm and target and not self._is_safe_path(target):
                _audit("PATH_BLOCKED", f"unsafe shortcut target from LLM: {target}", "FAIL")
                return f"[error] Đường dẫn shortcut không được phép: {target}"
            return create_shortcut(target, action.get("name", ""), action.get("desktop", "public"))
        elif t == "deploy_portable":
            source = self._resolve_local_path(action.get("source", ""))
            dest = action.get("dest", "")
            if from_llm:
                if not self._is_safe_path(source):
                    _audit("PATH_BLOCKED", f"unsafe deploy source from LLM: {source}", "FAIL")
                    return f"[error] Nguồn deploy không được phép: {source}"
                if dest and not self._is_safe_dest(dest):
                    _audit("PATH_BLOCKED", f"unsafe deploy dest from LLM: {dest}", "FAIL")
                    return f"[error] Thư mục đích không được phép: {dest}"
            return deploy_portable(source, dest, action.get("name", ""), action.get("exe", ""), action.get("desktop", "public"))
        elif t == "remove_bloatware":
            return self._remove_bloatware()
        elif t == "list_profiles":
            return self._list_profiles()
        elif t == "run_profile":
            return self._run_profile_sync(action.get("name", ""))
        elif t == "cli":
            return _run_cli_command(action.get("command", ""))
        elif t == "copy_to_all_users":
            source = self._resolve_local_path(action.get("source", ""))
            dest_rel = action.get("dest_relative", "")
            if from_llm and not self._is_safe_path(source):
                _audit("PATH_BLOCKED", f"unsafe copy source from LLM: {source}", "FAIL")
                return f"[error] Đường dẫn không được phép: {source}"
            return copy_to_all_users(source, dest_rel)
        elif t == "install_fonts":
            source = self._resolve_local_path(action.get("source", ""))
            if from_llm and not self._is_safe_path(source):
                _audit("PATH_BLOCKED", f"unsafe font source from LLM: {source}", "FAIL")
                return f"[error] Đường dẫn không được phép: {source}"
            return install_fonts(source)
        return ""

    def _check_skip_profile(self, name: str, on_output):
        """Dry-run profile: kiểm tra từng bước sẽ skip hay chạy, không thực thi gì."""
        profile = self._find_profile(name)
        if not profile:
            on_output(f"[error] Không tìm thấy profile: {name}", "fail")
            return
        pname = profile.get("name", name)
        actions = profile.get("actions", [])
        on_output(f"[check] Kiểm tra skip cho profile: {pname} ({len(actions)} bước)", "title")
        on_output("  (Dry-run — không thực thi gì)\n", "info")
        will_run = 0
        will_skip = 0
        for i, action in enumerate(actions, 1):
            short = self._describe_action_short(action)
            skip_reason = self._check_skip(action)
            if skip_reason:
                on_output(f"  [{i:2d}] [skip] {short} -- {skip_reason}", "info")
                will_skip += 1
            else:
                on_output(f"  [{i:2d}] [run]  {short}", "warn")
                will_run += 1
        on_output(f"\n[ok] Kết quả: {will_skip} bước skip, {will_run} bước sẽ chạy", "ok")

    def _list_profiles(self) -> str:
        profiles = self.config.get("profiles", {})
        if not profiles:
            return "[info] Chưa có profile nào. Thêm vào config.yaml."
        lines = ["[list] Các profile có sẵn:\n"]
        for key, p in profiles.items():
            name = p.get("name", key)
            actions = p.get("actions", [])
            lines.append(f"  {name} ({len(actions)} bước):")
            for i, a in enumerate(actions, 1):
                desc = self._describe_action_short(a)
                lines.append(f"    {i}. {desc}")
            lines.append("")
        lines.append("Gõ: cài máy mới")
        return "\n".join(lines)

    @staticmethod
    def _describe_action_short(action: dict) -> str:
        return AntiGravityAgent._describe_action(action, short=True)

    @staticmethod
    def _describe_action(action: dict, short: bool = False) -> str:
        """Mô tả action — short=True cho skip report, short=False cho progress."""
        t = action.get("type", "")
        # Mapping dữ liệu chung
        data = {
            "install": (f"Cài {action.get('package', '')}",
                       f"[...] Đang cài đặt: {action.get('package', '')}..."),
            "install_local": (f"Cài từ file: {os.path.basename(action.get('path', ''))}",
                             f"[...] Đang mở installer: {os.path.basename(action.get('path', ''))}..."),
            "uninstall": (f"Gỡ {action.get('package', '')}",
                         f"[...] Đang gỡ: {action.get('package', '')}..."),
            "search": (f"Tìm {action.get('query', '')}",
                      f"[search] Đang tìm: {action.get('query', '')}..."),
            "list_installed": ("Xem phần mềm đã cài",
                              "[list] Đang lấy danh sách phần mềm..."),
            "system_info": ("Xem thông tin hệ thống",
                           "[info] Đang lấy thông tin hệ thống..."),
            "get_hostname": ("Xem tên máy",
                           "[info] Đang lấy tên máy..."),
            "set_hostname": (f"Đặt tên máy: {action.get('name', '')}",
                           f"[...] Đang đặt tên máy: {action.get('name', '')}..."),
            "create_shortcut": (f"Tạo shortcut: {action.get('name', '')}",
                              f"[...] Đang tạo shortcut: {action.get('name', '')}..."),
            "deploy_portable": (f"Cài portable: {action.get('name', '')}",
                              f"[...] Đang cài portable: {action.get('name', '')}..."),
            "remove_bloatware": ("Gỡ bloatware",
                               "[...] Đang gỡ bloatware..."),
            "upgrade_all": ("Cập nhật tất cả phần mềm",
                          "[...] Đang cập nhật tất cả phần mềm..."),
            "export_apps": ("Xuất danh sách phần mềm",
                          "[...] Đang xuất danh sách phần mềm..."),
            "cli": (f"Chạy lệnh: {action.get('command', '')}",
                   f"[>] {action.get('command', '')}"),
            "copy_to_all_users": (f"Copy {os.path.basename(action.get('source', ''))} cho tất cả user",
                                f"[...] Đang copy {os.path.basename(action.get('source', ''))} cho tất cả user..."),
            "install_fonts": (f"Cài font từ {os.path.basename(action.get('source', ''))}",
                            f"[...] Đang cài font..."),
        }
        # system_config đặc biệt — có sub-mapping
        if t == "system_config":
            cfg = action.get("config", "")
            names = {
                "uac_off": "Tắt UAC", "uac_on": "Bật UAC",
                "dark_mode": "Bật Dark Mode", "light_mode": "Bật Light Mode",
                "show_file_ext": "Hiện đuôi file", "show_hidden_files": "Hiện file ẩn",
                "date_dmy": "Định dạng ngày dd/MM/yyyy",
                "taskbar_left": "Taskbar trái", "taskbar_center": "Taskbar giữa",
                "disable_telemetry": "Tắt telemetry",
                "disable_bing_search": "Tắt Bing trong Start Menu",
                "disable_copilot": "Tắt Copilot",
                "classic_context_menu": "Menu chuột phải cổ điển",
                "disable_notifications": "Tắt Notification Center",
                "enable_notifications": "Bật Notification Center",
                "disable_tips": "Tắt Tips/Gợi ý Windows",
                "search_icon_only": "Search chỉ hiện icon",
                "search_hidden": "Ẩn Search trên taskbar",
                "search_box": "Hiện ô Search trên taskbar",
                "disable_task_view": "Tắt Task View",
                "enable_task_view": "Bật Task View",
                "unpin_store_taskbar": "Gỡ Store khỏi taskbar",
            }
            if cfg.startswith("timezone_"):
                tz = cfg.replace("timezone_", "").replace("_", " ")
                short_name = f"Đặt timezone: {tz}"
            else:
                short_name = names.get(cfg, cfg)
            if short:
                return short_name
            return f"[config] Đang áp dụng: {cfg}..."
        if t in data:
            return data[t][0] if short else data[t][1]
        return t

    def _run_profile_sync(self, name: str) -> str:
        profile = self._find_profile(name)
        if not profile:
            return f"[error] Không tìm thấy profile: {name}\n{self._list_profiles()}"
        pname = profile.get("name", name)
        actions = profile.get("actions", [])
        results = [f"[profile] {pname} ({len(actions)} bước)\n"]
        for i, action in enumerate(actions, 1):
            if self._cancelled:
                results.append(f"[warn] Đã dừng tại bước {i}/{len(actions)}")
                break
            desc = self._describe_action(action)
            results.append(f"  [{i}/{len(actions)}] {desc}")
            result = self._execute_action(action)
            if result:
                results.append(f"  {result}")
        results.append(f"\n[ok] Hoàn thành profile: {pname}")
        return "\n".join(results)

    def _run_profile_feedback(self, name: str, on_output, on_raise=None):
        profile = self._find_profile(name)
        if not profile:
            on_output(f"[error] Không tìm thấy profile: {name}", "fail")
            return
        pname = profile.get("name", name)
        actions = profile.get("actions", [])
        _audit("PROFILE", f"name={pname} steps={len(actions)}", "OK")
        # Cảnh báo nếu cần admin mà chưa elevated
        needs_admin = any(a.get("type") in ("system_config", "remove_bloatware") for a in actions)
        if needs_admin and not is_elevated():
            on_output(f"[warn] Profile '{pname}' cần quyền Admin để cấu hình hệ thống.", "warn")
            on_output("  Gợi ý: Đóng app → Click phải → Run as Administrator", "warn")
        # Header hiện ngay — KHÔNG pre-compute skip (tránh block output)
        on_output(f"[profile] {pname} -- {len(actions)} bước", "title")
        ok_count = 0
        fail_count = 0
        skip_count = 0
        run_num = 0
        def _on_winget_line(line):
            on_output(f"    {line}", "info")
        set_progress_callback(_on_winget_line)
        try:
            for idx, action in enumerate(actions):
                # Delay nhỏ để UI kịp render từng bước (tránh dump hàng loạt)
                if idx > 0:
                    import time; time.sleep(1.0)
                if self._cancelled:
                    on_output(f"[warn] Đã dừng sau {run_num} bước chạy", "warn")
                    break
                # --- Skip check inline — output ngay ---
                skip_reason = self._check_skip(action)
                if skip_reason:
                    short = self._describe_action_short(action)
                    on_output(f"  [skip] {short} -- {skip_reason}", "info")
                    _audit("PROFILE_SKIP", f"{action.get('type','')} reason={skip_reason}", "OK")
                    skip_count += 1
                    continue
                run_num += 1
                desc = self._describe_action(action)
                on_output(f"  [{run_num}] {desc}", "progress")
                if action.get("type") == "remove_bloatware":
                    self._remove_bloatware_feedback(on_output, on_raise=None)
                    ok_count += 1
                    continue
                result = self._execute_action(action)
                if result:
                    if "[ok]" in result or "[info]" in result:
                        on_output(f"  {result}", "ok")
                        ok_count += 1
                    elif "[error]" in result:
                        on_output(f"  {result}", "fail")
                        fail_count += 1
                    else:
                        on_output(f"  {result}", "result")
                        ok_count += 1
        finally:
            set_progress_callback(None)
        summary = f"[ok] Hoàn thành: {pname} ({ok_count} thành công"
        if skip_count:
            summary += f", {skip_count} bỏ qua"
        if fail_count:
            summary += f", {fail_count} lỗi"
        summary += ")"
        on_output(summary, "ok")

    @staticmethod
    def _describe_action_progress(action: dict) -> str:
        """Alias for backward compat — dùng _describe_action(short=False)."""
        return AntiGravityAgent._describe_action(action, short=False)

    def _remove_bloatware(self) -> str:
        bloatware = self.config.get("bloatware", [])
        if not bloatware:
            return "[info] Danh sách bloatware trống. Thêm vào config.yaml."
        _audit("BLOATWARE", f"count={len(bloatware)}", "OK")
        ok = skip = fail = 0
        for pkg_id in bloatware:
            if self._cancelled:
                return f"[warn] Đã dừng gỡ bloatware: {ok} đã gỡ, {skip} không có, {fail} lỗi"
            result = self.sw.uninstall_system(pkg_id)
            if "[ok]" in result: ok += 1
            elif "[info]" in result: skip += 1
            else: fail += 1
        return f"[ok] Gỡ bloatware xong: {ok} đã gỡ, {skip} không có, {fail} lỗi"

    def _remove_bloatware_feedback(self, on_output, on_raise=None):
        bloatware = self.config.get("bloatware", [])
        if not bloatware:
            on_output("[info] Danh sách bloatware trống.", "info")
            return
        _audit("BLOATWARE", f"count={len(bloatware)}", "OK")
        # Lấy danh sách app đã cài MỘT LẦN (thay vì check từng app)
        on_output(f"[...] Đang kiểm tra {len(bloatware)} bloatware...", "progress")
        installed_output = _get_installed_list()
        ok = skip = fail = 0
        for i, pkg_id in enumerate(bloatware, 1):
            if self._cancelled:
                on_output(f"[warn] Đã dừng tại {i}/{len(bloatware)}", "warn")
                break
            # Skip nếu app không có trên máy (check pkg_id trong output lines)
            found = any(pkg_id.lower() in line for line in installed_output)
            if not found:
                skip += 1
                continue
            on_output(f"    [{i}/{len(bloatware)}] Đang gỡ {pkg_id}...", "info")
            result = self.sw.uninstall_system(pkg_id)
            if "[ok]" in result: ok += 1
            else: fail += 1
            if on_raise:
                on_raise()
        on_output(f"[ok] Bloatware: {ok} đã gỡ, {skip} không có, {fail} lỗi", "ok")

    def chat_with_feedback(self, user_input: str, on_output, on_raise=None):
        self._cancel_event.clear()
        # === FAST PATH ===
        fast_actions = parse_fast(user_input, self.config.get("quick_commands"))
        if fast_actions is not None:
            _audit("FAST_PATH", f"input={user_input[:80]}", "OK")
            # Phân loại: diagnostic (nhiều CLI) hay action thường?
            is_diagnostic = (
                len(fast_actions) > 1
                and all(a.get("type") == "cli" for a in fast_actions)
            ) or (
                len(fast_actions) >= 1
                and fast_actions[0].get("type") == "cli"
                and any(kw in user_input.lower() for kw in [
                    "chậm", "lag", "lỗi", "mất", "không", "die", "chẩn đoán",
                    "slow", "error", "fix", "check", "kiểm tra"
                ])
            )
            # Bật progress callback
            def _on_winget_line(line):
                on_output(f"    {line}", "info")
            set_progress_callback(_on_winget_line)
            try:
                # Thu thập kết quả CLI cho diagnostic
                cli_results = []
                for action in fast_actions:
                    if self._cancelled:
                        break
                    atype = action.get("type")
                    if atype == "help":
                        on_output("help", "_ui_cmd")
                        continue
                    if atype == "clear":
                        on_output("clear", "_ui_cmd")
                        continue
                    if atype == "run_profile":
                        self._run_profile_feedback(action.get("name", ""), on_output, on_raise)
                        continue
                    if atype == "list_profiles":
                        on_output(self._list_profiles(), "info")
                        continue
                    if atype == "check_skip_profile":
                        self._check_skip_profile(action.get("name", "mac_dinh"), on_output)
                        continue
                    if atype == "cli":
                        cmd = action.get("command", "")
                        on_output(f"[>] {cmd}", "progress")
                        result = _run_cli_command(cmd)
                        tag = "fail" if "[error]" in result else "cli_output"
                        on_output(result, tag)
                        if is_diagnostic:
                            cli_results.append(f"$ {cmd}\n{result}")
                        continue
                    desc = self._describe_action(action)
                    if desc:
                        on_output(desc, "progress")
                    result = self._execute_action(action)
                    if result:
                        tag = "info" if "[skip]" in result else (
                            "ok" if "[ok]" in result or "[info]" in result else (
                            "fail" if "[error]" in result or "[loi]" in result else "result"))
                        on_output(result, tag)
            finally:
                set_progress_callback(None)

            # === DIAGNOSTIC → LLM ANALYSIS ===
            if is_diagnostic and cli_results and self.client and not self._cancelled:
                on_output("[...] Đang phân tích kết quả...", "progress")
                analysis_prompt = (
                    f"User hỏi: \"{user_input}\"\n\n"
                    "=== KẾT QUẢ CHẨN ĐOÁN ===\n" +
                    "\n---\n".join(cli_results) +
                    "\n\nDỰA VÀO kết quả trên:\n"
                    "1. Phân tích ngắn gọn vấn đề tìm thấy\n"
                    "2. Tạo actions để FIX NGAY nếu có thể\n"
                    "3. Nếu cần thêm thông tin → tạo actions thu thập thêm\n"
                    "4. Trả lời JSON: {\"message\": \"...\", \"actions\": [...], \"done\": false/true}"
                )
                self._llm_agentic_loop(analysis_prompt, on_output, on_raise)
            return

        # === LLM PATH ===
        if not self.client:
            self._connect_llm()
            if not self.client:
                on_output("[error] Không hiểu lệnh và không kết nối được LLM.\nThử: 'cài chrome', 'gỡ teamviewer', 'bật dark mode'", "fail")
                return
        self._llm_agentic_loop(user_input, on_output, on_raise)

    def _llm_agentic_loop(self, user_input: str, on_output, on_raise=None, max_rounds: int = 6):
        """LLM Agentic Loop — chạy đến khi LLM báo done=true hoặc hết rounds.

        Flow mỗi round:
          1. Gọi LLM với history (bao gồm kết quả round trước)
          2. Parse JSON → lấy message + actions + done
          3. Execute tất cả actions, thu kết quả chi tiết (ok/fail/skip)
          4. Nếu done=true hoặc không có actions → dừng
          5. Nếu còn actions → feed kết quả vào history → round tiếp theo
        """
        self.history.append({"role": "user", "content": user_input})
        self._trim_history()

        for round_num in range(max_rounds):
            if self._cancelled:
                on_output("[warn] Đã dừng.", "warn")
                break

            # --- Emit trạng thái trước khi gọi LLM (tránh UI đứng im) ---
            if round_num == 0:
                on_output(f"[...] Đang hỏi {self.provider_name}...", "progress")
            else:
                on_output(f"[...] Phân tích kết quả, round {round_num + 1}/{max_rounds}...", "progress")

            # --- Gọi LLM (streaming để UI không đứng im) ---
            try:
                stream = self.client.chat.completions.create(
                    model=self.model, messages=self.history, temperature=0.2,
                    stream=True,
                )
                # Accumulate streamed chunks — cập nhật spinner mỗi 20 chars
                reply_parts = []
                char_count = 0
                for chunk in stream:
                    if self._cancelled:
                        break
                    delta = chunk.choices[0].delta if chunk.choices else None
                    if delta and delta.content:
                        reply_parts.append(delta.content)
                        char_count += len(delta.content)
                        # Cập nhật spinner text để user thấy LLM đang phản hồi
                        if char_count % 20 < len(delta.content):
                            on_output(f"[...] LLM đang phản hồi... [{char_count} ký tự]", "progress")
                reply = "".join(reply_parts).strip()
                if not reply:
                    on_output("[warn] LLM trả về rỗng.", "warn")
                    return
            except Exception as e:
                _audit("LLM_ERROR", f"{self.provider_name}: {e}", "FAIL")
                on_output(f"[error] LLM lỗi: {e}", "fail")
                return

            self.history.append({"role": "assistant", "content": reply})

            # --- Parse JSON ---
            try:
                data = self._extract_json(reply)
                message = data.get("message", "")
                actions = data.get("actions", [])
                is_done = data.get("done", False)
            except Exception:
                # LLM trả plain text — hiển thị và dừng
                on_output(reply, "result")
                return

            if message:
                on_output(message, "info")

            # Không có actions → dừng (dù done hay không)
            if not actions:
                return

            # --- Execute actions, thu kết quả chi tiết ---
            action_results = []   # feed lại cho LLM
            has_any_result = False

            def _on_winget_line(line):
                on_output(f"    {line}", "info")
            set_progress_callback(_on_winget_line)

            try:
                for action in actions:
                    if self._cancelled:
                        break
                    atype = action.get("type", "")

                    if atype == "cli":
                        cmd = action.get("command", "")
                        on_output(f"[>] {cmd}", "progress")
                        result = _run_cli_command(cmd)
                        tag = "fail" if "[error]" in result else "cli_output"
                        on_output(result, tag)
                        # Luôn thu kết quả CLI vào feedback
                        action_results.append(f"[CLI] $ {cmd}\n{result}")
                        has_any_result = True
                        if on_raise:
                            on_raise()
                        continue

                    desc = self._describe_action(action)
                    if desc:
                        on_output(desc, "progress")

                    result = self._execute_action(action, from_llm=True)

                    if result:
                        if "[skip]" in result:
                            tag = "info"
                        elif "[ok]" in result or "[info]" in result:
                            tag = "ok"
                        elif "[error]" in result or "[warn]" in result:
                            tag = "fail"
                        else:
                            tag = "result"
                        on_output(f"  {result}", tag)
                        # Thu kết quả tất cả action types (không chỉ CLI)
                        action_results.append(f"[{atype.upper()}] {result}")
                        has_any_result = True

                    if on_raise:
                        on_raise()
            finally:
                set_progress_callback(None)

            # --- Dừng nếu done hoặc không có gì để feed lại ---
            if is_done or not has_any_result or self._cancelled:
                return

            # --- Feed kết quả vào history cho round tiếp ---
            # Phân loại kết quả để LLM dễ phân tích
            ok_results = [r for r in action_results if ("[ok]" in r or "[CLI]" in r) and "[error]" not in r]
            fail_results = [r for r in action_results if "[error]" in r or "[warn]" in r]
            skip_results = [r for r in action_results if "[skip]" in r]

            feedback_parts = ["=== KET QUA THUC THI ==="]
            if ok_results:
                feedback_parts.append(f"[ok] Thanh cong ({len(ok_results)}):\n" + "\n".join(ok_results))
            if fail_results:
                feedback_parts.append(f"[x] That bai ({len(fail_results)}):\n" + "\n".join(fail_results))
            if skip_results:
                feedback_parts.append(f"[skip] Bo qua ({len(skip_results)}): da hoan thanh truoc do")
            feedback_parts.append(
                "\nDỰA VÀO kết quả trên:\n"
                "- Nếu có lỗi cần fix → tạo actions để fix, done=false\n"
                "- Nếu cần thêm thông tin → tạo actions để thu thập, done=false\n"
                "- Nếu đã hoàn thành → tóm tắt ngắn gọn, actions=[], done=true"
            )

            feedback = "\n\n".join(feedback_parts)
            self.history.append({"role": "user", "content": feedback})
            self._trim_history()

        # Hết rounds mà chưa done
        _audit("AGENTIC_LOOP", f"reached max_rounds={max_rounds}", "WARN")

