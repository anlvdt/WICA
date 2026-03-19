# -*- coding: utf-8 -*-
"""Core agent logic - Fast path + LLM fallback.

Lệnh rõ ràng (cài X, gỡ Y, bật dark mode) -> xử lý NGAY bằng regex.
Lệnh phức tạp/mơ hồ -> mới gọi LLM.
"""
import json
import yaml
import os
from openai import OpenAI
from tools import SoftwareManager, SystemConfigurator, REGISTRY_CONFIGS, _audit, create_shortcut, deploy_portable, set_progress_callback, _run_cli_command, copy_to_all_users, install_fonts
from fast_commands import parse_fast
from keystore import get_key

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
MAX_HISTORY = 20

SYSTEM_PROMPT = """Bạn là WICA (Windows Install CLI Agent), trợ lý quản lý hệ thống Windows qua chat.
Bạn có thể: cài đặt phần mềm (online qua winget hoặc từ file local), gỡ phần mềm, cấu hình hệ thống.

QUAN TRỌNG: Bạn PHẢI trả lời bằng JSON với format sau:
{{
  "message": "Tin nhắn cho người dùng",
  "actions": [
    {{"type": "install", "package": "tên_package"}},
    {{"type": "install_local", "path": "đường_dẫn_file"}},
    {{"type": "uninstall", "package": "tên_package"}},
    {{"type": "search", "query": "từ_khóa"}},
    {{"type": "list_installed"}},
    {{"type": "system_config", "config": "tên_config"}},
    {{"type": "system_info"}},
    {{"type": "upgrade_all"}},
    {{"type": "export_apps", "path": "đường_dẫn_file.json"}}
  ]
}}

Nếu chỉ trò chuyện, trả về actions rỗng: {{"message": "...", "actions": []}}

Aliases phần mềm có sẵn:
{aliases}

System configs có sẵn:
{configs}

Quy tắc:
- Luôn xác nhận trước khi thực hiện hành động nguy hiểm
- Dùng alias nếu có, nếu không dùng tên gốc để search winget
- Với nhiều phần mềm, tạo nhiều actions
- Khi user muốn cài từ file local, dùng "install_local" với đường dẫn đầy đủ
- install_local sẽ mở installer bình thường (giống user double-click), KHÔNG silent install
- Trả lời bằng tiếng Việt có dấu
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
        self.client = None
        self.model = None
        self.provider_name = None
        self._connect_llm()
        self._cancelled = False
        self.sw = SoftwareManager(self.aliases, self.local_paths)
        self.sys_cfg = SystemConfigurator()
        self.history = [
            {"role": "system", "content": SYSTEM_PROMPT.format(
                aliases=json.dumps(self.aliases, indent=2, ensure_ascii=False),
                configs=json.dumps(list(REGISTRY_CONFIGS.keys()), ensure_ascii=False),
            )}
        ]

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
                import ctypes
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
        self._cancelled = True

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
            return json.loads(text[start:end])
        raise ValueError("No JSON found")

    def _resolve_local_path(self, path: str) -> str:
        path = path.strip().strip('"').strip("'")
        if os.path.isabs(path):
            return path
        for base in self.local_paths:
            full = os.path.join(base, path)
            if os.path.exists(full):
                return full
        tried = ", ".join(self.local_paths) if self.local_paths else "(chưa cấu hình local_paths)"
        _audit("RESOLVE_PATH", f"not found: {path} in {tried}", "FAIL")
        return path

    def _is_safe_path(self, path: str) -> bool:
        """Kiểm tra path nằm trong local_paths cho phép (chống path traversal)."""
        if not self.local_paths:
            return False
        real = os.path.realpath(path)
        for base in self.local_paths:
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

    def _execute_action(self, action: dict, from_llm: bool = False) -> str:
        t = action.get("type", "")
        if t == "install":
            return self.sw.install(action.get("package", ""))
        elif t == "install_local":
            path = self._resolve_local_path(action.get("path", ""))
            # validate path khi action từ LLM (chống path traversal)
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
        t = action.get("type", "")
        if t == "install":
            return f"Cài {action.get('package', '')}"
        elif t == "install_local":
            return f"Cài từ file: {os.path.basename(action.get('path', ''))}"
        elif t == "uninstall":
            return f"Gỡ {action.get('package', '')}"
        elif t == "system_config":
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
                "disable_weather": "Tắt Weather trên taskbar",
                "disable_widgets": "Tắt Widgets trên taskbar",
                "search_icon_only": "Search chỉ hiện icon",
                "search_hidden": "Ẩn Search trên taskbar",
                "search_box": "Hiện ô Search trên taskbar",
                "disable_task_view": "Tắt Task View",
                "enable_task_view": "Bật Task View",
                "unpin_store_taskbar": "Gỡ Store khỏi taskbar",
            }
            if cfg.startswith("timezone_"):
                tz = cfg.replace("timezone_", "").replace("_", " ")
                return f"Đặt timezone: {tz}"
            return names.get(cfg, cfg)
        elif t == "deploy_portable":
            return f"Cài portable: {action.get('name', '')}"
        elif t == "remove_bloatware":
            return "Gỡ bloatware"
        elif t == "create_shortcut":
            return f"Tạo shortcut: {action.get('name', '')}"
        elif t == "upgrade_all":
            return "Cập nhật tất cả phần mềm"
        elif t == "export_apps":
            return "Xuất danh sách phần mềm"
        elif t == "cli":
            return f"Chạy lệnh: {action.get('command', '')}"
        elif t == "copy_to_all_users":
            return f"Copy {os.path.basename(action.get('source', ''))} cho tất cả user"
        elif t == "install_fonts":
            return f"Cài font từ {os.path.basename(action.get('source', ''))}"
        elif t == "get_hostname":
            return "Xem tên máy"
        elif t == "set_hostname":
            return f"Đặt tên máy: {action.get('name', '')}"
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

    def _run_profile_feedback(self, name: str, on_output):
        profile = self._find_profile(name)
        if not profile:
            on_output(f"[error] Không tìm thấy profile: {name}", "fail")
            return
        pname = profile.get("name", name)
        actions = profile.get("actions", [])
        _audit("PROFILE", f"name={pname} steps={len(actions)}", "OK")
        on_output(f"[profile] {pname} -- {len(actions)} bước", "title")
        ok_count = 0
        fail_count = 0
        def _on_winget_line(line):
            on_output(f"    {line}", "info")
        set_progress_callback(_on_winget_line)
        try:
            for i, action in enumerate(actions, 1):
                if self._cancelled:
                    on_output(f"[warn] Đã dừng tại bước {i}/{len(actions)}", "warn")
                    break
                desc = self._describe_action(action)
                on_output(f"  [{i}/{len(actions)}] {desc}", "progress")
                if action.get("type") == "remove_bloatware":
                    self._remove_bloatware_feedback(on_output)
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
        on_output(f"[ok] Hoàn thành: {pname} ({ok_count} thành công, {fail_count} lỗi)", "ok")

    @staticmethod
    def _describe_action(action: dict) -> str:
        t = action.get("type", "")
        descs = {
            "install": f"[...] Đang cài đặt: {action.get('package', '')}...",
            "install_local": f"[...] Đang mở installer: {os.path.basename(action.get('path', ''))}...",
            "uninstall": f"[...] Đang gỡ: {action.get('package', '')}...",
            "search": f"[search] Đang tìm: {action.get('query', '')}...",
            "list_installed": "[list] Đang lấy danh sách phần mềm...",
            "system_config": f"[config] Đang áp dụng: {action.get('config', '')}...",
            "system_info": "[info] Đang lấy thông tin hệ thống...",
            "get_hostname": "[info] Đang lấy tên máy...",
            "set_hostname": f"[...] Đang đặt tên máy: {action.get('name', '')}...",
            "create_shortcut": f"[...] Đang tạo shortcut: {action.get('name', '')}...",
            "deploy_portable": f"[...] Đang cài portable: {action.get('name', '')}...",
            "remove_bloatware": "[...] Đang gỡ bloatware...",
            "upgrade_all": "[...] Đang cập nhật tất cả phần mềm...",
            "export_apps": "[...] Đang xuất danh sách phần mềm...",
            "cli": f"[>] {action.get('command', '')}",
            "copy_to_all_users": f"[...] Đang copy {os.path.basename(action.get('source', ''))} cho tất cả user...",
            "install_fonts": f"[...] Đang cài font...",
        }
        return descs.get(t, "")

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

    def _remove_bloatware_feedback(self, on_output):
        bloatware = self.config.get("bloatware", [])
        if not bloatware:
            on_output("[info] Danh sách bloatware trống.", "info")
            return
        _audit("BLOATWARE", f"count={len(bloatware)}", "OK")
        on_output(f"[...] Đang gỡ {len(bloatware)} bloatware...", "progress")
        ok = skip = fail = 0
        for i, pkg_id in enumerate(bloatware, 1):
            if self._cancelled:
                on_output(f"[warn] Đã dừng tại {i}/{len(bloatware)}", "warn")
                break
            on_output(f"    [{i}/{len(bloatware)}] {pkg_id}...", "info")
            result = self.sw.uninstall_system(pkg_id)
            if "[ok]" in result: ok += 1
            elif "[info]" in result: skip += 1
            else: fail += 1
        on_output(f"[ok] Bloatware: {ok} đã gỡ, {skip} không có, {fail} lỗi", "ok")

    def chat_with_feedback(self, user_input: str, on_output):
        self._cancelled = False
        # === FAST PATH ===
        fast_actions = parse_fast(user_input, self.config.get("quick_commands"))
        if fast_actions is not None:
            _audit("FAST_PATH", f"input={user_input[:80]}", "OK")
            # Bật progress callback cho cả lệnh đơn lẻ
            def _on_winget_line(line):
                on_output(f"    {line}", "info")
            set_progress_callback(_on_winget_line)
            try:
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
                        self._run_profile_feedback(action.get("name", ""), on_output)
                        continue
                    if atype == "list_profiles":
                        on_output(self._list_profiles(), "info")
                        continue
                    if atype == "cli":
                        cmd = action.get("command", "")
                        on_output(f"[>] {cmd}", "progress")
                        result = _run_cli_command(cmd)
                        tag = "fail" if "[error]" in result else "cli_output"
                        on_output(result, tag)
                        continue
                    desc = self._describe_action(action)
                    if desc:
                        on_output(desc, "progress")
                    result = self._execute_action(action)
                    if result:
                        tag = "ok" if "[ok]" in result or "[info]" in result else (
                            "fail" if "[error]" in result or "[loi]" in result else "result")
                        on_output(result, tag)
            finally:
                set_progress_callback(None)
            return
        # === LLM PATH ===
        on_output("[...] Đang hỏi AI...", "progress")
        if not self.client:
            self._connect_llm()
            if not self.client:
                on_output("[error] Không hiểu lệnh và không kết nối được LLM.\nThử: 'cài chrome', 'gỡ teamviewer', 'bật dark mode'", "fail")
                return
        self.history.append({"role": "user", "content": user_input})
        self._trim_history()
        try:
            response = self.client.chat.completions.create(model=self.model, messages=self.history, temperature=0.3)
            reply = response.choices[0].message.content.strip()
        except Exception as e:
            _audit("LLM_ERROR", f"{self.provider_name}: {e}", "FAIL")
            on_output(f"[error] LLM lỗi: {e}", "fail")
            return
        self.history.append({"role": "assistant", "content": reply})
        try:
            data = self._extract_json(reply)
            message = data.get("message", "")
            actions = data.get("actions", [])
        except Exception:
            on_output(reply, "result")
            return
        if message:
            on_output(message, "info")
        # Bật progress callback cho LLM actions
        def _on_winget_line(line):
            on_output(f"    {line}", "info")
        set_progress_callback(_on_winget_line)
        try:
            for action in actions:
                if self._cancelled:
                    break
                desc = self._describe_action(action)
                if desc:
                    on_output(desc, "progress")
                result = self._execute_action(action, from_llm=True)
                if result:
                    tag = "ok" if "[ok]" in result or "[info]" in result else (
                        "fail" if "[error]" in result or "[loi]" in result else "result")
                    on_output(result, tag)
        finally:
            set_progress_callback(None)
