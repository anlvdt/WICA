# -*- coding: utf-8 -*-
"""Fast command parser - xử lý lệnh ngay lập tức, không cần LLM.

Các lệnh rõ ràng (cài X, gỡ Y, bật dark mode...) được xử lý local
bằng regex matching. Chỉ gọi LLM khi câu lệnh mơ hồ/phức tạp.
"""
import re
from shared_constants import no_accent as _no_accent

# Patterns cho các lệnh phổ biến
INSTALL_PATTERNS = [
    r"(?:cài|cai|install|setup|tải|tai|cài đặt|cai dat)\s+(.+)",
]

UNINSTALL_PATTERNS = [
    r"(?:gỡ cài đặt|go cai dat|gỡ cài|go cai|gỡ bỏ|go bo|gỡ|go|uninstall|remove|xóa|xoa)\s+(.+)",
]

SEARCH_PATTERNS = [
    r"(?:tìm|tim|search|tìm kiếm|tim kiem|kiếm|kiem)\s+(.+)",
]

CONFIG_MAP = {
    r"(?:bật|bat|bật chế độ tối|dark\s*mode|che do toi|chế độ tối)": "dark_mode",
    r"(?:bật sáng|bat sang|light\s*mode|chế độ sáng|che do sang)": "light_mode",
    r"(?:hiện đuôi|hien duoi|hiện phần mở rộng|show.*ext|file ext)": "show_file_ext",
    r"(?:hiện file ẩn|hien file an|show.*hidden|hiện tệp ẩn)": "show_hidden_files",
    r"(?:ẩn file ẩn|an file an|hide.*hidden|ẩn tệp ẩn)": "hide_hidden_files",
    r"(?:taskbar.*(?:trái|trai|left))": "taskbar_left",
    r"(?:taskbar.*(?:giữa|giua|center))": "taskbar_center",
    r"(?:tắt|tat|disable).*(?:telemetry|thu thập|thu thap)": "disable_telemetry",
    r"(?:tắt|tat|disable).*(?:bing|bing search)": "disable_bing_search",
    r"(?:tắt|tat|disable).*copilot": "disable_copilot",
    r"(?:menu.*(?:cổ điển|co dien|classic)|classic.*(?:context|menu)|right.?click.*(?:cũ|cu|classic))": "classic_context_menu",
    r"(?:tắt|tat|disable).*(?:notification|thông báo|thong bao)": "disable_notifications",
    r"(?:bật|bat|enable).*(?:notification|thông báo|thong bao)": "enable_notifications",
    r"(?:tắt|tat|disable).*(?:tips|mẹo|meo|gợi ý|goi y)": "disable_tips",
    r"(?:search|tìm kiếm|tim kiem).*(?:icon|biểu tượng|bieu tuong|only)": "search_icon_only",
    r"(?:ẩn|an|hide|tắt|tat).*(?:search|tìm kiếm|tim kiem).*(?:box|ô|thanh)": "search_hidden",
    r"(?:tắt|tat|ẩn|an|disable|hide).*(?:task\s*view)": "disable_task_view",
    r"(?:bật|bat|hiện|hien|enable|show).*(?:task\s*view)": "enable_task_view",
    r"(?:unpin|gỡ|go|bỏ|bo|xóa|xoa).*(?:store|microsoft store).*(?:taskbar)": "unpin_store_taskbar",
    r"(?:unpin|gỡ|go|bỏ|bo|xóa|xoa).*(?:taskbar).*(?:store|microsoft store)": "unpin_store_taskbar",
}

INFO_PATTERNS = [
    r"(?:thông tin|thong tin|info|system info|máy tính|may tinh|cấu hình máy|cau hinh may)",
]

HOSTNAME_GET_PATTERNS = [
    r"(?:xem|check|lấy|lay)\s+(?:tên máy|ten may|hostname)",
    r"(?:tên máy|ten may|hostname)\s*(?:là gì|la gi|hiện tại|hien tai)?$",
]

HOSTNAME_SET_PATTERNS = [
    r"(?:đặt|dat|set|đổi|doi|rename)\s+(?:tên máy|ten may|hostname)\s+(.+)",
]

LIST_PATTERNS = [
    r"(?:liệt kê|liet ke|danh sách|danh sach|list|xem.*(?:đã cài|da cai|installed))",
]

PROFILE_PATTERNS = [
    r"(?:chạy|chay|dùng|dung|áp dụng|ap dung|run|apply)\s+profile\s+(.+)",
    r"profile\s+(.+)",
]

SETUP_NEW_PATTERNS = [
    r"(?:cài|cai|setup|cấu hình|cau hinh)\s+(?:máy mới|may moi|máy|may)\s*(?:mới|moi)?",
    r"(?:máy mới|may moi)",
]

SETUP_TAX_PATTERNS = [
    r"(?:cài|cai|setup|chạy|chay|run)\s+(?:ph[aầ]n m[eề]m\s+)?thu[eế](?!\s*dll)",
    r"(?:profile|ch[aạ]y profile)\s+thu[eế](?!\s*dll)",
    r"ph[aầ]n m[eề]m\s+thu[eế](?!\s*dll)",
]

SETUP_TAX_DLL_PATTERNS = [
    r"(?:cài|cai|setup|chạy|chay|run)\s+(?:ph[aầ]n m[eề]m\s+)?thu[eế]\s*dll",
    r"(?:profile|ch[aạ]y profile)\s+thu[eế]\s*dll",
    r"ph[aầ]n m[eề]m\s+thu[eế]\s*dll",
    r"thu[eế]\s*dll",
]

LIST_PROFILE_PATTERNS = [
    r"(?:danh sách|danh sach|xem|list)\s+profile",
    r"profile\s*$",
]

HELP_PATTERNS = [
    r"^(?:help|h[uư][oớ]ng d[aẫ]n|\?|tr[oợ] gi[uú]p)$",
]

CLEAR_PATTERNS = [
    r"^(?:clear|cls|x[oó]a m[aà]n h[iì]nh|xoa man hinh|l[aà]m s[aạ]ch)$",
]

CHECK_SKIP_PATTERNS = [
    r"(?:ki[eể]m tra|kiem tra|check)\s+skip",
    r"(?:xem|check)\s+(?:skip|b[oỏ] qua|bo qua)",
    r"skip\s+(?:ho[aạ]t [dđ][oộ]ng|hoat dong|check|ki[eể]m tra|kiem tra)",
]

UPGRADE_PATTERNS = [
    r"^(?:c[aậ]p nh[aậ]t|cap nhat|upgrade|update)\s*(?:t[aấ]t c[aả]|tat ca|all|h[eế]t|het)?$",
]

EXPORT_PATTERNS = [
    r"(?:xu[aấ]t|xuat|export)\s*(?:danh s[aá]ch|danh sach|app|list|ph[aầ]n m[eề]m|phan mem)?",
]

# Diagnostic patterns → auto-generate multi-action CLI chains (no LLM needed)
DIAGNOSTIC_PATTERNS = {
    # Mạng chậm / không có mạng
    r"(?:m[aạ]ng|mang)\s*(?:ch[aậ]m|cham|y[eế]u|yeu|l[aỗ]i|loi|kh[oô]ng|khong|m[aấ]t|mat|die|lag|drop|disconnect)": [
        {"type": "cli", "command": "ipconfig /all"},
        {"type": "cli", "command": "ping 8.8.8.8 -n 4"},
        {"type": "cli", "command": "nslookup google.com"},
    ],
    r"(?:kh[oô]ng|khong|ko)\s*(?:v[aà]o|vao|k[eế]t n[oố]i|ket noi)\s*(?:đ[uư][oợ]c|duoc)?\s*(?:m[aạ]ng|mang|net|web|internet)": [
        {"type": "cli", "command": "ipconfig /all"},
        {"type": "cli", "command": "ping 8.8.8.8 -n 4"},
        {"type": "cli", "command": "ping google.com -n 4"},
    ],
    # Máy lag / máy chậm
    r"(?:m[aá]y|may)\s*(?:ch[aậ]m|cham|lag|gi[aậ]t|giat|đ[oơ]|do|treo|đứng)": [
        {"type": "cli", "command": "tasklist /FI \"MEMUSAGE gt 100000\" /FO TABLE"},
        {"type": "system_info"},
    ],
    # Fix DNS / flush DNS
    r"(?:fix|flush|x[oó]a|xoa|l[aà]m m[oớ]i|lam moi|reset)\s*dns": [
        {"type": "cli", "command": "ipconfig /flushdns"},
        {"type": "cli", "command": "nslookup google.com"},
    ],
    # Kiểm tra ổ đĩa / disk
    r"(?:ki[eể]m tra|kiem tra|check|xem)\s*(?:[oổ] [dđ][iĩ]a|o dia|disk|[oổ] c[uứ]ng|o cung|ssd|hdd)": [
        {"type": "cli", "command": "fsutil volume diskfree C:"},
        {"type": "cli", "command": "reg query \"HKLM\\HARDWARE\\DEVICEMAP\\Scsi\" /s /v Identifier"},
    ],
    # Xem port / cổng
    r"(?:xem|check|ki[eể]m tra|kiem tra)\s*(?:port|c[oổ]ng|cong|k[eế]t n[oố]i|ket noi)\s*(?:đang d[uù]ng|dang dung)?": [
        {"type": "cli", "command": "netstat -ano"},
    ],
    # Xem Wi-Fi / WiFi password / mật khẩu wifi
    r"(?:xem|check|l[aấ]y|lay)\s*(?:m[aậ]t kh[aẩ]u|mat khau|pass|password)\s*(?:wifi|wi-fi)": [
        {"type": "cli", "command": "netsh wlan show profiles"},
    ],
    r"(?:wifi|wi-fi)\s*(?:m[aậ]t kh[aẩ]u|mat khau|pass|password|info)": [
        {"type": "cli", "command": "netsh wlan show profiles"},
    ],
    # IP / địa chỉ IP
    r"(?:xem|check|l[aấ]y|lay)\s*(?:ip|[dđ][iị]a ch[iỉ]|dia chi)\s*(?:m[aá]y|may|c[uủ]a|cua)?": [
        {"type": "cli", "command": "ipconfig /all"},
    ],
    # Xem user / người dùng
    r"(?:xem|check|\bai\b|user|ng[uư][oờ]i d[uù]ng|nguoi dung)\s*(?:đang [dđ][aă]ng nh[aậ]p|dang dang nhap|hi[eệ]n t[aạ]i|hien tai)?": [
        {"type": "cli", "command": "whoami /all"},
    ],
    # Xem tiến trình / process
    r"(?:xem|check|li[eệ]t k[eê])\s*(?:ti[eế]n tr[iì]nh|tien trinh|process|task)": [
        {"type": "cli", "command": "tasklist /FO TABLE"},
    ],
    # Kiểm tra Windows Update
    r"(?:l[oỗ]i|loi|fix|s[uử]a|sua|ki[eể]m tra|kiem tra|check)\s*(?:windows\s*)?update": [
        {"type": "cli", "command": "sc query wuauserv"},
        {"type": "cli", "command": "sc query bits"},
    ],
    # Gỡ bloatware
    r"(?:g[oỡ]|go|x[oó]a|xoa|remove|delete)\s*(?:bloatware|r[aá]c|rac|app r[aá]c|app rac)": [
        {"type": "remove_bloatware"},
    ],
    # Dọn Start Menu
    r"(?:d[oọ]n|don|clean|x[oó]a|xoa|remove|clear)\s*(?:start\s*menu|startmenu|icon\s*(?:r[aá]c|rac|qu[aả]ng\s*c[aá]o|quang cao|gi[aả]i\s*tr[ií]|giai tri))": [
        {"type": "clean_start_menu"},
    ],
}


# CLI commands - import từ shared_constants (single source of truth)
from shared_constants import CLI_WHITELIST as _CLI_COMMANDS


def parse_fast(text: str, quick_commands: dict = None) -> list[dict] | None:
    """Parse lệnh nhanh. Trả về list actions hoặc None nếu cần LLM."""
    text = text.strip()
    text_lower = text.lower()

    # Help
    for p in HELP_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "help"}]

    # Clear
    for p in CLEAR_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "clear"}]

    # Check skip
    for p in CHECK_SKIP_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "check_skip_profile", "name": "mac_dinh"}]

    # CLI command - detect khi input bắt đầu bằng lệnh whitelist
    first_word = text_lower.split()[0].replace(".exe", "") if text_lower.split() else ""
    if first_word in _CLI_COMMANDS:
        return [{"type": "cli", "command": text}]

    # Diagnostic patterns — multi-action CLI chains (mạng chậm, máy lag, etc.)
    for pattern, actions in DIAGNOSTIC_PATTERNS.items():
        if re.search(pattern, text_lower):
            import copy
            return copy.deepcopy(actions)

    # Quick commands từ config.yaml (cài teamviewer qs, copy profile vpn, cài font...)
    if quick_commands:
        # Bỏ prefix "cài", "cài đặt", "setup", "copy" để match
        stripped = re.sub(
            r"^(?:cài đặt|cai dat|cài|cai|setup|copy)\s+", "", text_lower
        ).strip()
        text_na = _no_accent(text_lower)
        stripped_na = _no_accent(stripped)
        for cmd_name, cmd_data in quick_commands.items():
            cmd_na = _no_accent(cmd_name)
            if text_lower == cmd_name or stripped == cmd_name:
                action = cmd_data.get("action", {})
                if action:
                    return [action]
            # Match không dấu
            if text_na == cmd_na or stripped_na == cmd_na:
                action = cmd_data.get("action", {})
                if action:
                    return [action]
            # Cũng match nếu user gõ "cài <tên>" hoặc "setup <tên>"
            cmd_stripped = cmd_name.replace("cài ", "").replace("cài đặt ", "")
            cmd_stripped_na = _no_accent(cmd_stripped)
            if stripped == cmd_stripped or stripped_na == cmd_stripped_na:
                action = cmd_data.get("action", {})
                if action:
                    return [action]

    # Setup máy mới = chạy profile mặc định
    for p in SETUP_NEW_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "run_profile", "name": "mac_dinh"}]

    # Setup phần mềm thuế = chạy profile thue
    for p in SETUP_TAX_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "run_profile", "name": "thue"}]

    # Setup phần mềm thuế DLL = chạy profile thue_dll
    for p in SETUP_TAX_DLL_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "run_profile", "name": "thue_dll"}]

    # List profiles
    for p in LIST_PROFILE_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "list_profiles"}]

    # Run profile
    for p in PROFILE_PATTERNS:
        m = re.search(p, text_lower)
        if m:
            return [{"type": "run_profile", "name": m.group(1).strip()}]

    # System info
    for p in INFO_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "system_info"}]

    # Hostname get
    for p in HOSTNAME_GET_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "get_hostname"}]

    # Hostname set
    for p in HOSTNAME_SET_PATTERNS:
        m = re.search(p, text_lower)
        if m:
            return [{"type": "set_hostname", "name": m.group(1).strip()}]

    # List installed
    for p in LIST_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "list_installed"}]

    # System config
    for pattern, config_name in CONFIG_MAP.items():
        if re.search(pattern, text_lower):
            return [{"type": "system_config", "config": config_name}]

    # Upgrade all
    for p in UPGRADE_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "upgrade_all"}]

    # Export apps
    for p in EXPORT_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "export_apps"}]

    # Uninstall (check trước install vì "gỡ cài đặt" chứa "cài")
    for p in UNINSTALL_PATTERNS:
        m = re.search(p, text_lower)
        if m:
            packages = _split_packages(m.group(1))
            return [{"type": "uninstall", "package": pkg} for pkg in packages]

    # Install
    for p in INSTALL_PATTERNS:
        m = re.search(p, text_lower)
        if m:
            raw = m.group(1)
            # Nếu có đường dẫn file → install_local
            if _looks_like_path(raw):
                return [{"type": "install_local", "path": raw.strip()}]
            packages = _split_packages(raw)
            return [{"type": "install", "package": pkg} for pkg in packages]

    # Search
    for p in SEARCH_PATTERNS:
        m = re.search(p, text_lower)
        if m:
            return [{"type": "search", "query": m.group(1).strip()}]

    # Không match → cần LLM
    return None


def _split_packages(text: str) -> list[str]:
    """Tách nhiều package: 'chrome, 7zip và vlc' → ['chrome', '7zip', 'vlc']"""
    # Loại bỏ các từ thừa
    text = re.sub(r"\b(?:cho tôi|cho toi|giúp|giup|đi|di|nha|nhé|nhe|với|voi|luôn|luon|hộ|ho)\b", "", text)
    # Tách bằng dấu phẩy, "và", "and", khoảng trắng nhiều
    parts = re.split(r"[,;]\s*|\s+(?:và|va|and)\s+", text.strip())
    return [p.strip() for p in parts if p.strip()]


def _looks_like_path(text: str) -> bool:
    """Kiểm tra text có giống đường dẫn file không."""
    text = text.strip().strip('"').strip("'")
    if re.match(r"^[a-zA-Z]:\\", text):
        return True
    if text.startswith("\\\\"):
        return True
    if re.search(r"\.(exe|msi|msix|zip|rar)$", text.lower()):
        return True
    return False
