# -*- coding: utf-8 -*-
"""Fast command parser - xử lý lệnh ngay lập tức, không cần LLM.

Các lệnh rõ ràng (cài X, gỡ Y, bật dark mode...) được xử lý local
bằng regex matching. Chỉ gọi LLM khi câu lệnh mơ hồ/phức tạp.
"""
import re

# Patterns cho các lệnh phổ biến
INSTALL_PATTERNS = [
    r"(?:cài|cai|install|setup|tải|tai|cài đặt|cai dat)\s+(.+)",
]

UNINSTALL_PATTERNS = [
    r"(?:gỡ cài đặt|go cai dat|gỡ cài|go cai|gỡ bỏ|go bo|gỡ|go|gõ|uninstall|remove|xóa|xoa)\s+(.+)",
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
    r"(?:tắt|tat|disable).*(?:weather|thời tiết|thoi tiet|widget)": "disable_widgets",
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

UPGRADE_PATTERNS = [
    r"^(?:c[aậ]p nh[aậ]t|cap nhat|upgrade|update)\s*(?:t[aấ]t c[aả]|tat ca|all|h[eế]t|het)?$",
]

EXPORT_PATTERNS = [
    r"(?:xu[aấ]t|xuat|export)\s*(?:danh s[aá]ch|danh sach|app|list|ph[aầ]n m[eề]m|phan mem)?",
]

# CLI commands - detect khi input bắt đầu bằng tên lệnh trong whitelist
_CLI_COMMANDS = {
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
    # Other safe tools
    "sfc", "dism", "gpresult", "gpupdate",
    "bcdedit", "shutdown", "tzutil", "reg",
}


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

    # CLI command - detect khi input bắt đầu bằng lệnh whitelist
    first_word = text_lower.split()[0].replace(".exe", "") if text_lower.split() else ""
    if first_word in _CLI_COMMANDS:
        return [{"type": "cli", "command": text}]

    # Quick commands từ config.yaml (cài teamviewer qs, copy profile vpn, cài font...)
    if quick_commands:
        # Bỏ prefix "cài", "cài đặt", "setup", "copy" để match
        stripped = re.sub(
            r"^(?:cài đặt|cai dat|cài|cai|setup|copy)\s+", "", text_lower
        ).strip()
        for cmd_name, cmd_data in quick_commands.items():
            if text_lower == cmd_name or stripped == cmd_name:
                action = cmd_data.get("action", {})
                if action:
                    return [action]
            # Cũng match nếu user gõ "cài <tên>" hoặc "setup <tên>"
            if stripped == cmd_name.replace("cài ", "").replace("cài đặt ", ""):
                action = cmd_data.get("action", {})
                if action:
                    return [action]

    # Setup máy mới = chạy profile mặc định
    for p in SETUP_NEW_PATTERNS:
        if re.search(p, text_lower):
            return [{"type": "run_profile", "name": "mac_dinh"}]

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
    if re.search(r"\.(exe|msi|msix)$", text.lower()):
        return True
    return False
