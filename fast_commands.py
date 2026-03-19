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
}

INFO_PATTERNS = [
    r"(?:thông tin|thong tin|info|system info|máy tính|may tinh|cấu hình máy|cau hinh may)",
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


def parse_fast(text: str) -> list[dict] | None:
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
