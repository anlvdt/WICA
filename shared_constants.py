# -*- coding: utf-8 -*-
"""Shared constants — single source of truth for CLI whitelist, timeouts, etc.

Imported by tools.py và fast_commands.py để tránh duplicate.
"""

# --- Timeout constants (seconds) ---
WINGET_TIMEOUT = 600          # 10 phút cho install/uninstall đơn
WINGET_UPGRADE_TIMEOUT = 1200  # 20 phút cho upgrade --all
WINGET_LIST_TIMEOUT = 30       # 30s cho list
WINGET_CHECK_TIMEOUT = 10      # 10s cho kiểm tra package
CLI_TIMEOUT = 60               # 1 phút cho lệnh CLI
TIMEZONE_TIMEOUT = 30          # 30s cho timezone
SOURCE_RESET_TIMEOUT = 120     # 2 phút cho source reset
SOURCE_UPDATE_TIMEOUT = 180    # 3 phút cho source update
PROCESS_CLEANUP_TIMEOUT = 5    # 5s cho cleanup pipe

# --- CLI Whitelist — lệnh an toàn cho phép chạy trực tiếp ---
# KHÔNG có powershell, cmd, hoặc bất kỳ shell nào
# KHÔNG có diskpart, bcdedit — quá nguy hiểm với EDR enterprise
CLI_WHITELIST = {
    # Network diagnostics (read-only)
    "ipconfig", "ping", "tracert", "nslookup", "netstat", "arp",
    "route", "pathping", "nbtstat", "getmac",
    # System info (read-only)
    "hostname", "whoami", "systeminfo", "ver",
    "tasklist",
    # Disk info (read-only, restricted — xem _CHKDSK_BLOCKED_FLAGS)
    "chkdsk", "fsutil",
    # Network config (restricted — xem _NETSH_BLOCKED_SUBCOMMANDS)
    "netsh",
    # Other safe tools
    "sfc", "dism", "gpresult", "gpupdate",
    "tzutil", "w32tm",   # timezone tools — Microsoft-signed system binaries
    # Winget — Microsoft-signed, EDR trusted
    "winget",
    # Registry read-only (restricted — xem _REG_BLOCKED_SUBCOMMANDS)
    "reg",
    # Controlled commands (có arg-level restriction riêng)
    "taskkill", "sc", "shutdown", "icacls",
    "certutil", "cipher", "wmic",
}

# --- CLI Blacklist — lệnh CẤM TUYỆT ĐỐI ---
CLI_BLACKLIST = {
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "cmd", "cmd.exe",
    "wscript", "wscript.exe", "cscript", "cscript.exe",
    "mshta", "mshta.exe",
    "rundll32", "rundll32.exe",
    "regsvr32", "regsvr32.exe",
    "format",        # format disk — cực kỳ nguy hiểm
    "diskpart",      # partition editor — EDR enterprise flag
    "bcdedit",       # boot config — EDR enterprise flag
}

# --- Arg-level restrictions cho các lệnh nhạy cảm ---

# certutil: LOLBin nổi tiếng — chỉ cho phép các sub-command an toàn
# Chặn: -urlcache, -decode, -encode, -decodehex, -f (download/decode bypass)
_CERTUTIL_ALLOWED_SUBCMDS = {
    "-store", "-viewstore", "-dump", "-dumpfile",
    "-verify", "-verifyctl", "-verifycrl",
    "-hashfile",
    "-ping",
}

# netsh: chặn các sub-command có thể disable firewall / thêm rule / cấu hình proxy
_NETSH_BLOCKED_SUBCOMMANDS = {
    # Firewall manipulation
    "advfirewall",
    "firewall",
}

# netsh: các sub-command write bị chặn hoàn toàn (reset network stack)
# winsock reset / int ip reset có thể disrupt network — cần approval
_NETSH_BLOCKED_WRITE_SUBCMDS = {
    # Reset network stack — disruptive, cần approval
    ("winsock", "reset"),
    ("int", "reset"),
    ("interface", "reset"),
    # Proxy config
    ("winhttp", "set"),
    ("winhttp", "import"),
}

# sc: chặn stop/delete/config các security service
_SC_BLOCKED_SERVICES = {
    # CrowdStrike Falcon
    "csfalconservice", "csagent", "csdevicecontrol",
    # Windows Defender
    "windefend", "sense", "mssense", "wdnissvc", "wdfilter",
    # Carbon Black
    "cbdefense", "cbstream",
    # Symantec/SEP
    "sepmaster", "smc",
    # McAfee
    "mcshield", "mfefire",
    # Generic EDR/AV patterns — check substring
}
_SC_BLOCKED_ACTIONS = {"stop", "delete", "config", "failure", "sdset"}

# taskkill: chặn kill các security process
_TASKKILL_BLOCKED_PROCESSES = {
    # CrowdStrike
    "csfalconservice.exe", "csagent.exe", "csfalconcontainer.exe",
    # Windows Defender
    "msmpeng.exe", "nissrv.exe", "mssense.exe", "securityhealthservice.exe",
    # Carbon Black
    "cbdefense.exe", "cbstream.exe",
    # Sentinel One
    "sentinelone.exe", "sentinelagent.exe",
    # Generic
    "msseces.exe",
}

# shutdown: chỉ cho phép /a (abort) — chặn /s /r /f /h
_SHUTDOWN_ALLOWED_FLAGS = {"/a", "-a"}

# icacls: chặn modify ACL — chỉ cho phép read (không có /grant /deny /remove /reset /setowner)
_ICACLS_BLOCKED_FLAGS = {"/grant", "/deny", "/remove", "/reset", "/setowner", "/inheritance"}

# fsutil: chặn các sub-command write/behavior change
_FSUTIL_BLOCKED_SUBCMDS = {
    "behavior",   # fsutil behavior set — thay đổi filesystem behavior
    "dirty",      # fsutil dirty set — mark volume dirty
    "hardlink",   # fsutil hardlink create
    "objectid",   # fsutil objectid set
    "quota",      # fsutil quota modify/disable/enforce
    "repair",     # fsutil repair set
    "reparsepoint",  # fsutil reparsepoint set/delete
    "sparse",     # fsutil sparse setflag
    "usn",        # fsutil usn deletejournal
}

# dism: chặn các sub-command thay đổi system (enable/disable features, apply image)
_DISM_BLOCKED_FLAGS = {
    "/enable-feature", "/disable-feature",
    "/apply-image", "/apply-unattend",
    "/add-package", "/remove-package",
    "/add-driver", "/remove-driver",
    "/set-edition", "/apply-customdataimage",
    "/cleanup-image",  # có thể xóa recovery partition
}

# chkdsk: chặn /f /r /x — schedule disk repair và force reboot
# Chỉ cho phép read-only: chkdsk C: (không có flags)
_CHKDSK_BLOCKED_FLAGS = {"/f", "/r", "/x", "/b", "/scan", "/spotfix"}

# w32tm: chỉ cho phép /query và /resync — chặn /config (thay đổi NTP server)
_W32TM_BLOCKED_FLAGS = {"/config", "/register", "/unregister"}

# cipher: chặn /w (wipe free space) — gây chú ý EDR
_CIPHER_BLOCKED_FLAGS = {"/w"}
