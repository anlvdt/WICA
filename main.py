# -*- coding: utf-8 -*-
"""WICA - Windows Install CLI Agent.
Dark title bar via DWM API. Custom scrollbar. No emoji. EDR-safe.
"""
BUILD_VERSION = "2026.03.20.v10"
import sys, os, re, threading, time, ctypes, ctypes.wintypes, tkinter as tk
import queue
from tkinter import filedialog
if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))
from agent import AntiGravityAgent
from tools import _cancel_winget
from privilege import is_elevated, get_run_context, current_username
from shared_constants import no_accent as _no_accent

# --- Spinner frames cho loading animation ---
SPINNER = ["●  ○  ○", "○  ●  ○", "○  ○  ●", "○  ●  ○"]

C = {
    "bg": "#1e1e2e", "bg_alt": "#181825", "bg_input": "#313244",
    "bg_hover": "#45475a", "accent": "#89dceb", "accent_dim": "#74c7ec",
    "text": "#ffffff", "text_dim": "#cdd6f4", "text_user": "#89dceb",
    "ok": "#a6e3a1", "fail": "#f38ba8", "warn": "#fab387",
    "progress": "#cba6f7", "file": "#f9e2af", "border": "#313244",
    "btn": "#89b4fa", "btn_hover": "#74c7ec",
    "sb_thumb": "#9399b2", "sb_active": "#cdd6f4", "sb_bg": "#1e1e2e", "sb_track": "#45475a",
}
FM = ("Consolas", 12)
FI = ("Segoe UI", 12)
FT = ("Segoe UI Semibold", 14)
FS = ("Segoe UI", 10)
EMO = re.compile(
    r'[\U0001f300-\U0001f9ff\u2600-\u27bf\u2700-\u27bf'
    r'\u231a-\u23ff\u25aa-\u25ff\u2b05-\u2b55'
    r'\u200d\ufe0f\u2705\u274c\u2139\ufe0f\u23f0\u23f3]+'
)

def _dark_titlebar(root):
    """Dark title bar — hỗ trợ cả Win 10 (attr 19) và Win 11 (attr 20)."""
    try:
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        v = ctypes.c_int(1)
        # Win 11+ (build 22000+): DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        hr = ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(v), ctypes.sizeof(v))
        if hr != 0:
            # Win 10 older builds: undocumented attr 19
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(v), ctypes.sizeof(v))
    except Exception:
        pass  # Dark titlebar not critical

def _enable_ime_for_hwnd(hwnd: int):
    """Kích hoạt IME cho HWND — hoạt động cả khi Run as Admin.

    Khi elevated (Run as Admin), UIPI chặn IME messages từ UniKey (user-level).
    Fix: dùng ChangeWindowMessageFilterEx để allow WM_IME_* messages qua UIPI.
    Sau đó ImmAssociateContextEx để gắn IME context.

    EDR-safe: user32.dll + imm32.dll là Windows system DLL chuẩn.
    """
    try:
        # WM_IME_* message range cần allow qua UIPI khi elevated
        MSGFLT_ALLOW = 1
        WM_IME_STARTCOMPOSITION = 0x010D
        WM_IME_ENDCOMPOSITION   = 0x010E
        WM_IME_COMPOSITION      = 0x010F
        WM_IME_SETCONTEXT       = 0x0281
        WM_IME_NOTIFY           = 0x0282
        WM_IME_CONTROL          = 0x0283
        WM_IME_COMPOSITIONFULL  = 0x0284
        WM_IME_SELECT           = 0x0285
        WM_IME_CHAR             = 0x0286
        WM_IME_REQUEST          = 0x0288
        WM_IME_KEYDOWN          = 0x0290
        WM_IME_KEYUP            = 0x0291
        WM_CHAR                 = 0x0102
        WM_KEYDOWN              = 0x0100
        WM_KEYUP                = 0x0101
        WM_INPUTLANGCHANGEREQUEST = 0x0050
        WM_INPUTLANGCHANGE      = 0x0051

        cwmfe = ctypes.windll.user32.ChangeWindowMessageFilterEx
        cwmfe.restype = ctypes.wintypes.BOOL
        for msg in [
            WM_IME_STARTCOMPOSITION, WM_IME_ENDCOMPOSITION, WM_IME_COMPOSITION,
            WM_IME_SETCONTEXT, WM_IME_NOTIFY, WM_IME_CONTROL,
            WM_IME_COMPOSITIONFULL, WM_IME_SELECT, WM_IME_CHAR,
            WM_IME_REQUEST, WM_IME_KEYDOWN, WM_IME_KEYUP,
            WM_CHAR, WM_KEYDOWN, WM_KEYUP,
            WM_INPUTLANGCHANGEREQUEST, WM_INPUTLANGCHANGE,
        ]:
            cwmfe(hwnd, msg, MSGFLT_ALLOW, None)
    except Exception:
        pass  # UIPI filter fail — IME may not work elevated, non-critical
    try:
        IACE_DEFAULT = 0x0010
        ctypes.windll.imm32.ImmAssociateContextEx(hwnd, None, IACE_DEFAULT)
    except Exception:
        pass  # IME associate fail — fallback to default input, non-critical


def _find_unikey_exe() -> str | None:
    """Tìm UniKey executable từ các path thường gặp."""
    candidates = [
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "UniKey", "UniKeyNT.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "UniKey", "UniKeyNT.exe"),
        "C:\\Tools\\UniKey\\UniKeyNT.exe",
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "UniKey", "UniKeyNT.exe"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def _ensure_unikey_elevated():
    """Nếu app đang elevated và UniKey không chạy elevated, restart UniKey as admin.

    Khi Run as Admin/Different User, UIPI chặn messages từ UniKey (user-level).
    Fix: tìm UniKey process, kill, và re-launch với quyền admin.

    EDR-SAFE: 100% ctypes — KHÔNG subprocess, KHÔNG shell.
    Dùng CreateToolhelp32Snapshot (kernel32) để enum process,
    OpenProcess + TerminateProcess để kill, ShellExecuteW để launch.
    """
    if not is_elevated():
        return  # Không cần nếu app không elevated

    try:
        import time

        # --- Windows API constants ---
        TH32CS_SNAPPROCESS = 0x2
        PROCESS_TERMINATE = 0x0001
        PROCESS_QUERY_INFORMATION = 0x0400
        MAX_PATH = 260

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.wintypes.DWORD),
                ("cntUsage", ctypes.wintypes.DWORD),
                ("th32ProcessID", ctypes.wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.wintypes.DWORD),
                ("cntThreads", ctypes.wintypes.DWORD),
                ("th32ParentProcessID", ctypes.wintypes.DWORD),
                ("pcPriClassBase", ctypes.wintypes.LONG),
                ("dwFlags", ctypes.wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * MAX_PATH),
            ]

        kernel32 = ctypes.windll.kernel32

        # --- Enum processes via snapshot ---
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            return

        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        unikey_pids = []
        if kernel32.Process32FirstW(snapshot, ctypes.byref(pe)):
            while True:
                if pe.szExeFile.lower() == "uniKeynt.exe".lower():
                    unikey_pids.append(pe.th32ProcessID)
                if not kernel32.Process32NextW(snapshot, ctypes.byref(pe)):
                    break
        kernel32.CloseHandle(snapshot)

        unikey_path = _find_unikey_exe()

        if not unikey_pids:
            # UniKey không chạy — launch bình thường (không cần runas,
            # UIPI đã được fix bằng ChangeWindowMessageFilterEx)
            if unikey_path:
                try:
                    os.startfile(unikey_path)
                except Exception:
                    pass
            return

        if not unikey_path:
            return

        # --- Graceful shutdown UniKey via WM_CLOSE (EDR-safe) ---
        # Dùng WM_CLOSE thay vì TerminateProcess để tránh EDR alert.
        # TerminateProcess chỉ dùng làm fallback nếu WM_CLOSE không hiệu quả.
        # Verify path của process trước khi close để tránh đóng nhầm process giả mạo tên
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        WM_CLOSE = 0x0010
        user32 = ctypes.windll.user32

        verified_pids = set()
        for pid in unikey_pids:
            h_query = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if h_query:
                buf = ctypes.create_unicode_buffer(MAX_PATH)
                buf_size = ctypes.wintypes.DWORD(MAX_PATH)
                try:
                    if kernel32.QueryFullProcessImageNameW(h_query, 0, buf, ctypes.byref(buf_size)):
                        if buf.value.lower() == unikey_path.lower():
                            verified_pids.add(pid)
                except Exception:
                    pass
                kernel32.CloseHandle(h_query)

        if not verified_pids:
            return

        # Bước 1: Gửi WM_CLOSE cho tất cả window thuộc UniKey PIDs
        # EnumWindows callback tìm window → GetWindowThreadProcessId → PostMessage WM_CLOSE
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
        target_pids = verified_pids.copy()

        def _close_cb(hwnd, _lparam):
            try:
                pid = ctypes.wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value in target_pids:
                    user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass
            return True  # Tiếp tục enum

        user32.EnumWindows(WNDENUMPROC(_close_cb), 0)

        # Bước 2: Đợi tối đa 2s cho graceful shutdown
        for _ in range(4):
            time.sleep(0.5)
            # Kiểm tra xem UniKey còn chạy không
            still_running = False
            for pid in list(verified_pids):
                h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h:
                    exit_code = ctypes.wintypes.DWORD()
                    kernel32.GetExitCodeProcess(h, ctypes.byref(exit_code))
                    kernel32.CloseHandle(h)
                    if exit_code.value == 259:  # STILL_ACTIVE
                        still_running = True
                    else:
                        verified_pids.discard(pid)
                else:
                    verified_pids.discard(pid)
            if not still_running:
                break

        # Bước 3: Fallback — TerminateProcess cho process còn sót (hiếm khi cần)
        for pid in verified_pids:
            handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if handle:
                kernel32.TerminateProcess(handle, 0)
                kernel32.CloseHandle(handle)

        time.sleep(0.5)  # Đợi dừng hẳn

        # --- Re-launch bình thường (UIPI đã được fix bằng ChangeWindowMessageFilterEx) ---
        try:
            os.startfile(unikey_path)
        except Exception:
            pass
    except Exception:
        pass  # Non-critical — user có thể tự restart UniKey

class DarkScroll(tk.Frame):
    """Scrollable text with custom dark Canvas scrollbar."""
    SB_W = 10
    SB_W_HOV = 14
    SB_MIN_THUMB = 35

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["bg"], bd=0, highlightthickness=0)
        self._sb = tk.Canvas(self, width=self.SB_W, bg=C["bg"], bd=0,
                             highlightthickness=0, relief=tk.FLAT)
        self._sb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2), pady=4)
        self.text = tk.Text(self, **kw)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.text.configure(yscrollcommand=self._sync)
        self._top = 0.0; self._bot = 1.0
        self._drg = False; self._dy = 0; self._dt = 0.0; self._hov = False
        self._sb.bind("<Button-1>", self._press)
        self._sb.bind("<B1-Motion>", self._move)
        self._sb.bind("<ButtonRelease-1>", self._rel)
        self._sb.bind("<Configure>", lambda e: self._draw())
        self._sb.bind("<Enter>", lambda e: self._sh(True))
        self._sb.bind("<Leave>", lambda e: self._sh(False))
        self.text.bind("<MouseWheel>", self._wh)
        # Robust delayed redraws to handle layout timing
        for ms in (100, 300, 600, 1000):
            self.after(ms, self._draw)

    def _sync(self, t, b):
        self._top, self._bot = float(t), float(b)
        self._draw()

    def _sh(self, v):
        self._hov = v
        self._sb.configure(width=self.SB_W_HOV if v else self.SB_W)
        self._draw()

    def _draw(self):
        self._sb.delete("t")
        h = self._sb.winfo_height()
        w = self._sb.winfo_width()
        if h < 10 or w < 2:
            return
        r = min(w // 2, 4)
        # Always draw track
        self._sb.create_rectangle(1, 4 + r, w - 1, h - 4 - r, fill=C["sb_track"], outline=C["sb_track"], tags="t")
        self._sb.create_oval(1, 4, w - 1, 4 + 2 * r, fill=C["sb_track"], outline=C["sb_track"], tags="t")
        self._sb.create_oval(1, h - 4 - 2 * r, w - 1, h - 4, fill=C["sb_track"], outline=C["sb_track"], tags="t")
        # Only draw thumb when scrollable
        if self._bot - self._top >= 0.999:
            return
        y1 = max(0, int(self._top * h))
        y2 = min(h, int(self._bot * h))
        if y2 - y1 < self.SB_MIN_THUMB:
            y2 = y1 + self.SB_MIN_THUMB
        c = C["sb_active"] if (self._drg or self._hov) else C["sb_thumb"]
        self._sb.create_rectangle(1, y1 + r, w - 1, y2 - r, fill=c, outline=c, tags="t")
        self._sb.create_oval(1, y1, w - 1, y1 + 2 * r, fill=c, outline=c, tags="t")
        self._sb.create_oval(1, y2 - 2 * r, w - 1, y2, fill=c, outline=c, tags="t")

    def _press(self, e):
        self._drg = True; self._dy = e.y; self._dt = self._top; self._draw()

    def _move(self, e):
        if not self._drg: return
        h = self._sb.winfo_height()
        if h > 0:
            self.text.yview_moveto(max(0, min(1.0, self._dt + (e.y - self._dy) / h)))

    def _rel(self, e):
        self._drg = False; self._draw()

    def _wh(self, e):
        self.text.yview_scroll(int(-1 * (e.delta / 120)), "units")

    def configure(self, **kw): self.text.configure(**kw)
    def insert(self, *a, **kw): self.text.insert(*a, **kw)
    def see(self, *a): self.text.see(*a)
    def tag_configure(self, *a, **kw): self.text.tag_configure(*a, **kw)
    def clear(self):
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.configure(state=tk.DISABLED)


class SettingsDialog:
    """Settings dialog — polished dark theme with improved UX."""

    _W, _H = 540, 680  # Dialog size

    def __init__(self, parent, app):
        self.app = app
        self.win = tk.Toplevel(parent)
        self.win.title("Cài đặt — WICA")
        self.win.configure(bg=C["bg"])
        self.win.geometry(f"{self._W}x{self._H}")
        self.win.resizable(False, False)
        self.win.transient(parent)
        self.win.grab_set()
        # Center on parent
        self.win.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() - self._W) // 2
        py = parent.winfo_y() + (parent.winfo_height() - self._H) // 2
        self.win.geometry(f"+{max(0,px)}+{max(0,py)}")
        _dark_titlebar(self.win)

        # Load current config
        import yaml
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except Exception:
            self.config = {}

        # === Bottom buttons (pack first so they stay visible) ===
        tk.Frame(self.win, bg=C["border"], height=1).pack(fill=tk.X, side=tk.BOTTOM)
        bottom = tk.Frame(self.win, bg=C["bg_alt"], pady=10, padx=24)
        bottom.pack(fill=tk.X, side=tk.BOTTOM)
        self._status_label = tk.Label(bottom, text="", font=FS, fg=C["ok"], bg=C["bg_alt"])
        self._status_label.pack(side=tk.LEFT)
        self._action_btn(bottom, "Lưu thay đổi", self._save, primary=True).pack(side=tk.RIGHT, padx=(8, 0))
        self._action_btn(bottom, "Đóng", self.win.destroy).pack(side=tk.RIGHT)

        # === Header ===
        hdr = tk.Frame(self.win, bg=C["bg"], padx=28, pady=14)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Cài đặt", font=("Segoe UI Semibold", 18),
                 fg=C["accent"], bg=C["bg"]).pack(side=tk.LEFT)
        tk.Label(hdr, text="WICA", font=("Segoe UI", 10),
                 fg=C["text_dim"], bg=C["bg"]).pack(side=tk.LEFT, padx=(8, 0), pady=(6, 0))

        # Container
        container = tk.Frame(self.win, bg=C["bg"], padx=28)
        container.pack(fill=tk.BOTH, expand=True)

        # === LLM Section ===
        self._section(container, "LLM Provider", "Cấu hình kết nối AI — cần API key để sử dụng")
        providers = self.config.get("llm_providers", [])
        p0 = providers[0] if providers else {}

        self.var_provider = tk.StringVar(value=p0.get("name", "groq"))
        self._field(container, "Provider", self.var_provider, placeholder="groq")

        self.var_apikey = tk.StringVar(value=p0.get("api_key", ""))
        self._field(container, "API Key", self.var_apikey, show="•", placeholder="gsk-xxx... hoặc env:GROQ_API_KEY")

        self.var_baseurl = tk.StringVar(value=p0.get("base_url", ""))
        self._field(container, "Base URL", self.var_baseurl, placeholder="https://api.groq.com/openai/v1")

        self.var_model = tk.StringVar(value=p0.get("model", ""))
        self._field(container, "Model", self.var_model, placeholder="llama-3.3-70b-versatile")

        # LLM status + reconnect button
        llm_row = tk.Frame(container, bg=C["bg"])
        llm_row.pack(fill=tk.X, pady=(6, 0))
        if app.agent.client:
            status_text = f"● Đã kết nối: {app.agent.provider_name} ({app.agent.model})"
            status_color = C["ok"]
        else:
            status_text = "○ Chưa kết nối"
            status_color = C["fail"]
        self._llm_status = tk.Label(llm_row, text=status_text, font=FS,
                                    fg=status_color, bg=C["bg"], anchor="w")
        self._llm_status.pack(side=tk.LEFT)
        self._action_btn(llm_row, "Kết nối lại", self._reconnect_llm).pack(side=tk.RIGHT)

        # === Giao diện ===
        self._section(container, "Giao diện", "Tùy chỉnh hiển thị")

        # Font size — custom +/- control
        row_font = tk.Frame(container, bg=C["bg"])
        row_font.pack(fill=tk.X, pady=5)
        tk.Label(row_font, text="Cỡ chữ", font=FS, fg=C["text_dim"],
                 bg=C["bg"], width=10, anchor="w").pack(side=tk.LEFT)

        fc = tk.Frame(row_font, bg=C["bg"])
        fc.pack(side=tk.LEFT)
        self.var_fontsize = tk.IntVar(value=app._font_size)
        self._stepper_btn(fc, "−", lambda: self._adj_font(-1)).pack(side=tk.LEFT)
        self._font_label = tk.Label(fc, text=str(app._font_size), width=3,
                                     font=("Segoe UI Semibold", 11), fg=C["text"],
                                     bg=C["bg_input"], anchor="center", pady=2)
        self._font_label.pack(side=tk.LEFT, padx=2)
        self._stepper_btn(fc, "+", lambda: self._adj_font(1)).pack(side=tk.LEFT)
        tk.Label(row_font, text="pt   (Ctrl +/−)", font=FS, fg=C["text_dim"],
                 bg=C["bg"]).pack(side=tk.LEFT, padx=(4, 0))

        # Sound — custom toggle
        row_sound = tk.Frame(container, bg=C["bg"])
        row_sound.pack(fill=tk.X, pady=5)
        tk.Label(row_sound, text="Âm thanh", font=FS, fg=C["text_dim"],
                 bg=C["bg"], width=10, anchor="w").pack(side=tk.LEFT)
        self.var_sound = tk.BooleanVar(value=getattr(app, '_notify_sound', True))
        self._toggle = tk.Canvas(row_sound, width=44, height=22, bg=C["bg"],
                                  highlightthickness=0, cursor="hand2")
        self._toggle.pack(side=tk.LEFT)
        self._toggle.bind("<Button-1>", self._click_toggle)
        self._draw_toggle()
        tk.Label(row_sound, text="Phát âm khi hoàn thành", font=FS,
                 fg=C["text_dim"], bg=C["bg"]).pack(side=tk.LEFT, padx=(8, 0))

        # === Nâng cao ===
        self._section(container, "Nâng cao", "Chỉnh sửa file cấu hình gốc")

        btn_row = tk.Frame(container, bg=C["bg"])
        btn_row.pack(fill=tk.X, pady=6)
        self._action_btn(btn_row, "Mở config.yaml", self._open_config).pack(side=tk.LEFT, padx=(0, 8))

    # --- UI helpers ---

    def _section(self, parent, title, subtitle=None):
        f = tk.Frame(parent, bg=C["bg"])
        f.pack(fill=tk.X, pady=(16, 0))
        tk.Frame(f, bg="#45475a", height=1).pack(fill=tk.X)
        row = tk.Frame(f, bg=C["bg"])
        row.pack(fill=tk.X, pady=(8, 4))
        tk.Label(row, text=title, font=("Segoe UI Semibold", 11),
                 fg=C["accent_dim"], bg=C["bg"], anchor="w").pack(side=tk.LEFT)
        if subtitle:
            tk.Label(row, text=f"  —  {subtitle}", font=("Segoe UI", 9),
                     fg="#6c7086", bg=C["bg"], anchor="w").pack(side=tk.LEFT)

    def _field(self, parent, label, var, show=None, placeholder=None):
        row = tk.Frame(parent, bg=C["bg"])
        row.pack(fill=tk.X, pady=3)
        tk.Label(row, text=label, font=FS, fg=C["text_dim"],
                 bg=C["bg"], width=10, anchor="w").pack(side=tk.LEFT)
        # Bordered entry wrapper
        wrapper = tk.Frame(row, bg=C["border"], bd=1, relief=tk.FLAT)
        wrapper.pack(side=tk.LEFT, fill=tk.X, expand=True)
        kw = dict(textvariable=var, font=FS, bg=C["bg_input"], fg=C["text"],
                  insertbackground=C["accent"], relief=tk.FLAT, bd=0)
        if show:
            kw["show"] = show
        entry = tk.Entry(wrapper, **kw)
        entry.pack(fill=tk.X, padx=4, pady=3)
        entry.bind("<FocusIn>", lambda e: wrapper.configure(bg=C["accent"]))
        entry.bind("<FocusOut>", lambda e: wrapper.configure(bg=C["border"]))
        # Placeholder text
        if placeholder and not var.get():
            entry.configure(fg="#585b70")
            entry.insert(0, placeholder)
            def _on_focus_in(e, ent=entry, ph=placeholder, v=var):
                if ent.get() == ph and not v.get():
                    ent.delete(0, tk.END)
                    ent.configure(fg=C["text"])
                wrapper.configure(bg=C["accent"])
            def _on_focus_out(e, ent=entry, ph=placeholder, v=var):
                if not ent.get().strip():
                    v.set("")
                    ent.insert(0, ph)
                    ent.configure(fg="#585b70")
                wrapper.configure(bg=C["border"])
            entry.bind("<FocusIn>", _on_focus_in)
            entry.bind("<FocusOut>", _on_focus_out)
        return entry

    def _stepper_btn(self, parent, text, cmd):
        b = tk.Label(parent, text=text, font=("Segoe UI Semibold", 12),
                     bg=C["bg_input"], fg=C["text"], width=2, anchor="center",
                     pady=1, cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.configure(bg=C["bg_hover"]))
        b.bind("<Leave>", lambda e: b.configure(bg=C["bg_input"]))
        return b

    def _adj_font(self, delta):
        val = max(8, min(20, self.var_fontsize.get() + delta))
        self.var_fontsize.set(val)
        self._font_label.configure(text=str(val))

    def _draw_toggle(self):
        self._toggle.delete("all")
        on = self.var_sound.get()
        # Track with rounded ends
        track_color = C["accent"] if on else C["bg_input"]
        self._toggle.create_rectangle(2, 2, 42, 20, fill=track_color,
                                       outline=track_color, width=0)
        # Thumb circle
        cx = 32 if on else 12
        self._toggle.create_oval(cx - 8, 3, cx + 8, 19, fill="#ffffff", outline="#ffffff")

    def _click_toggle(self, e=None):
        self.var_sound.set(not self.var_sound.get())
        self._draw_toggle()

    def _action_btn(self, parent, text, cmd, primary=False):
        bg = C["btn"] if primary else C["bg_input"]
        fg = "#1e1e2e" if primary else C["text"]
        hb = C["btn_hover"] if primary else C["bg_hover"]
        b = tk.Label(parent, text=text, font=("Segoe UI Semibold", 10),
                     bg=bg, fg=fg, padx=16, pady=5, cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.configure(bg=hb))
        b.bind("<Leave>", lambda e: b.configure(bg=bg))
        return b

    # --- Actions ---

    def _open_config(self):
        try:
            os.startfile(self.config_path)
            self._status_label.configure(text="Đã mở config.yaml", fg=C["ok"])
        except Exception as e:
            self._status_label.configure(text=f"Lỗi: {e}", fg=C["fail"])

    def _reconnect_llm(self):
        self._llm_status.configure(text="◌ Đang kết nối...", fg=C["progress"])
        # Chạy trong thread để không block UI
        def _do_reconnect():
            self.app.agent._connect_llm()
            # Update UI từ main thread
            self.win.after(0, self._update_llm_status)
        threading.Thread(target=_do_reconnect, daemon=True).start()

    def _update_llm_status(self):
        """Cập nhật LLM status label sau khi reconnect xong."""
        if self.app.agent.client:
            self._llm_status.configure(
                text=f"● Đã kết nối: {self.app.agent.provider_name} ({self.app.agent.model})",
                fg=C["ok"])
            self._status_label.configure(
                text=f"Đã kết nối: {self.app.agent.provider_name}", fg=C["ok"])
            # Cập nhật status bar chính
            self.app._llm_status_label.configure(
                text=f"LLM: {self.app.agent.provider_name}", fg=C["ok"])
        else:
            self._llm_status.configure(text="○ Không kết nối được", fg=C["fail"])
            self._status_label.configure(text="Không kết nối được LLM", fg=C["fail"])
            self.app._llm_status_label.configure(text="LLM: chưa kết nối", fg=C["warn"])

    def _save(self):
        import yaml
        # Update first provider in config
        providers = self.config.get("llm_providers", [])
        if providers:
            providers[0]["name"] = self.var_provider.get().strip()
            providers[0]["api_key"] = self.var_apikey.get().strip()
            providers[0]["base_url"] = self.var_baseurl.get().strip()
            providers[0]["model"] = self.var_model.get().strip()
        else:
            self.config["llm_providers"] = [{
                "name": self.var_provider.get().strip(),
                "base_url": self.var_baseurl.get().strip(),
                "api_key": self.var_apikey.get().strip(),
                "model": self.var_model.get().strip(),
            }]

        # Save config.yaml
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                yaml.dump(self.config, f, allow_unicode=True, default_flow_style=False,
                          sort_keys=False)
            self._status_label.configure(text="Đã lưu config.yaml ✓", fg=C["ok"])
        except Exception as e:
            self._status_label.configure(text=f"Lỗi lưu: {e}", fg=C["fail"])
            return

        # Apply app preferences
        new_size = self.var_fontsize.get()
        self.app._font_size = new_size
        self.app.chat.text.configure(font=("Consolas", new_size))
        self.app.ent.configure(font=("Segoe UI", new_size))

        self.app._notify_sound = self.var_sound.get()


class AutoComplete:
    """Autocomplete popup cho input widget — gợi ý lệnh từ config."""

    MAX_SHOW = 7  # Số gợi ý hiện tối đa

    def __init__(self, text_widget, root):
        self.widget = text_widget
        self.root = root
        self.popup = None
        self.listbox = None
        self._suggestions: list[str] = []
        self._all_items: list[str] = []
        self._load_suggestions()
        # Bind events
        self.widget.bind("<KeyRelease>", self._on_key, add="+")
        self.widget.bind("<Tab>", self._on_tab)
        self.widget.bind("<Escape>", self._on_escape, add="+")
        self.widget.bind("<FocusOut>", self._on_focus_out, add="+")

    def _load_suggestions(self):
        """Load gợi ý từ config.yaml."""
        import yaml
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}

        items = set()

        # Local-only packages — không gợi ý "cài/gỡ" qua alias
        # (dùng quick commands thay thế, vd: "htkk", "cài htkk")
        _local_only_values = {
            "htkk", "htkk_dll", "itaxviewer", "itaxviewer_dll",
            "ct_signinghub", "signinghub",
        }

        # Aliases → "cài <alias>" / "gỡ <alias>" (chỉ cho winget packages)
        for alias, pkg_id in cfg.get("aliases", {}).items():
            if pkg_id.lower() in _local_only_values:
                continue  # Skip — dùng quick commands cho phần mềm local
            items.add(f"cài {alias}")
            items.add(f"gỡ {alias}")

        # Quick commands
        for qc in cfg.get("quick_commands", {}).keys():
            items.add(qc)

        # Profile names → "cài máy mới" etc.
        for pkey, pdata in cfg.get("profiles", {}).items():
            name = pdata.get("name", pkey) if isinstance(pdata, dict) else pkey
            items.add(name.lower())

        # Common standalone commands
        items.update([
            "thông tin máy", "tên máy", "danh sách đã cài",
            "dark mode", "light mode", "hiện đuôi file", "hiện file ẩn",
            "taskbar trái", "taskbar giữa", "gỡ bloatware",
            "dọn start menu", "xóa icon rác", "dọn icon quảng cáo",
            "tắt widget", "tắt weather", "tắt task view",
            "tắt thông báo", "tắt tips", "tắt bing", "tắt copilot",
            "tắt uac", "bật uac", "tắt telemetry",
            "menu cổ điển", "search icon",
        ])

        self._all_items = sorted(items)

    def _get_text(self) -> str:
        return self.widget.get("1.0", "end-1c").strip()

    def _on_key(self, e):
        # Bỏ qua navigation keys
        if e.keysym in ("Up", "Down", "Tab", "Return", "Escape",
                        "Shift_L", "Shift_R", "Control_L", "Control_R",
                        "Alt_L", "Alt_R", "BackSpace"):
            if e.keysym == "BackSpace":
                self._update()
            return
        self._update()

    def _update(self):
        text = self._get_text().lower()
        if len(text) < 1:
            self._hide()
            return

        # Normalize input không dấu để so sánh với gợi ý có dấu
        text_no_accent = _no_accent(text)

        # Filter: match cả có dấu lẫn không dấu
        def _match(s: str) -> bool:
            s_lower = s.lower()
            s_no_accent = _no_accent(s)
            return text in s_lower or text_no_accent in s_no_accent

        def _starts(s: str) -> bool:
            return s.lower().startswith(text) or _no_accent(s).startswith(text_no_accent)

        matches = [s for s in self._all_items if _match(s)]
        # Ưu tiên startswith
        starts = [s for s in matches if _starts(s)]
        contains = [s for s in matches if not _starts(s)]
        self._suggestions = (starts + contains)[:self.MAX_SHOW]

        if not self._suggestions:
            self._hide()
            return

        self._show()

    def _show(self):
        if not self._suggestions:
            self._hide()
            return

        if self.popup and self.popup.winfo_exists():
            # Update existing
            self.listbox.delete(0, tk.END)
            for s in self._suggestions:
                self.listbox.insert(tk.END, s)
            self.listbox.selection_set(0)
            self._resize()
            return

        self.popup = tk.Toplevel(self.root)
        self.popup.wm_overrideredirect(True)
        self.popup.configure(bg=C["border"])

        self.listbox = tk.Listbox(
            self.popup,
            bg=C["bg_input"], fg=C["text"],
            selectbackground=C["accent_dim"],
            selectforeground="#1e1e2e",
            font=("Segoe UI", 11),
            relief=tk.FLAT, bd=0,
            highlightthickness=0,
            activestyle="none",
            exportselection=False,
        )
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        for s in self._suggestions:
            self.listbox.insert(tk.END, s)
        self.listbox.selection_set(0)

        self.listbox.bind("<ButtonRelease-1>", self._on_click)
        self.listbox.bind("<Double-Button-1>", self._on_click)

        self._resize()

    def _resize(self):
        if not self.popup or not self.popup.winfo_exists():
            return
        self.widget.update_idletasks()
        # Position: trên ô input
        x = self.widget.winfo_rootx()
        w = self.widget.winfo_width()
        item_h = 24
        h = min(len(self._suggestions), self.MAX_SHOW) * item_h + 4
        y = self.widget.winfo_rooty() - h - 2
        if y < 0:
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 2
        self.popup.geometry(f"{w}x{h}+{x}+{y}")
        self.listbox.configure(height=min(len(self._suggestions), self.MAX_SHOW))

    def _hide(self):
        if self.popup and self.popup.winfo_exists():
            self.popup.destroy()
        self.popup = None
        self.listbox = None

    def _accept(self):
        if not self.listbox or not self.popup or not self.popup.winfo_exists():
            return False
        sel = self.listbox.curselection()
        if not sel:
            return False
        text = self.listbox.get(sel[0])
        self.widget.delete("1.0", tk.END)
        self.widget.insert("1.0", text)
        self.widget.mark_set(tk.INSERT, tk.END)
        self._hide()
        return True

    def _on_tab(self, e):
        if self._accept():
            return "break"

    def _on_escape(self, e):
        if self.popup and self.popup.winfo_exists():
            self._hide()
            return "break"

    def _on_click(self, e):
        self._accept()

    def _on_focus_out(self, e):
        """Dismiss autocomplete khi input mất focus."""
        # Delay nhỏ để cho phép click vào listbox trước khi hide
        self.root.after(150, self._hide_if_no_focus)

    def _hide_if_no_focus(self):
        """Hide popup nếu focus không nằm trong autocomplete."""
        try:
            focused = self.root.focus_get()
            if focused != self.widget and focused != self.listbox:
                self._hide()
        except Exception:
            self._hide()

    def navigate(self, direction):
        """Up/Down navigation trong popup. Returns True nếu đã xử lý."""
        if not self.listbox or not self.popup or not self.popup.winfo_exists():
            return False
        sel = self.listbox.curselection()
        if not sel:
            idx = 0
        else:
            idx = sel[0] + direction
        idx = max(0, min(idx, self.listbox.size() - 1))
        self.listbox.selection_clear(0, tk.END)
        self.listbox.selection_set(idx)
        self.listbox.see(idx)
        return True

    @property
    def is_visible(self):
        return self.popup is not None and self.popup.winfo_exists()


class ChatApp:
    PH_TEXT = "Nhập lệnh... (vd: cài chrome, gỡ teamviewer)"

    def __init__(self):
        self.agent = AntiGravityAgent()
        self._ph = False
        self._cancelled = False
        self._cmd_history = []      # Lịch sử lệnh
        self._cmd_history_idx = -1  # Vị trí hiện tại trong lịch sử
        self._spinner_id = None     # ID của spinner animation
        self._spinner_idx = 0
        self._font_size = 12        # Font zoom
        self._auto_scroll = True    # Auto-scroll tracking
        self._notify_sound = True   # Phát âm khi hoàn thành
        self._out_queue = queue.Queue()
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        self.root = tk.Tk()
        self.root.withdraw()  # Hide during setup to prevent white flash
        self.root.title("WICA - Windows Install CLI Agent")
        
        # Load app icon if available
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        icon_path = os.path.join(base_dir, "app_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass
                
        self.root.configure(bg=C["bg"])
        self._center_window(1000, 720)
        self.root.minsize(560, 420)
        self.root.update_idletasks()
        _dark_titlebar(self.root)
        self._build_status_bar()
        self._build_input()
        self._build_chips()
        self._autocomplete = AutoComplete(self.ent, self.root)
        self._build_chat()
        self._welcome()
        # Đăng ký callback để hiện SoftVN sync progress real-time lên chat
        def _softvn_ui_cb(msg: str):
            self._out_queue.put(("softvn", msg))
        self.agent._softvn_copy_cb = _softvn_ui_cb
        self._softvn_header_shown = False
        self._chat_backup = None  # Buffer cho undo clear
        self.root.deiconify()  # Show after everything is ready
        self.root.state("zoomed")  # Maximize by default
        self.root.bind("<Control-l>", lambda e: self._clear())
        self.root.bind("<Control-z>", self._undo_clear)
        self.root.bind("<Escape>", lambda e: self._cancel() if not self._cancelled and self._is_busy() else None)
        # Font zoom: Ctrl+Plus / Ctrl+Minus
        self.root.bind("<Control-equal>", lambda e: self._zoom_font(1))
        self.root.bind("<Control-plus>", lambda e: self._zoom_font(1))
        self.root.bind("<Control-minus>", lambda e: self._zoom_font(-1))
        self.root.bind("<Control-0>", lambda e: self._zoom_font(0))
        # Output queue polling — drain mỗi 50ms để tránh batch delay
        self._poll_output()
        # Kích hoạt IME + UniKey elevated sau khi window hiển thị
        self.root.after(300, self._init_ime)
        # Auto-elevate UniKey nếu cần (chạy trong thread để không block UI)
        if is_elevated():
            threading.Thread(target=_ensure_unikey_elevated, daemon=True).start()

    def _build_status_bar(self):
        """Status bar phía dưới cùng — hiện quyền, LLM, version."""
        self._status_frame = tk.Frame(self.root, bg=C["bg_alt"], height=28)
        self._status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self._status_frame.pack_propagate(False)
        # Privilege indicator
        ctx = get_run_context()
        user = current_username()
        if ctx == "admin":
            priv_text = f"Admin: {user} (all users)"
            priv_color = C["ok"]
        elif ctx == "different_user":
            priv_text = f"Run-as: {user} (all users)"
            priv_color = C["warn"]
        else:
            priv_text = f"User: {user}"
            priv_color = C["text_dim"]
        tk.Label(self._status_frame, text=priv_text, fg=priv_color,
                 bg=C["bg_alt"], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(10, 8), pady=2)
        # LLM status
        if self.agent.client:
            llm_text = f"LLM: {self.agent.provider_name}"
            llm_color = C["ok"]
        else:
            llm_text = "LLM: chưa kết nối"
            llm_color = C["warn"]
        self._llm_status_label = tk.Label(self._status_frame, text=llm_text, fg=llm_color,
                 bg=C["bg_alt"], font=("Segoe UI", 9))
        self._llm_status_label.pack(side=tk.LEFT, padx=8, pady=2)
        # Version
        tk.Label(self._status_frame, text=f"v{BUILD_VERSION}", fg=C["text_dim"],
                 bg=C["bg_alt"], font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=(8, 10), pady=2)
        # Settings button
        settings_btn = tk.Label(self._status_frame, text="⚙️ Cài đặt", fg=C["accent_dim"],
                                bg=C["bg_alt"], font=("Segoe UI", 9), cursor="hand2")
        settings_btn.pack(side=tk.RIGHT, padx=8, pady=2)
        settings_btn.bind("<Button-1>", lambda e: self._open_settings())
        settings_btn.bind("<Enter>", lambda e: settings_btn.configure(fg=C["accent"]))
        settings_btn.bind("<Leave>", lambda e: settings_btn.configure(fg=C["accent_dim"]))

    def _start_spinner(self, text="Đang xử lý..."):
        """Bắt đầu spinner — in vào chat area và bắt đầu tick timer."""
        self._spinner_idx = 0
        self._spinner_text = text
        self._spinner_start = time.time()
        # In dòng spinner đầu tiên vào chat
        self._spinner_line_idx = None  # sẽ dùng tag để update
        self._tick_spinner()

    def _tick_spinner(self):
        frame = SPINNER[self._spinner_idx % len(SPINNER)]
        elapsed = time.time() - self._spinner_start
        if elapsed < 60:
            elapsed_str = f"{elapsed:.0f}s"
        else:
            m = int(elapsed // 60)
            s = int(elapsed % 60)
            elapsed_str = f"{m}m{s:02d}s"
        spinner_text = f"{frame}  {self._spinner_text}  [{elapsed_str}]"
        # Cập nhật dòng spinner trong chat (xóa dòng cũ, ghi dòng mới)
        self.chat.text.configure(state=tk.NORMAL)
        try:
            # Xóa nội dung tag "spinner_line" nếu có
            ranges = self.chat.text.tag_ranges("spinner_line")
            if ranges:
                self.chat.text.delete(ranges[0], ranges[1])
            # Chèn dòng spinner mới tại vị trí cuối
            self.chat.text.insert(tk.END, "  " + spinner_text + "\n", ("progress", "spinner_line"))
        except Exception:
            pass
        self.chat.text.configure(state=tk.DISABLED)
        if self._auto_scroll:
            self.chat.see(tk.END)
        self._spinner_idx += 1
        self._spinner_id = self.root.after(350, self._tick_spinner)

    def _stop_spinner(self):
        if self._spinner_id:
            self.root.after_cancel(self._spinner_id)
            self._spinner_id = None
        # Xóa dòng spinner khỏi chat
        self.chat.text.configure(state=tk.NORMAL)
        try:
            ranges = self.chat.text.tag_ranges("spinner_line")
            if ranges:
                self.chat.text.delete(ranges[0], ranges[1])
        except Exception:
            pass
        self.chat.text.configure(state=tk.DISABLED)

    def _set_status(self, text: str):
        """Cập nhật step text trên spinner mà không reset timer."""
        self._spinner_text = text

    def _poll_output(self):
        """Drain output queue — tối đa 8 items/cycle (50ms) để UI responsive hơn."""
        for _ in range(8):
            try:
                t, tag = self._out_queue.get_nowait()
                if t == "softvn":
                    self._handle_softvn_msg(tag)
                elif tag == "_ui_cmd":
                    if t == "clear":
                        self._clear()
                    elif t == "help":
                        self._clear()
                elif tag == "set_status":
                    self._set_status(t)
                elif tag == "_profile_retry":
                    self._show_retry_button(t["failed"], t["profile"])
                else:
                    self._out(t, tag)
            except queue.Empty:
                break
        self.root.after(50, self._poll_output)

    def _show_retry_button(self, failed_actions: list, profile_name: str):
        """Hiện nút Retry inline trong chat cho các task thất bại."""
        # Frame chứa danh sách lỗi + nút retry
        frame = tk.Frame(self.chat.text, bg=C["bg"], pady=4)

        # Danh sách task lỗi
        for desc, _ in failed_actions:
            lbl = tk.Label(frame, text=f"  ✗ {desc}",
                           bg=C["bg"], fg=C.get("fail", "#ff6b6b"),
                           font=("Consolas", 11), anchor="w", justify="left")
            lbl.pack(fill="x", padx=8)

        # Nút retry
        btn = tk.Button(
            frame,
            text=f"  ↺  Thử lại {len(failed_actions)} bước lỗi  ",
            bg=C.get("warn", "#fab387"), fg="#1e1e2e",
            font=("Segoe UI", 11, "bold"),
            relief="flat", cursor="hand2", padx=12, pady=6,
            command=lambda: self._do_retry(failed_actions, profile_name, frame),
        )
        btn.pack(anchor="w", padx=8, pady=(4, 2))

        self.chat.text.configure(state=tk.NORMAL)
        self.chat.text.insert(tk.END, "\n")
        self.chat.text.window_create(tk.END, window=frame)
        self.chat.text.insert(tk.END, "\n")
        self.chat.text.configure(state=tk.DISABLED)
        if self._auto_scroll:
            self.chat.see(tk.END)

    def _do_retry(self, failed_actions: list, profile_name: str, frame: tk.Frame):
        """Chạy retry trong background thread, xóa nút retry trước khi chạy."""
        # Xóa frame retry khỏi chat
        try:
            self.chat.text.configure(state=tk.NORMAL)
            idx = self.chat.text.index(frame)
            self.chat.text.delete(f"{idx} - 1c", f"{idx} + 1c")
            frame.destroy()
            self.chat.text.configure(state=tk.DISABLED)
        except Exception:
            pass
        self._w(f"  > retry {profile_name}\n", "user")
        self._busy(True)
        threading.Thread(
            target=self._exec_retry,
            args=(failed_actions, profile_name),
            daemon=True,
        ).start()

    def _exec_retry(self, failed_actions: list, profile_name: str):
        self.root.after(0, self._start_spinner, "Đang retry...")
        try:
            self.agent._retry_failed_actions(
                failed_actions, profile_name, self._out_s, self._schedule_raise
            )
        except Exception as e:
            self._out_s(f"[error] {e}", "fail")
        self.root.after(0, self._stop_spinner)
        self.root.after(0, self._w, "  " + "-" * 52 + "\n", "divider")
        self.root.after(0, self._busy, False)
        self.root.after(100, self._raise_window)
        if self._notify_sound:
            try:
                ctypes.windll.user32.MessageBeep(0x00000040)
            except Exception:
                pass

    def _init_ime(self):
        """Gọi ImmAssociateContextEx sau khi Tk window đã render xong.

        Phải delay vì winfo_id() chỉ hợp lệ sau khi window visible.
        Gọi cho cả Entry widget và root window.
        """
        try:
            hwnd = self.ent.winfo_id()
            _enable_ime_for_hwnd(hwnd)
        except Exception:
            pass
        try:
            root_hwnd = self.root.winfo_id()
            _enable_ime_for_hwnd(root_hwnd)
        except Exception:
            pass

    def _zoom_font(self, delta):
        """Ctrl+/- zoom font. Ctrl+0 reset."""
        if delta == 0:
            self._font_size = 12
        else:
            self._font_size = max(8, min(20, self._font_size + delta))
        new_fm = ("Consolas", self._font_size)
        new_fi = ("Segoe UI", self._font_size)
        self.chat.text.configure(font=new_fm)
        self.ent.configure(font=new_fi)

    def _is_busy(self):
        return str(self.ent.cget("state")) == "disabled"

    def _center_window(self, w, h):
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _build_chips(self):
        """Fast action chips — nút bấm nhanh cho thao tác thường dùng."""
        # Chip definitions: (label, command_text)
        # command_text sẽ được gửi vào chat như thể user gõ
        chips = [
            ("Cài máy mới", "cài máy mới"),
            ("PM Thuế", "cài phần mềm thuế"),
            ("Gỡ PM Thuế", "gỡ phần mềm thuế"),
            ("Chrome", "cài chrome"),
            ("UltraViewer", "cài ultraviewer"),
            ("UniKey", "unikey"),
            ("TeamViewer QS", "teamviewer qs"),
            ("Gỡ Bloatware", "gỡ bloatware"),
            ("Dark Mode", "dark mode"),
            ("Thông tin máy", "thông tin máy"),
        ]
        # Separator
        tk.Frame(self.root, bg="#313244", height=1).pack(fill=tk.X, side=tk.BOTTOM)
        self._chips_frame = tk.Frame(self.root, bg=C["bg_alt"], padx=10, pady=6)
        self._chips_frame.pack(fill=tk.X, side=tk.BOTTOM)
        for label, cmd in chips:
            chip = tk.Label(
                self._chips_frame, text=label,
                font=("Segoe UI", 9), fg=C["text_dim"], bg="#313244",
                padx=10, pady=3, cursor="hand2",
            )
            chip.pack(side=tk.LEFT, padx=3)
            chip.bind("<Button-1>", lambda e, c=cmd: self._chip_exec(c))
            chip.bind("<Enter>", lambda e, w=chip: w.configure(bg=C["accent_dim"], fg="#1e1e2e"))
            chip.bind("<Leave>", lambda e, w=chip: w.configure(bg="#313244", fg=C["text_dim"]))

    def _chip_exec(self, command: str):
        """Thực thi command từ chip click — giống user gõ vào chat."""
        if self._is_busy():
            return
        ts = time.strftime("%H:%M")
        self._w(f"  {ts}  > ", "ts")
        self._w(command + "\n", "user")
        self._busy(True)
        threading.Thread(target=self._exec, args=(command,), daemon=True).start()

    def _build_chat(self):
        # Chat container (for floating button overlay)
        self._chat_container = tk.Frame(self.root, bg=C["bg"])
        self._chat_container.pack(fill=tk.BOTH, expand=True)
        self.chat = DarkScroll(self._chat_container, wrap=tk.WORD, state=tk.DISABLED,
            bg=C["bg"], fg=C["text"], font=FM, insertbackground=C["text"],
            selectbackground=C["accent_dim"], selectforeground="#1e1e2e",
            relief=tk.FLAT, padx=20, pady=14,
            spacing1=4, spacing3=4, borderwidth=0, highlightthickness=0)
        self.chat.pack(fill=tk.BOTH, expand=True)
        for n, o in {
            "user": dict(foreground=C["text_user"], font=("Segoe UI Semibold", 13),
                         spacing1=8, lmargin1=4, lmargin2=4),
            "ok": dict(foreground=C["ok"], lmargin1=8, lmargin2=8),
            "fail": dict(foreground=C["fail"], lmargin1=8, lmargin2=8),
            "warn": dict(foreground=C["warn"], lmargin1=8, lmargin2=8),
            "info": dict(foreground=C["text_dim"], lmargin1=8, lmargin2=8),
            "progress": dict(foreground=C["progress"], lmargin1=8, lmargin2=8),
            "file": dict(foreground=C["file"], lmargin1=8, lmargin2=8),
            "result": dict(foreground=C["text"], lmargin1=8, lmargin2=8),
            "divider": dict(foreground="#313244", spacing1=6, spacing3=6),
            "title": dict(foreground=C["accent"], font=("Segoe UI Semibold", 15),
                          spacing1=4),
            "cmd": dict(foreground="#cdd6f4", font=FM, lmargin1=12, lmargin2=12,
                        background="#181825"),
            "cmd_inline": dict(foreground=C["accent"], font=("Consolas", 11),
                               lmargin1=8, lmargin2=8),
            "label": dict(foreground="#6c7086", font=("Segoe UI", 10),
                          lmargin1=8, lmargin2=8),
            "hint": dict(foreground=C["text_dim"], font=("Segoe UI", 10),
                         lmargin1=8, lmargin2=8),
            "ts": dict(foreground="#585b70", font=("Segoe UI", 9)),
            "cli_header": dict(foreground="#6c7086", font=("Consolas", 10),
                               lmargin1=12, lmargin2=12, underline=True),
        }.items():
            self.chat.tag_configure(n, **o)
        # Scroll-to-bottom floating button (hidden by default)
        self._scroll_btn = tk.Label(self._chat_container, text=" ↓ ", font=("Segoe UI Semibold", 11),
                                     bg=C["accent_dim"], fg="#1e1e2e", padx=10, pady=3, cursor="hand2")
        self._scroll_btn.bind("<Button-1>", lambda e: self._scroll_to_bottom())
        self._scroll_btn.bind("<Enter>", lambda e: self._scroll_btn.configure(bg=C["accent"]))
        self._scroll_btn.bind("<Leave>", lambda e: self._scroll_btn.configure(bg=C["accent_dim"]))
        self._scroll_btn_visible = False
        # Right-click copy menu
        self._chat_menu = tk.Menu(self.root, tearoff=0, bg=C["bg_alt"], fg=C["text"],
                                  activebackground=C["accent"], activeforeground="#1e1e2e",
                                  font=("Segoe UI", 10), bd=0)
        self._chat_menu.add_command(label="Sao chép", command=self._copy_selection)
        self._chat_menu.add_command(label="Sao chép tất cả", command=self._copy_all)
        self.chat.text.bind("<Button-3>", self._show_chat_menu)
        # Auto-scroll pause: nếu user scroll lên thì tạm dừng auto-scroll
        self.chat.text.bind("<MouseWheel>", self._on_chat_scroll)

    def _build_input(self):
        # Thin separator
        tk.Frame(self.root, bg="#313244", height=1).pack(fill=tk.X, side=tk.BOTTOM)
        row = tk.Frame(self.root, bg=C["bg_alt"], padx=14, pady=10)
        row.pack(fill=tk.X, side=tk.BOTTOM)
        # Buttons bên phải
        bt = tk.Frame(row, bg=C["bg_alt"])
        bt.pack(side=tk.RIGHT, padx=(10, 0))
        self._mkb(bt, "File", self._pick).pack(side=tk.LEFT, padx=(0, 5))
        self.btn_send = self._mkb(bt, "Gửi  Enter", self._send, True)
        self.btn_send.pack(side=tk.LEFT)
        self.btn_stop = self._mkb(bt, "Dừng  Esc", self._cancel)
        self.btn_stop.configure(bg=C["fail"], fg="#ffffff")
        self.btn_stop.bind("<Enter>", lambda e: self.btn_stop.configure(bg="#e05070"))
        self.btn_stop.bind("<Leave>", lambda e: self.btn_stop.configure(bg=C["fail"]))
        # Input wrapper — border highlight khi focus, dim khi busy
        self._input_wrapper = tk.Frame(row, bg=C["border"], bd=0, highlightthickness=2,
                                        highlightbackground=C["border"], highlightcolor=C["border"])
        self._input_wrapper.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        # Clean input — Antigravity style (borderless, generous padding)
        self.ent = tk.Text(self._input_wrapper, font=FI, height=2, wrap=tk.WORD,
            bg=C["bg_input"], fg=C["text_dim"],
            insertbackground=C["accent"],
            selectbackground=C["accent_dim"],
            selectforeground="#1e1e2e",
            relief=tk.FLAT, bd=0,
            highlightthickness=0, undo=True,
            padx=12, pady=8)
        self.ent.pack(fill=tk.BOTH, expand=True, ipady=2)
        self.ent.bind("<Return>", self._on_return)
        self.ent.bind("<Shift-Return>", lambda e: None)
        self.ent.bind("<FocusIn>", self._on_input_focus_in)
        self.ent.bind("<FocusOut>", self._on_input_focus_out)
        # Command history
        self.ent.bind("<Up>", self._history_prev)
        self.ent.bind("<Down>", self._history_next)
        self._setph()
        self.ent.focus_set()

    def _mkb(self, p, t, cmd, pri=False):
        bg = C["btn"] if pri else C["bg_alt"]
        fg = "#1e1e2e" if pri else C["text_dim"]
        hb = C["btn_hover"] if pri else C["bg_hover"]
        b = tk.Label(p, text=t, bg=bg, fg=fg, font=("Segoe UI Semibold", 10),
                     padx=16, pady=6, cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.configure(bg=hb))
        b.bind("<Leave>", lambda e: b.configure(bg=bg))
        return b


    def _show_chat_menu(self, e):
        """Hiện right-click context menu trên chat."""
        try:
            self._chat_menu.tk_popup(e.x_root, e.y_root)
        finally:
            self._chat_menu.grab_release()

    def _copy_selection(self):
        """Copy text đang chọn trong chat."""
        try:
            sel = self.chat.text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(sel)
        except tk.TclError:
            pass  # Không có text được chọn

    def _copy_all(self):
        """Copy toàn bộ nội dung chat."""
        content = self.chat.text.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    def _on_chat_scroll(self, e):
        """Track scroll — tạm dừng auto-scroll nếu user scroll lên."""
        self.chat.text.yview_scroll(int(-1*(e.delta/120)), "units")
        # Kiểm tra xem có đang ở cuối không
        _, bot = self.chat.text.yview()
        self._auto_scroll = (bot >= 0.99)
        # Show/hide scroll-to-bottom button
        if not self._auto_scroll and not self._scroll_btn_visible:
            self._scroll_btn.place(relx=0.5, rely=1.0, anchor="s", y=-12)
            self._scroll_btn_visible = True
        elif self._auto_scroll and self._scroll_btn_visible:
            self._scroll_btn.place_forget()
            self._scroll_btn_visible = False
        return "break"

    def _scroll_to_bottom(self):
        """Scroll chat xuống cuối và bật lại auto-scroll."""
        self._auto_scroll = True
        self.chat.see(tk.END)
        if self._scroll_btn_visible:
            self._scroll_btn.place_forget()
            self._scroll_btn_visible = False

    def _setph(self):
        self._ph = True
        self.ent.delete("1.0", tk.END)
        self.ent.insert("1.0", self.PH_TEXT)
        self.ent.configure(fg=C["text_dim"])

    def _clrph(self, e=None):
        if self._ph:
            self._ph = False
            self.ent.delete("1.0", tk.END)
            self.ent.configure(fg=C["text"])

    def _rstph(self, e=None):
        if not self.ent.get("1.0", tk.END).strip():
            self._setph()

    def _on_input_focus_in(self, e=None):
        """Input focus — highlight border + clear placeholder."""
        self._input_wrapper.configure(highlightbackground=C["accent"], highlightcolor=C["accent"])
        self._clrph(e)

    def _on_input_focus_out(self, e=None):
        """Input blur — dim border + restore placeholder."""
        self._input_wrapper.configure(highlightbackground=C["border"], highlightcolor=C["border"])
        self._rstph(e)

    def _get_input(self):
        if self._ph:
            return ""
        return self.ent.get("1.0", tk.END).strip()

    def _set_input(self, text):
        self.ent.delete("1.0", tk.END)
        if text:
            self.ent.insert("1.0", text)

    def _on_return(self, e):
        if self._autocomplete.is_visible:
            self._autocomplete._accept()
            return "break"
        self._send()
        return "break"

    def _handle_softvn_msg(self, msg: str):
        """Xử lý SoftVN sync progress message — hiện rõ ràng trên chat."""
        if not msg:
            return
        # Header: hiện 1 lần duy nhất khi bắt đầu sync
        if not self._softvn_header_shown and not msg.startswith("[ok]") \
                and not msg.startswith("[x]") and not msg.startswith("[~]"):
            self._softvn_header_shown = True
            self._w("  SoftVN Sync\n", "title")
        # Phân loại message
        import re as _re
        progress_match = _re.match(r"^\s*\[(\d+)/(\d+)\]\s+(.+)$", msg)
        if progress_match:
            idx, total, fname = progress_match.groups()
            self._w(f"    [{idx}/{total}] {fname}\n", "progress")
        elif msg.startswith("[ok]"):
            self._w(f"  {msg}\n", "ok")
        elif msg.startswith("[x]") or msg.startswith("[~]"):
            self._w(f"  {msg}\n", "warn")
        else:
            self._w(f"    {msg}\n", "info")

    def _welcome(self):
        ctx = get_run_context()
        user = current_username()

        # === Header compact ===
        self._w("WICA", "title")
        self._w(f"  v{BUILD_VERSION}  ·  ", "info")
        if self.agent.client:
            self._w(f"{self.agent.provider_name}", "ok")
        else:
            self._w("LLM offline", "fail")
        self._w("  ·  ", "info")
        if ctx == "admin":
            self._w(f"Admin: {user}\n", "ok")
        elif ctx == "different_user":
            self._w(f"Run-as: {user}\n", "warn")
        else:
            self._w(f"User: {user}\n", "info")

        # SoftVN copy status
        status = getattr(self.agent, '_softvn_copy_status', 'pending')
        if status == "permission_denied":
            self._w("  [x] SoftVN sync cần quyền Admin\n", "warn")

        self._w("─" * 48 + "\n", "divider")

        # === Quick reference — compact 2-column style ===
        self._w("  Profile  ", "title")
        self._w("cài máy mới  ·  cài phần mềm thuế  ·  cài phần mềm thuế dll\n", "cmd_inline")

        self._w("  Cài / Gỡ  ", "title")
        self._w("cài chrome, 7zip  ·  gỡ teamviewer  ·  cập nhật tất cả  ·  gỡ bloatware\n", "cmd_inline")

        self._w("  Deploy    ", "title")
        self._w("unikey  ·  teamviewer qs  ·  cài font vni  ·  copy profile vpn\n", "cmd_inline")

        self._w("  Config    ", "title")
        self._w("dark mode  ·  hiện đuôi file  ·  taskbar trái  ·  tắt copilot  ·  tắt uac\n", "cmd_inline")

        self._w("  LLM       ", "title")
        self._w("mạng chậm  ·  máy lag  ·  lỗi update  ·  mô tả vấn đề bằng tiếng Việt\n", "cmd_inline")

        self._w("  CLI       ", "title")
        self._w("ipconfig /all  ·  ping 8.8.8.8  ·  tasklist  ·  systeminfo\n", "cmd_inline")

        self._w("\n", "info")
        self._w("  Kéo file vào chat để cài  ·  ↑↓ lệnh cũ  ·  Tab autocomplete  ·  Ctrl+L xoá\n", "hint")
        self._w("─" * 48 + "\n", "divider")

    def _w(self, t, tag):
        self.chat.configure(state=tk.NORMAL)
        # Nếu spinner đang chạy, insert TRƯỚC spinner line để output hiện đúng thứ tự
        ranges = self.chat.text.tag_ranges("spinner_line")
        if ranges and tag != "spinner_line":
            self.chat.text.insert(ranges[0], t, tag)
        else:
            self.chat.insert(tk.END, t, tag)
        self.chat.configure(state=tk.DISABLED)
        if self._auto_scroll:
            self.chat.see(tk.END)
            # Hide scroll-to-bottom button khi auto-scroll đang bật
            if self._scroll_btn_visible:
                self._scroll_btn.place_forget()
                self._scroll_btn_visible = False

    def _out(self, t, tag="result"):
        clean = EMO.sub("", t).strip()
        for line in clean.split("\n"):
            line = line.strip()
            if not line:
                continue
            # CLI output: highlight header/separator lines (dòng chứa toàn --- hoặc ===)
            if tag == "cmd" and re.match(r'^[\-=]{4,}', line):
                self._w("  " + line + "\n", "cli_header")
            else:
                self._w("  " + line + "\n", tag)

    def _out_s(self, t, tag="result"):
        if tag == "_ui_cmd":
            self._out_queue.put((t, "_ui_cmd"))
            return
        if tag == "cli_output":
            tag = "cmd"
        if tag == "progress" and t.strip():
            clean = EMO.sub("", t).strip()
            status_text = clean[:80] + "..." if len(clean) > 80 else clean
            self._out_queue.put((status_text, "set_status"))
        self._out_queue.put((t, tag))

    def _busy(self, on):
        if on:
            self._cancelled = False
            self._auto_scroll = True  # Reset auto-scroll khi bắt đầu task mới
            self.ent.configure(state=tk.DISABLED, bg="#252535")
            self._input_wrapper.configure(highlightbackground="#45475a", highlightcolor="#45475a")
            self.btn_send.pack_forget()
            self.btn_stop.pack(side=tk.LEFT)
        else:
            self.ent.configure(state=tk.NORMAL, bg=C["bg_input"])
            self._input_wrapper.configure(highlightbackground=C["border"], highlightcolor=C["border"])
            self.ent.focus_set()
            # Re-kích hoạt IME sau khi enable lại Entry
            self.root.after(50, self._init_ime)
            self.btn_stop.pack_forget()
            self.btn_send.pack(side=tk.LEFT)

    def _cancel(self):
        self._cancelled = True
        _cancel_winget()
        self.agent.cancel()
        self._out("[Đã dừng]", "warn")

    def _refresh_llm_status(self):
        """Cập nhật LLM status trên status bar (gọi từ main thread)."""
        if self.agent.client:
            self._llm_status_label.configure(
                text=f"LLM: {self.agent.provider_name}", fg=C["ok"])
        else:
            self._llm_status_label.configure(text="LLM: chưa kết nối", fg=C["warn"])

    def _open_settings(self):
        SettingsDialog(self.root, self)

    def _clear(self):
        # Lưu nội dung cũ vào buffer để Ctrl+Z undo
        self._chat_backup = self.chat.text.get("1.0", tk.END)
        self.chat.clear()
        self._welcome()
        # Hide scroll-to-bottom button nếu đang hiện
        if self._scroll_btn_visible:
            self._scroll_btn.place_forget()
            self._scroll_btn_visible = False

    def _undo_clear(self, e=None):
        """Ctrl+Z — khôi phục chat sau khi clear. Chỉ hoạt động 1 lần."""
        if not self._chat_backup or self._is_busy():
            return
        self.chat.text.configure(state=tk.NORMAL)
        self.chat.text.delete("1.0", tk.END)
        self.chat.text.insert("1.0", self._chat_backup)
        self.chat.text.configure(state=tk.DISABLED)
        self.chat.see(tk.END)
        self._chat_backup = None

    def _send(self):
        t = self._get_input()
        if not t:
            return
        # Save to command history (chỉ dòng đầu cho multi-line)
        cmd_line = t.split("\n")[0].strip() if "\n" in t else t
        if not self._cmd_history or self._cmd_history[-1] != cmd_line:
            self._cmd_history.append(cmd_line)
        self._cmd_history_idx = -1
        self._set_input("")
        self._ph = False
        self.ent.configure(fg=C["text"])
        if os.path.isfile(t.strip('"').strip("'")):
            self._dropf(t.strip('"').strip("'")); return
        ts = time.strftime("%H:%M")
        self._w(f"  {ts}  > ", "ts"); self._w(t+"\n", "user")
        self._busy(True)
        threading.Thread(target=self._exec, args=(t,), daemon=True).start()

    def _history_prev(self, e=None):
        """Up arrow — navigate autocomplete hoặc lệnh trước."""
        if self._autocomplete.navigate(-1):
            return "break"
        if not self._cmd_history:
            return "break"
        if self._cmd_history_idx == -1:
            self._cmd_history_idx = len(self._cmd_history) - 1
        elif self._cmd_history_idx > 0:
            self._cmd_history_idx -= 1
        self._clrph()
        self._set_input(self._cmd_history[self._cmd_history_idx])
        return "break"

    def _history_next(self, e=None):
        """Down arrow — navigate autocomplete hoặc lệnh sau."""
        if self._autocomplete.navigate(1):
            return "break"
        if not self._cmd_history or self._cmd_history_idx == -1:
            return "break"
        if self._cmd_history_idx < len(self._cmd_history) - 1:
            self._cmd_history_idx += 1
            self._clrph()
            self._set_input(self._cmd_history[self._cmd_history_idx])
        else:
            self._cmd_history_idx = -1
            self._set_input("")
        return "break"

    def _exec(self, t):
        self.root.after(0, self._start_spinner, "Đang xử lý...")
        try: self.agent.chat_with_feedback(t, self._out_s, self._schedule_raise)
        except Exception as e: self._out_s(f"[error] {e}", "fail")
        self.root.after(0, self._stop_spinner)
        self.root.after(0, self._w, "  "+"-"*52+"\n", "divider")
        self.root.after(0, self._busy, False)
        self.root.after(0, self._refresh_llm_status)
        self.root.after(100, self._raise_window)
        # Notification sound khi hoàn thành
        if self._notify_sound:
            try:
                MB_ICONASTERISK = 0x00000040
                ctypes.windll.user32.MessageBeep(MB_ICONASTERISK)
            except Exception:
                pass

    def _schedule_raise(self):
        # Debounce: skip nếu đã raise trong 2s gần đây
        now = time.time()
        if hasattr(self, '_last_raise_time') and now - self._last_raise_time < 2.0:
            return
        self._last_raise_time = now
        self.root.after(50, self._raise_window)

    def _raise_window(self):
        """Đưa cửa sổ chính lên trên cùng sau khi winget console che.

        EDR-safe: dùng SetForegroundWindow + topmost trick thay vì AttachThreadInput.
        AttachThreadInput bị nhiều EDR flag vì là kỹ thuật injection phổ biến.
        """
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetParent(self.root.winfo_id())
            if not hwnd:
                hwnd = self.root.winfo_id()
            # Topmost trick: set topmost briefly để force foreground
            user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x0003)  # HWND_TOPMOST, SWP_NOMOVE|SWP_NOSIZE
            user32.SetForegroundWindow(hwnd)
            user32.BringWindowToTop(hwnd)
            # Restore non-topmost sau 300ms
            self.root.after(300, lambda: user32.SetWindowPos(hwnd, -2, 0, 0, 0, 0, 0x0003))  # HWND_NOTOPMOST
        except Exception:
            try:
                self.root.lift()
                self.root.attributes('-topmost', True)
                self.root.after(300, lambda: self.root.attributes('-topmost', False))
            except Exception:
                pass

    def _pick(self):
        ps = filedialog.askopenfilenames(title="Chọn file cài đặt",
            filetypes=[("File cài đặt","*.exe *.msi *.msix *.msixbundle *.appx *.zip *.rar"),("Tất cả","*.*")])
        for p in ps: self._dropf(p)

    def _dropf(self, p):
        p = p.strip().strip('"').strip("'")
        fn = os.path.basename(p); ext = os.path.splitext(p)[1].lower()
        ok = {".exe",".msi",".msix",".msixbundle",".appx",".appxbundle",".zip",".rar"}
        if ext not in ok: self._out(f"[lỗi] Định dạng không hỗ trợ: {fn}", "fail"); return
        self._w("  [file] ", "info"); self._w(fn+"\n", "file")
        self._busy(True)
        threading.Thread(target=self._exec, args=(f"cài đặt file local: {p}",), daemon=True).start()

    def run(self): self.root.mainloop()

def main(): ChatApp().run()
if __name__ == "__main__": main()
