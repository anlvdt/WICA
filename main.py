# -*- coding: utf-8 -*-
"""WICA - Windows Install CLI Agent.
Dark title bar via DWM API. Custom scrollbar. No emoji. EDR-safe.
"""
import sys, os, re, threading, ctypes, tkinter as tk
from tkinter import filedialog
if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))
from agent import AntiGravityAgent
from tools import _cancel_winget

C = {
    "bg": "#1e1e2e", "bg_alt": "#181825", "bg_input": "#313244",
    "bg_hover": "#45475a", "accent": "#89dceb", "accent_dim": "#74c7ec",
    "text": "#ffffff", "text_dim": "#cdd6f4", "text_user": "#89dceb",
    "ok": "#a6e3a1", "fail": "#f38ba8", "warn": "#fab387",
    "progress": "#cba6f7", "file": "#f9e2af", "border": "#313244",
    "btn": "#89b4fa", "btn_hover": "#74c7ec",
    "sb_thumb": "#45475a", "sb_active": "#585b70", "sb_bg": "#1e1e2e",
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
    try:
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        v = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(v), ctypes.sizeof(v))
    except Exception: pass

class DarkScroll(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["bg"], bd=0, highlightthickness=0)
        self.text = tk.Text(self, **kw)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._sb = tk.Canvas(self, width=6, bg=C["sb_bg"], bd=0, highlightthickness=0, relief=tk.FLAT)
        self._sb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0,3), pady=6)
        self.text.configure(yscrollcommand=self._sync)
        self._top=0.0; self._bot=1.0; self._drg=False; self._dy=0; self._dt=0.0; self._hov=False
        self._sb.bind("<Button-1>", self._press); self._sb.bind("<B1-Motion>", self._move)
        self._sb.bind("<ButtonRelease-1>", self._rel); self._sb.bind("<Configure>", lambda e: self._draw())
        self._sb.bind("<Enter>", lambda e: self._sh(True)); self._sb.bind("<Leave>", lambda e: self._sh(False))
        self.text.bind("<MouseWheel>", self._wh)
    def _sync(self, t, b): self._top, self._bot = float(t), float(b); self._draw()
    def _sh(self, v): self._hov = v; self._draw()
    def _draw(self):
        self._sb.delete("t")
        if self._bot - self._top >= 1.0: return
        h, w = self._sb.winfo_height(), self._sb.winfo_width()
        y1, y2 = max(0, int(self._top*h)), min(h, int(self._bot*h))
        if y2-y1 < 20: y2 = y1+20
        c = C["sb_active"] if (self._drg or self._hov) else C["sb_thumb"]
        r = min(w//2, 3)
        self._sb.create_rectangle(1, y1+r, w-1, y2-r, fill=c, outline=c, tags="t")
        self._sb.create_oval(1, y1, w-1, y1+2*r, fill=c, outline=c, tags="t")
        self._sb.create_oval(1, y2-2*r, w-1, y2, fill=c, outline=c, tags="t")
    def _press(self, e): self._drg=True; self._dy=e.y; self._dt=self._top; self._draw()
    def _move(self, e):
        if not self._drg: return
        h = self._sb.winfo_height()
        if h > 0: self.text.yview_moveto(max(0, min(1, self._dt+(e.y-self._dy)/h)))
    def _rel(self, e): self._drg=False; self._draw()
    def _wh(self, e): self.text.yview_scroll(int(-1*(e.delta/120)), "units")
    def configure(self, **kw): self.text.configure(**kw)
    def insert(self, *a, **kw): self.text.insert(*a, **kw)
    def see(self, *a): self.text.see(*a)
    def tag_configure(self, *a, **kw): self.text.tag_configure(*a, **kw)
    def clear(self):
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.configure(state=tk.DISABLED)

class ChatApp:
    def __init__(self):
        self.agent = AntiGravityAgent()
        self._ph = False
        self._cancelled = False
        self.root = tk.Tk()
        self.root.title("WICA - Windows Install CLI Agent")
        self.root.configure(bg=C["bg"])
        # Center on screen + DPI-aware sizing
        self._center_window(800, 620)
        self.root.minsize(500, 380)
        self.root.update_idletasks()
        _dark_titlebar(self.root)
        self._build_input()
        self._build_chat()
        self._welcome()
        # Keyboard shortcuts
        self.root.bind("<Control-l>", lambda e: self._clear())
        self.root.bind("<Escape>", lambda e: self._cancel() if not self._cancelled and str(self.ent.cget("state")) == "disabled" else None)

    def _center_window(self, w, h):
        """Đặt cửa sổ giữa màn hình, xử lý cả DPI scaling."""
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _build_chat(self):
        self.chat = DarkScroll(self.root, wrap=tk.WORD, state=tk.DISABLED,
            bg=C["bg"], fg=C["text"], font=FM, insertbackground=C["text"],
            selectbackground=C["accent_dim"], selectforeground="#1e1e2e",
            relief=tk.FLAT, padx=16, pady=12,
            spacing1=2, spacing3=2, borderwidth=0, highlightthickness=0)
        self.chat.pack(fill=tk.BOTH, expand=True)
        for n, o in {"user": dict(foreground=C["text_user"], font=("Segoe UI Semibold",12)),
            "ok": dict(foreground=C["ok"]), "fail": dict(foreground=C["fail"]),
            "warn": dict(foreground=C["warn"]), "info": dict(foreground=C["text_dim"]),
            "progress": dict(foreground=C["progress"]), "file": dict(foreground=C["file"]),
            "result": dict(foreground=C["text"]), "divider": dict(foreground=C["border"]),
            "title": dict(foreground=C["accent"], font=("Segoe UI Semibold",13)),
            "cmd": dict(foreground="#ffffff", font=FM)}.items():
            self.chat.tag_configure(n, **o)

    def _build_input(self):
        # Bottom bar: border + input row
        tk.Frame(self.root, bg=C["border"], height=1).pack(fill=tk.X, side=tk.BOTTOM)
        row = tk.Frame(self.root, bg=C["bg_alt"], padx=10, pady=6)
        row.pack(fill=tk.X, side=tk.BOTTOM)
        # Buttons FIRST (right side, fixed width)
        bt = tk.Frame(row, bg=C["bg_alt"])
        bt.pack(side=tk.RIGHT, padx=(6,0))
        self._mkb(bt, "Ch\u1ecdn file", self._pick).pack(side=tk.LEFT, padx=(0,4))
        self.btn_send = self._mkb(bt, "G\u1eedi", self._send, True)
        self.btn_send.pack(side=tk.LEFT)
        self.btn_stop = self._mkb(bt, "D\u1eebng", self._cancel)
        self.btn_stop.configure(bg=C["fail"], fg="#ffffff")
        self.btn_stop.bind("<Enter>", lambda e: self.btn_stop.configure(bg="#e05070"))
        self.btn_stop.bind("<Leave>", lambda e: self.btn_stop.configure(bg=C["fail"]))
        # Input box AFTER buttons (fills remaining space)
        box = tk.Frame(row, bg=C["bg_input"])
        box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # Text widget (IME/UniKey compatible) — single line
        self.ent = tk.Text(box, height=1, wrap=tk.NONE, bg=C["bg_input"], fg=C["text"],
            font=FI, insertbackground=C["accent"], relief=tk.FLAT, borderwidth=0,
            highlightthickness=0, selectbackground=C["accent_dim"], selectforeground="#1e1e2e",
            padx=8, pady=4, undo=True, maxundo=10)
        self.ent.pack(fill=tk.X, padx=2, pady=2)
        self.ent.bind("<Return>", self._on_return)
        self.ent.focus_set()
        self._setph()
        self.ent.bind("<FocusIn>", self._clrph)
        self.ent.bind("<FocusOut>", self._rstph)

    def _mkb(self, p, t, cmd, pri=False):
        bg=C["btn"] if pri else C["bg_alt"]; fg="#1e1e2e" if pri else C["text_dim"]
        hb=C["btn_hover"] if pri else C["bg_hover"]
        b=tk.Label(p, text=t, bg=bg, fg=fg, font=FS, padx=12, pady=5, cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.configure(bg=hb))
        b.bind("<Leave>", lambda e: b.configure(bg=bg))
        return b

    # -- helpers cho Text widget (thay StringVar) --
    def _get_input(self):
        return self.ent.get("1.0", "end-1c").strip()
    def _set_input(self, text):
        self.ent.delete("1.0", tk.END)
        if text: self.ent.insert("1.0", text)
    def _on_return(self, e):
        self._send()
        return "break"  # chan newline trong single-line Text

    def _setph(self):
        if not self._get_input():
            self.ent.configure(fg=C["text_dim"])
            self._set_input("Nh\u1eadp l\u1ec7nh... (vd: c\u00e0i chrome, g\u1ee1 teamviewer)")
            self._ph = True
    def _clrph(self, e=None):
        if self._ph: self._set_input(""); self.ent.configure(fg=C["text"]); self._ph=False
    def _rstph(self, e=None):
        if not self._get_input(): self._setph()

    def _welcome(self):
        self._w("  WICA - Windows Install CLI Agent\n\n", "title")
        if self.agent.client:
            self._w(f"  [connected] {self.agent.provider_name} ({self.agent.model})\n\n", "ok")
        else:
            self._w("  [offline] Ch\u01b0a k\u1ebft n\u1ed1i LLM. Ki\u1ec3m tra config.yaml.\n\n", "fail")
        self._w("  L\u1ec7nh th\u01b0\u1eddng d\u00f9ng:\n\n", "title")
        for c, d in [
            ("c\u00e0i m\u00e1y m\u1edbi", "Ch\u1ea1y profile c\u00e0i \u0111\u1eb7t chu\u1ea9n"),
            ("xem profile", "Xem chi ti\u1ebft c\u00e1c b\u01b0\u1edbc trong profile"),
            ("c\u00e0i chrome, 7zip", "C\u00e0i ph\u1ea7n m\u1ec1m qua winget"),
            ("g\u1ee1 teamviewer", "G\u1ee1 ph\u1ea7n m\u1ec1m"),
            ("c\u1eadp nh\u1eadt", "C\u1eadp nh\u1eadt t\u1ea5t c\u1ea3 ph\u1ea7n m\u1ec1m"),
            ("xu\u1ea5t danh s\u00e1ch", "Xu\u1ea5t app \u0111\u00e3 c\u00e0i ra file JSON"),
            ("t\u1eaft telemetry", "T\u1eaft thu th\u1eadp d\u1eef li\u1ec7u Windows"),
            ("t\u1eaft bing", "T\u1eaft Bing trong Start Menu"),
            ("b\u1eadt dark mode", "C\u1ea5u h\u00ecnh h\u1ec7 th\u1ed1ng"),
            ("th\u00f4ng tin m\u00e1y t\u00ednh", "Xem th\u00f4ng tin"),
            ("xo\u00e1 m\u00e0n h\u00ecnh", "X\u00f3a n\u1ed9i dung chat (Ctrl+L)"),
        ]:
            self._w(f"    {c}", "cmd"); self._w(f"  -- {d}\n", "info")
        self._w("\n  L\u1ec7nh CLI tr\u1ef1c ti\u1ebfp (kh\u00f4ng c\u1ea7n m\u1edf terminal):\n\n", "title")
        for c, d in [
            ("ipconfig", "Xem c\u1ea5u h\u00ecnh m\u1ea1ng"),
            ("ping 8.8.8.8", "Ki\u1ec3m tra k\u1ebft n\u1ed1i m\u1ea1ng"),
            ("netstat -an", "Xem c\u00e1c k\u1ebft n\u1ed1i \u0111ang m\u1edf"),
            ("tasklist", "Xem ti\u1ebfn tr\u00ecnh \u0111ang ch\u1ea1y"),
            ("systeminfo", "Th\u00f4ng tin h\u1ec7 th\u1ed1ng chi ti\u1ebft"),
            ("whoami", "Xem user hi\u1ec7n t\u1ea1i"),
        ]:
            self._w(f"    {c}", "cmd"); self._w(f"  -- {d}\n", "info")
        self._w("\n  K\u00e9o th\u1ea3 file .exe/.msi v\u00e0o chat ho\u1eb7c nh\u1ea5n [Ch\u1ecdn file]\n", "file")
        self._w("  "+"-"*52+"\n\n", "divider")

    def _w(self, t, tag):
        self.chat.configure(state=tk.NORMAL); self.chat.insert(tk.END, t, tag)
        self.chat.configure(state=tk.DISABLED); self.chat.see(tk.END)
    def _out(self, t, tag="result"):
        clean = EMO.sub("", t).strip()
        # Hiện từng dòng riêng biệt
        for line in clean.split("\n"):
            line = line.strip()
            if line:
                self._w("  " + line + "\n", tag)
    def _out_s(self, t, tag="result"):
        if tag == "_ui_cmd":
            if t == "clear":
                self.root.after(0, self._clear)
            elif t == "help":
                self.root.after(0, self._clear)
            return
        # CLI output hiển thị monospace
        if tag == "cli_output":
            tag = "cmd"
        self.root.after(0, self._out, t, tag)

    def _busy(self, on):
        if on:
            self._cancelled = False
            self.ent.configure(state=tk.DISABLED, bg=C["bg_input"], fg=C["text_dim"])
            self.btn_send.pack_forget()
            self.btn_stop.pack(side=tk.LEFT)
        else:
            self.ent.configure(state=tk.NORMAL, bg=C["bg_input"], fg=C["text"])
            self.btn_stop.pack_forget()
            self.btn_send.pack(side=tk.LEFT)
            self.ent.focus_set()

    def _cancel(self):
        self._cancelled = True
        _cancel_winget()
        self.agent.cancel()
        self._out("[D\u00e3 d\u1eebng]", "warn")

    def _clear(self):
        self.chat.clear()
        self._welcome()

    def _send(self):
        if self._ph: return
        t = self._get_input()
        if not t: return
        self._set_input("")
        if os.path.isfile(t.strip('"').strip("'")):
            self._dropf(t.strip('"').strip("'")); return
        self._w("  > ", "info"); self._w(t+"\n", "user")
        self._busy(True)
        threading.Thread(target=self._exec, args=(t,), daemon=True).start()

    def _exec(self, t):
        try: self.agent.chat_with_feedback(t, self._out_s)
        except Exception as e: self._out_s(f"[error] {e}", "fail")
        self.root.after(0, self._w, "  "+"-"*52+"\n", "divider")
        self.root.after(0, self._busy, False)

    def _pick(self):
        ps = filedialog.askopenfilenames(title="Ch\u1ecdn file c\u00e0i \u0111\u1eb7t",
            filetypes=[("File c\u00e0i \u0111\u1eb7t","*.exe *.msi *.msix *.msixbundle *.appx"),("T\u1ea5t c\u1ea3","*.*")])
        for p in ps: self._dropf(p)

    def _dropf(self, p):
        p = p.strip().strip('"').strip("'")
        fn = os.path.basename(p); ext = os.path.splitext(p)[1].lower()
        ok = {".exe",".msi",".msix",".msixbundle",".appx",".appxbundle"}
        if ext not in ok: self._out(f"[l\u1ed7i] \u0110\u1ecbnh d\u1ea1ng kh\u00f4ng h\u1ed7 tr\u1ee3: {fn}", "fail"); return
        self._w("  [file] ", "info"); self._w(fn+"\n", "file")
        self._busy(True)
        threading.Thread(target=self._exec, args=(f"cai dat file local: {p}",), daemon=True).start()

    def run(self): self.root.mainloop()

def main(): ChatApp().run()
if __name__ == "__main__": main()
