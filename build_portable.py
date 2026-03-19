# -*- coding: utf-8 -*-
"""Build portable USB package - EDR-safe folder mode.

QUAN TRONG:
- CHI dung PyInstaller folder mode (--noconfirm), KHONG --onefile
- --onefile unpack vao %TEMP% = bi Defender/CrowdStrike flag ngay
- KHONG tao .bat file (bat = script = EDR canh bao)
"""
import subprocess
import shutil
import os

DIST_DIR = "dist"
APP_NAME = "WICA"
USB_DIR = os.path.join(DIST_DIR, f"{APP_NAME}-USB")

# API keys can lay tu env var luc build, ma hoa vao file .keys
_KEY_NAMES = ["GROQ_API_KEY", "NVIDIA_API_KEY"]


def _create_keyfile(dest_dir: str):
    """Doc API key tu env var hoac registry, ma hoa va luu vao .keys."""
    keys = {}
    for name in _KEY_NAMES:
        # Thu env var truoc
        val = os.environ.get(name, "")
        # Fallback: doc tu registry HKCU\Environment
        if not val:
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
                    val, _ = winreg.QueryValueEx(key, name)
            except Exception:
                pass
        # Fallback 2: HKEY_USERS\{SID}\Environment
        if not val:
            try:
                import winreg
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(winreg.HKEY_USERS, i)
                        if sid.startswith("S-1-5-21") and not sid.endswith("_Classes"):
                            try:
                                with winreg.OpenKey(winreg.HKEY_USERS,
                                                    f"{sid}\\Environment") as key:
                                    val, _ = winreg.QueryValueEx(key, name)
                                    if val:
                                        break
                            except (OSError, FileNotFoundError):
                                pass
                        i += 1
                    except OSError:
                        break
            except Exception:
                pass
        if val:
            keys[name] = val
            print(f"  [key] {name} -> da ma hoa vao .keys")
    if keys:
        raw = __import__("json").dumps(keys, ensure_ascii=False).encode("utf-8")
        import base64
        salt = b"W1CA_AnT1Gr4v1tY_2026!"
        encrypted = base64.b64encode(bytes(d ^ salt[i % len(salt)] for i, d in enumerate(raw)))
        keyfile = os.path.join(dest_dir, ".keys")
        with open(keyfile, "wb") as f:
            f.write(encrypted)
        print(f"  [key] File .keys da tao: {keyfile}")
    else:
        print("  [key] Khong tim thay API key trong env var hoac registry")


def build():
    print(f"[build] Dang build {APP_NAME} portable...")

    # === CLEAN BUILD: Xoa cache cu de dam bao code moi nhat ===
    for d in ["build", os.path.join(DIST_DIR, APP_NAME)]:
        if os.path.exists(d):
            print(f"  [clean] Xoa {d}/")
            shutil.rmtree(d)
    spec_file = f"{APP_NAME}.spec"
    if os.path.isfile(spec_file):
        print(f"  [clean] Xoa {spec_file}")
        os.remove(spec_file)

    # PyInstaller FOLDER mode (EDR-safe, KHONG --onefile)
    subprocess.run([
        "pyinstaller",
        "--noconfirm",
        "--name", APP_NAME,
        "--icon", "NONE",
        "--add-data", "config.yaml;.",
        "--hidden-import", "yaml",
        "--hidden-import", "openai",
        "--hidden-import", "win32com.client",
        "--hidden-import", "keystore",
        "--windowed",
        "main.py"
    ], check=True)

    # Tao thu muc USB
    if os.path.exists(USB_DIR):
        shutil.rmtree(USB_DIR)
    os.makedirs(USB_DIR, exist_ok=True)

    # Copy toan bo folder output (KHONG phai single exe)
    src_folder = os.path.join(DIST_DIR, APP_NAME)
    if os.path.isdir(src_folder):
        shutil.copytree(src_folder, os.path.join(USB_DIR, APP_NAME), dirs_exist_ok=True)
    else:
        print(f"[error] Khong tim thay: {src_folder}")
        return

    # Copy config (giu nguyen env:xxx placeholder - app tu doc tu registry)
    shutil.copy2("config.yaml", os.path.join(USB_DIR, APP_NAME))

    # Ma hoa API key vao file .keys (an, khong doc duoc bang mat)
    app_dir = os.path.join(USB_DIR, APP_NAME)
    _create_keyfile(app_dir)
    # Cung tao trong dist/WICA/_internal/ (PyInstaller working dir)
    internal_dir = os.path.join(src_folder, "_internal")
    if os.path.isdir(internal_dir):
        _create_keyfile(internal_dir)

    # Tao thu muc logs
    os.makedirs(os.path.join(USB_DIR, APP_NAME, "logs"), exist_ok=True)

    # Tao file .zip de de copy qua mang
    zip_path = os.path.join(DIST_DIR, f"{APP_NAME}-Portable")
    shutil.make_archive(zip_path, "zip", USB_DIR)
    zip_file = zip_path + ".zip"
    zip_size = os.path.getsize(zip_file) / (1024 * 1024)

    print(f"\n[ok] Portable build: {USB_DIR}/")
    print(f"  {APP_NAME}-USB/")
    print(f"  +-- {APP_NAME}/")
    print(f"      +-- {APP_NAME}.exe   (Chay truc tiep)")
    print(f"      +-- config.yaml      (Cau hinh)")
    print(f"      +-- logs/            (Audit log)")
    print(f"\n[ok] ZIP: {zip_file} ({zip_size:.1f} MB)")

    # === Auto copy sang USB (F:\App\) va ZIP (F:\) ===
    usb_app = r"F:\App"
    usb_zip = r"F:\WICA-Portable.zip"
    src_app = os.path.join(USB_DIR, APP_NAME)
    if os.path.exists("F:\\"):
        # Copy app sang USB
        try:
            if os.path.exists(usb_app):
                shutil.rmtree(usb_app)
            shutil.copytree(src_app, usb_app, dirs_exist_ok=True)
            print(f"\n[ok] Da copy sang USB: {usb_app}")
        except Exception as e:
            print(f"\n[warn] Loi copy sang USB: {e}")
        # Copy ZIP sang USB
        try:
            shutil.copy2(zip_file, usb_zip)
            print(f"[ok] Da copy ZIP sang USB: {usb_zip}")
        except Exception as e:
            print(f"[warn] Loi copy ZIP: {e}")
    else:
        print(f"\n[info] USB (F:) khong co. Copy thu cong:")

    print(f"\nCopy file .zip hoac thu muc {APP_NAME}-USB vao USB de su dung.")
    print(f"Giai nen zip, chay {APP_NAME}.exe truc tiep, khong can cai dat.")


if __name__ == "__main__":
    build()
