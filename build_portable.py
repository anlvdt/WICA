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


def build():
    print(f"[build] Dang build {APP_NAME} portable...")

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

    # Copy config
    shutil.copy2("config.yaml", os.path.join(USB_DIR, APP_NAME))

    # Tao thu muc logs
    os.makedirs(os.path.join(USB_DIR, APP_NAME, "logs"), exist_ok=True)

    print(f"\n[ok] Portable build: {USB_DIR}/")
    print(f"  {APP_NAME}-USB/")
    print(f"  +-- {APP_NAME}/")
    print(f"      +-- {APP_NAME}.exe   (Chay truc tiep)")
    print(f"      +-- config.yaml      (Cau hinh)")
    print(f"      +-- logs/            (Audit log)")
    print(f"\nCopy thu muc {APP_NAME}-USB vao USB de su dung.")
    print(f"Chay {APP_NAME}.exe truc tiep, khong can cai dat.")


if __name__ == "__main__":
    build()
