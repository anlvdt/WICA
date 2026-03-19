# WICA - Windows Install CLI Agent

Chat agent quản lý phần mềm và cấu hình hệ thống Windows qua giao diện chat.
Thiết kế thân thiện tuyệt đối với Windows Defender và CrowdStrike Falcon Sensor.

## Tính năng
- Cài/gỡ phần mềm qua winget (Microsoft-signed, EDR trusted)
- Cài từ file local qua os.startfile() (giống user double-click)
- Cấu hình hệ thống qua winreg (dark mode, UAC, timezone, v.v.)
- Profile cài đặt nhanh (cài máy mới 1 lệnh)
- Gỡ bloatware hàng loạt
- Deploy app portable + tạo shortcut
- LLM fallback (Groq/NVIDIA NIM/Ollama) cho lệnh phức tạp
- Chạy portable từ USB, không cần cài đặt
- Audit log đầy đủ mọi hành động
- Giao diện tiếng Việt có dấu

## EDR Safety
- KHÔNG shell=True, KHÔNG PowerShell/cmd
- KHÔNG silent install, KHÔNG hidden window
- Chỉ gọi winget.exe trực tiếp (argument list)
- Registry chỉ qua Python winreg module
- Path validation chống LLM path traversal
- Mọi action ghi audit log

## Cài đặt
```bash
pip install -r requirements.txt
```

## Cấu hình
- Đặt biến môi trường `GROQ_API_KEY` (hoặc sửa trực tiếp trong config.yaml)
- Sửa `config.yaml` để thêm alias, profile, local_paths

## Chạy
```bash
python main.py
```

## Đóng gói USB
```bash
python build_portable.py
```
Copy thư mục `dist/WICA-USB` vào USB. Chạy `WICA.exe` trực tiếp.
