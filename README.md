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

### CLI (zero-touch deploy)
```bash
WICA.exe --run-profile mac_dinh   # mở GUI và tự chạy profile ngay
WICA.exe --cmd "cài chrome"       # mở GUI và tự chạy 1 lệnh bất kỳ
```
Dùng bởi `PostSetup.cmd` trên USB cài Windows tự động — không cần gõ lệnh trong chat.

### Fix WiFi driver (ThinkPad T14 và tương tự)
Gõ `fix wifi` (fast command, không cần LLM) hoặc là bước 0 của profile `mac_dinh`:
- Dò card WiFi/thiết bị mạng thiếu driver qua WMI (EDR-safe, không PowerShell)
- Tự cài driver khớp từ `USB\Drivers`, `C:\SoftVN\Drivers`, `C:\Drivers` bằng `pnputil`
- Nếu còn thiếu: in hardware ID + đoán hãng (VEN_8086 Intel / 17CB Qualcomm /
  10EC Realtek / 14C3 MediaTek) để biết cần tải driver nào
- T14 Intel (AX201/AX211) dùng bộ IntelWiFi có sẵn; T14 AMD Gen 3/4 cần thêm
  Qualcomm NFA725A (Lenovo DS556215) vào `Drivers\QualcommWiFi\`

Lưu ý: `config.yaml` cạnh `WICA.exe` được ưu tiên hơn bản bundle trong `_internal`
(sửa config không cần build lại).

## Đóng gói USB
```bash
python build_portable.py
```
Copy thư mục `dist/WICA-USB` vào USB. Chạy `WICA.exe` trực tiếp.
