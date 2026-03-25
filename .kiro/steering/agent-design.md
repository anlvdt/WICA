---
inclusion: always
---

# WICA Agent Design Rules

## Core Principle: Agent, Not Script
WICA là agent HÀNH ĐỘNG — không phải script cứng nhắc. Mọi yêu cầu phải được xử lý hết sức có thể trước khi báo thất bại.

## Fast Path + LLM Escalation Pattern
1. **Fast path** xử lý lệnh rõ ràng bằng regex (nhanh, không cần LLM)
2. **Khi fast path fail** → tự động escalate sang LLM agentic loop với context lỗi
3. LLM nhận kết quả thất bại → tự tìm cách khác (search, retry, thử lệnh khác)
4. Chỉ báo lỗi cho user khi đã hết MỌI phương án

```
User input → Fast path (regex) → Execute
                                    ├── Success → Done
                                    └── Fail → LLM Escalation
                                                 ├── Search/Retry → Success → Done
                                                 └── Hết cách → Báo lỗi + gợi ý
```

## Winget Install/Uninstall Resilience
Khi winget exact match fail, thử theo thứ tự:
1. `winget --id <alias> -e` (exact match)
2. `winget <name>` (fuzzy match, không -e)
3. `winget <tên gốc user gõ>` (nếu khác alias)
4. Registry uninstall (cho local-only packages)
5. `os.startfile` uninstaller (EDR-safe, giống user double-click)
6. LLM escalation: search winget → tìm đúng ID → retry

## Local-Only Packages
Phần mềm thuế VN (HTKK, iTaxViewer, CTSigningHub) không có trên winget.
- Cài: qua `install_htkk` / `install_tax` từ file local
- Gỡ: qua registry UninstallString, KHÔNG qua winget
- Autocomplete: dùng quick_commands, không sinh từ aliases

## EDR Safety — Không bao giờ vi phạm
- KHÔNG shell=True, KHÔNG PowerShell/cmd
- KHÔNG silent install flags — hiện UI cho user
- Mọi action đều audit log
- winget + os.startfile + winreg + ctypes = bộ công cụ duy nhất

## UI/UX Principles
- Fast path cho tốc độ, LLM cho trí thông minh
- Khi busy: visual feedback rõ ràng (input dim, spinner, timestamp)
- Output fail → không dừng lại → escalate → tìm cách khác
- Autocomplete nhất quán: local packages dùng quick_commands, winget packages dùng aliases
