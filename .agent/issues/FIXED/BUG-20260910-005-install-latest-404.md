# BUG-20260910-005: Cả 2 luồng install trong Quick Start đều 404 / chết

- severity: high
- reproduced: yes (fetch trực tiếp `releases/download/latest/...` → HTTP 404; `install.ps1` tham chiếu biến `$Db` chưa khai báo)
- root_cause: (1) URL `releases/download/<tag>/` yêu cầu tag thật — repo không có tag "latest", GitHub chỉ redirect ở `releases/latest/download/`; (2) `install.ps1` gõ nhầm biến `$Db` thay vì `$exe` (không khai báo đâu); (3) `release.yml` không upload `install.sh` vào assets → `curl | bash` 404; (4) `Set-Content -Encoding UTF8` (PS 5.1) ghi BOM vào config JSON của client.
- fix: installers dùng `releases/latest/download/<asset>` khi version=latest, versioned URL cho tag cụ thể; `install.ps1` thống nhất `$exe` + ghi config không BOM qua `[IO.File]::WriteAllText(UTF8Encoding($false))`; `release.yml` job publish checkout + copy `install.sh` vào artifacts.
- regression_test: verify thủ công URL pattern (fetch 404 trước / 200 sau với asset có sẵn); smoke cài đặt E2E để v0.3 (`scripts/install_smoke.ps1`).
- status: FIXED (2026-09-11)

## Chi tiết triệu chứng

1. `install.ps1` / `install.sh` mặc định `$Version = "latest"` → URL `releases/download/latest/<asset>` → **404** (repo không có tag tên "latest").
2. `install.ps1` dùng biến `$Db` (dòng `-OutFile $Db`, `Test-Path $Db`, `"$Db"` trong command, `Installed at: $Db`) — biến **không bao giờ được khai báo** → download chết ngay cả khi URL đúng.
3. `install.sh` không có trong release assets → 1-liner `curl .../install.sh | bash` của README cũng 404.
4. BOM trong config client làm JSON parser (Node) của Claude/Cursor fail đọc `mcp.json` sau khi installer ghi.

## Verify sau fix

- Pattern `releases/latest/download/<asset>` → 200 (binary v0.2.0 tồn tại).
- Asset `install.sh` xuất hiện từ release kế tiếp trở đi (v0.2.0 đã publish trước khi fix nên chưa chứa — chạy lại release hoặc dùng bản sau).
