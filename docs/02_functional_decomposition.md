# WINWATCH - PHÂN RÃ CHỨC NĂNG

**Tác giả:** Nguyễn Thành Nhân

---

# 1. Windows Agent

## 1.1 Event Collection

Thu thập Windows Event Log theo thời gian thực.

Nguồn:

- Microsoft-Windows-Sysmon/Operational
- Security

Module:

`windows_agent/event_reader.py`

---

## 1.2 Event Parsing

Chuyển Windows Event XML thành dictionary chuẩn của WinWatch.

Module:

`windows_agent/event_parser.py`

Chức năng:

- Parse XML.
- Lấy Event ID.
- Lấy hostname.
- Lấy username.
- Lấy process.
- Lấy source/destination IP.
- Lấy destination port.
- Lấy file path.
- Lấy DNS query.
- Chuẩn hóa string.
- Credential redaction.

---

## 1.3 Event Queue

Lưu tạm event trước khi truyền tới Ubuntu.

Cấu trúc:

`queue.Queue`

Mục đích:

- Tách quá trình thu thập khỏi truyền mạng.
- Tránh làm callback Event Log bị block.
- Giữ event khi đường truyền tạm thời gặp lỗi.

---

## 1.4 Event Transmission

Module:

`windows_agent/event_sender.py`

Chức năng:

- Kết nối Ubuntu TCP/5514.
- Serialize event thành JSON.
- Gửi event.
- Reconnect khi mất kết nối.
- Retry event chưa gửi thành công.

---

# 2. Ubuntu Monitoring Server

## 2.1 TCP Receiver

Module:

`ubuntu_server/server.py`

Chức năng:

- Listen TCP/5514.
- Chấp nhận Windows Client được phép.
- Nhận JSON.
- Kiểm tra UTF-8.
- Kiểm tra JSON.
- Tạo SecurityEvent.

---

## 2.2 Event Model

Module:

`ubuntu_server/models.py`

Class:

`SecurityEvent`

Chức năng:

- Lưu thuộc tính event.
- Validate hostname.
- Validate Event ID.
- Validate IP.
- Validate port.
- Xác định event type.
- Tạo summary.
- Chuyển object thành dictionary.

---

## 2.3 Event Storage

Module:

`ubuntu_server/event_store.py`

Class:

`EventStore`

Chức năng:

- Lưu JSONL.
- Lưu CSV.
- Kiểm tra event trước khi ghi.
- Hỗ trợ thread-safe file write.

---

## 2.4 Offline File Input

Module:

`ubuntu_server/file_loader.py`

Class:

`EventFileLoader`

Chức năng:

- Đọc CSV.
- Kiểm tra file không tồn tại.
- Kiểm tra thiếu column.
- Normalize column.
- Normalize value.
- Chuyển dòng CSV thành SecurityEvent.
- Bỏ qua dòng lỗi.

---

## 2.5 Data Analysis

Module:

`ubuntu_server/analyzer.py`

Class:

`EventAnalyzer`

Chức năng:

- Đếm event theo loại.
- Đếm process.
- Đếm login failure.
- Đếm destination IP.
- Đếm DNS query.
- Loại trùng process bằng set.
- Loại trùng IP bằng set.
- Xếp hạng bằng list of tuples.
- Tạo summary.

---

## 2.6 Report Export

Module:

`ubuntu_server/report_exporter.py`

Class:

`ReportExporter`

Output:

- summary.txt
- summary.json

---

# 3. Main Program

Module:

`ubuntu_server/main.py`

Hai chế độ:

## Realtime

`python -m ubuntu_server.main realtime`

hoặc:

`python -m ubuntu_server.main`

## Offline Analysis

`python -m ubuntu_server.main analyze`

---

# 4. Sơ đồ phân rã tổng quát

WinWatch
|
+-- Windows Agent
|   |
|   +-- Event Reader
|   +-- Event Parser
|   +-- Credential Redaction
|   +-- Event Queue
|   +-- Event Sender
|
+-- Ubuntu Server
    |
    +-- TCP Receiver
    +-- SecurityEvent Model
    +-- Event Validation
    +-- Event Storage
    +-- Offline CSV Loader
    +-- Event Analyzer
    +-- Report Exporter
