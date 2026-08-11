# WINWATCH - BIẾN, THÔNG SỐ VÀ RÀNG BUỘC

**Tác giả:** Nguyễn Thành Nhân

---

## 1. Thông số hệ thống

| Tên | Giá trị | Ý nghĩa |
|---|---|---|
| SERVER_HOST | 0.0.0.0 | Ubuntu listen trên IPv4 |
| SERVER_PORT | 5514 | TCP port của WinWatch |
| Ubuntu IP | 192.168.100.138 | Monitoring Server |
| Windows IP | 192.168.100.135 | Windows Client |
| EVENT_QUEUE_MAXSIZE | 10000 | Số event tối đa trong Queue |
| CONNECT_TIMEOUT_SECONDS | 5 | Timeout TCP |
| RECONNECT_DELAY_SECONDS | 5 | Thời gian retry |

---

## 2. Event ID

| Event ID | Event Type | Nguồn |
|---:|---|---|
| 1 | PROCESS_CREATE | Sysmon |
| 3 | NETWORK_CONNECT | Sysmon |
| 5 | PROCESS_TERMINATE | Sysmon |
| 11 | FILE_CREATE | Sysmon |
| 22 | DNS_QUERY | Sysmon |
| 26 | FILE_DELETE | Sysmon |
| 4624 | LOGIN_SUCCESS | Security |
| 4625 | LOGIN_FAILURE | Security |

---

## 3. Kiểu dữ liệu

| Biến | Kiểu | Ý nghĩa |
|---|---|---|
| timestamp | str | Thời gian event |
| hostname | str | Tên Windows Client |
| event_id | int | Windows/Sysmon Event ID |
| event_type | str | Loại event chuẩn hóa |
| username | str | Tài khoản |
| process_name | str | Process path |
| command_line | str | Command line đã sanitize |
| source_ip | str | Source IP |
| destination_ip | str | Destination IP |
| destination_port | int hoặc None | Port đích |
| target_file | str | File được tác động |
| dns_query | str | Domain DNS |
| events | list | Danh sách SecurityEvent |
| errors | list | Danh sách lỗi |
| event_counts | dict | Đếm event theo loại |
| unique_processes | set | Process không trùng |
| top_processes | list[tuple] | Xếp hạng process |

---

## 4. Ràng buộc dữ liệu

### Hostname

Không được để trống.

### Event ID

Phải là số nguyên lớn hơn 0.

### Source

Chỉ chấp nhận:

- sysmon
- security
- csv

### Destination Port

Nếu tồn tại:

0 <= destination_port <= 65535

### IP Address

Source IP và destination IP phải là IPv4/IPv6 hợp lệ nếu trường có dữ liệu.

### CSV

Các cột bắt buộc:

- timestamp
- hostname
- event_id
- source

### TCP Client

Ubuntu chỉ cho phép:

- 192.168.100.135
- 127.0.0.1 cho local test

### Payload

Một event không được vượt quá MAX_EVENT_BYTES.

### Credential

Thông tin nhạy cảm trong command line phải được thay bằng:

[REDACTED]

trước khi truyền về Ubuntu.

---

## 5. Xử lý ngoại lệ

Các trường hợp đã xử lý:

- FileNotFoundError
- PermissionError
- ValueError
- TypeError
- JSONDecodeError
- UnicodeDecodeError
- OSError
- csv.Error
- queue.Full

Project vượt yêu cầu tối thiểu hai tình huống ngoại lệ của đề thi.
