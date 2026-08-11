# WINWATCH - PHÂN TÍCH IPO

**Project:** WinWatch - Real-Time Windows Activity Monitoring System  
**Tác giả:** Nguyễn Thành Nhân  
**Lĩnh vực:** An ninh mạng  

---

## 1. Bài toán

WinWatch là hệ thống giám sát hoạt động của Windows Client theo thời gian
thực bằng Python.

Windows Agent thu thập các sự kiện từ Windows Security Log và Sysmon,
chuẩn hóa dữ liệu và gửi về Ubuntu Monitoring Server thông qua TCP.

Ubuntu Server tiếp nhận, kiểm tra, lưu trữ và phân tích dữ liệu,
đồng thời hỗ trợ phân tích lại dữ liệu từ file CSV.

---

## 2. Input - Dữ liệu đầu vào

### Realtime Input

- Sysmon Event Log.
- Windows Security Event Log.
- JSON event nhận qua TCP port 5514.

### Offline Input

- File `data/sample_events.csv`.

### Các trường dữ liệu chính

- timestamp
- hostname
- event_id
- event_type
- source
- username
- process_name
- command_line
- source_ip
- destination_ip
- destination_port
- target_file
- dns_query

### 8 nhóm sự kiện

1. Process Create
2. Process Terminate
3. Login Success
4. Login Failure
5. Network Connect
6. File Create
7. File Delete
8. DNS Query

---

## 3. Process - Xử lý

### Pipeline Realtime

1. Windows sinh sự kiện.
2. Sysmon/Security Log ghi sự kiện.
3. Python Windows Agent subscribe Event Log.
4. Parse Windows Event XML.
5. Chuẩn hóa dữ liệu.
6. Che thông tin nhạy cảm trong command line.
7. Đưa event vào Queue.
8. Serialize event thành JSON.
9. Gửi JSON qua TCP.
10. Ubuntu nhận JSON.
11. Chuyển JSON thành SecurityEvent object.
12. Validate dữ liệu.
13. Lưu JSONL và CSV.
14. EventAnalyzer thực hiện thống kê.

### Pipeline Offline

1. Đọc file CSV.
2. Kiểm tra file và các cột bắt buộc.
3. Chuẩn hóa tên cột và giá trị.
4. Chuyển từng dòng thành SecurityEvent.
5. Bỏ qua dòng lỗi và ghi nhận lỗi.
6. Gom nhóm và thống kê dữ liệu.
7. Xếp hạng process và destination IP.
8. Xuất báo cáo TXT và JSON.

---

## 4. Output - Kết quả đầu ra

### Realtime Output

- Sự kiện hiển thị trên terminal Ubuntu.
- `data/events.jsonl`
- `output/events.csv`

### Analysis Output

- Tổng số sự kiện.
- Số lượng từng loại event.
- Process xuất hiện nhiều nhất.
- Số process duy nhất.
- Destination IP xuất hiện nhiều nhất.
- Số destination IP duy nhất.
- Thống kê login failure.
- Thống kê DNS query.

### Report Output

- `output/summary.txt`
- `output/summary.json`

---

## 5. Phạm vi project

WinWatch tập trung vào giám sát 8 nhóm hoạt động cơ bản của một Windows
Client trong môi trường lab.

Project không nhằm thay thế SIEM/EDR thương mại và hiện chưa triển khai:

- Detection Engine nâng cao.
- Incident Correlation.
- Risk Score.
- Machine Learning.
- MITRE ATT&CK correlation.
- Giám sát nhiều endpoint ở quy mô doanh nghiệp.

Các chức năng này được xem là hướng phát triển trong tương lai.
