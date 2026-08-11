# WINWATCH - UML CLASS DIAGRAM

**Project:** WinWatch - Real-Time Windows Activity Monitoring System  
**Tác giả:** Nguyễn Thành Nhân

---

## UML Class Diagram

```mermaid
classDiagram

class SecurityEvent {
    +str timestamp
    +str hostname
    +int event_id
    +str event_type
    +str source
    +str username
    +str process_name
    +str command_line
    +str source_ip
    +str destination_ip
    +int destination_port
    +str target_file
    +str dns_query

    +validate()
    +is_login_event()
    +is_network_event()
    +is_file_event()
    +process_basename()
    +summary()
    +to_dict()
    +from_dict()
}

class EventStore {
    +Path jsonl_file
    +Path csv_file

    +save_event()
    +count_jsonl_events()
    +count_csv_events()
    -append_jsonl()
    -append_csv()
}

class EventFileLoader {
    +set required_columns

    +load_csv()
    -validate_columns()
    -normalize_row()
}

class EventAnalyzer {
    +list events

    +add_event()
    +event_counts()
    +process_counts()
    +login_failure_counts()
    +destination_ip_counts()
    +dns_query_counts()
    +unique_processes()
    +unique_destination_ips()
    +rank_counts()
    +top_processes()
    +top_destination_ips()
    +build_summary()
}

class ReportExporter {
    +Path text_file
    +Path json_file

    +export()
    -write_json_report()
    -write_text_report()
}

class WinWatchTCPServer {
    +EventStore event_store
    +EventAnalyzer analyzer
    +set allowed_client_ips

    +verify_request()
}

class WindowsEventReader {
    +Queue event_queue

    +start()
    -subscribe()
    -event_callback()
    +stop()
}

class EventSender {
    +Queue event_queue

    +start()
    +stop()
    -connect()
    -close_socket()
    -serialize_event()
    -send_loop()
}

EventFileLoader --> SecurityEvent : creates
EventStore --> SecurityEvent : stores
EventAnalyzer --> SecurityEvent : analyzes

WinWatchTCPServer --> SecurityEvent : receives
WinWatchTCPServer --> EventStore : uses
WinWatchTCPServer --> EventAnalyzer : uses

ReportExporter --> EventAnalyzer : exports

WindowsEventReader ..> EventSender : shared Queue
```

---

## Mô tả quan hệ chính

### SecurityEvent

Là thực thể dữ liệu trung tâm của WinWatch.

Một object đại diện cho một sự kiện Windows đã được chuẩn hóa.

### EventFileLoader → SecurityEvent

Đọc từng dòng CSV và tạo SecurityEvent object.

### EventStore → SecurityEvent

Nhận SecurityEvent hợp lệ và lưu xuống JSONL/CSV.

### EventAnalyzer → SecurityEvent

Sử dụng danh sách SecurityEvent để thống kê và xếp hạng.

### WinWatchTCPServer → SecurityEvent

Nhận JSON từ Windows và tạo SecurityEvent object.

### WinWatchTCPServer → EventStore

Gọi EventStore để lưu event.

### WinWatchTCPServer → EventAnalyzer

Đưa event hợp lệ vào bộ phân tích.

### ReportExporter → EventAnalyzer

Lấy kết quả phân tích và xuất summary.txt / summary.json.

### WindowsEventReader và EventSender

Hai module sử dụng chung Queue để tách quá trình thu thập Event Log
khỏi quá trình gửi dữ liệu qua TCP.
