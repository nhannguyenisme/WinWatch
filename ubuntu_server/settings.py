"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : ubuntu_server/settings.py

Chức năng:
    Quản lý các tham số cấu hình dùng chung cho Ubuntu Monitoring Server.

    Module tập trung địa chỉ mạng, đường dẫn dữ liệu và các Event ID
    nhằm tránh sử dụng giá trị cố định rải rác trong source code.
"""

from pathlib import Path


# ---------------------------------------------------------------------------
# Project directories
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "output"

EVENTS_JSONL_FILE = DATA_DIR / "events.jsonl"
EVENTS_CSV_FILE = OUTPUT_DIR / "events.csv"
ALERTS_JSON_FILE = OUTPUT_DIR / "alerts.json"
SUMMARY_FILE = OUTPUT_DIR / "summary.txt"


# ---------------------------------------------------------------------------
# Network configuration
# ---------------------------------------------------------------------------

# Ubuntu lắng nghe trên tất cả IPv4 interface.
SERVER_HOST = "0.0.0.0"

# Cổng riêng của WinWatch trong mạng lab.
SERVER_PORT = 5514


# ---------------------------------------------------------------------------
# Windows / Sysmon Event IDs
# ---------------------------------------------------------------------------

SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_PROCESS_TERMINATE = 5
SYSMON_FILE_CREATE = 11
SYSMON_DNS_QUERY = 22
SYSMON_FILE_DELETE = 26

WINDOWS_LOGIN_SUCCESS = 4624
WINDOWS_LOGIN_FAILURE = 4625


EVENT_TYPES = {
    SYSMON_PROCESS_CREATE: "PROCESS_CREATE",
    SYSMON_NETWORK_CONNECT: "NETWORK_CONNECT",
    SYSMON_PROCESS_TERMINATE: "PROCESS_TERMINATE",
    SYSMON_FILE_CREATE: "FILE_CREATE",
    SYSMON_DNS_QUERY: "DNS_QUERY",
    SYSMON_FILE_DELETE: "FILE_DELETE",
    WINDOWS_LOGIN_SUCCESS: "LOGIN_SUCCESS",
    WINDOWS_LOGIN_FAILURE: "LOGIN_FAILURE",
}


# Logon types liên quan trực tiếp đến hoạt động tương tác của người dùng.
INTERACTIVE_LOGON_TYPES = {
    2,   # Interactive
    7,   # Unlock
    10,  # RemoteInteractive (RDP)
    11,  # CachedInteractive
}


def ensure_project_directories() -> None:
    """
    Đảm bảo các thư mục lưu dữ liệu và báo cáo tồn tại.

    Hàm này được gọi khi Ubuntu Monitoring Server khởi động để chương
    trình không phụ thuộc vào việc người dùng tạo thư mục thủ công.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)



# ---------------------------------------------------------------------------
# TCP security / protocol configuration
# ---------------------------------------------------------------------------

# Chỉ Windows Client của lab và localhost được phép kết nối tới WinWatch.
# Localhost được giữ lại để phục vụ unit test và kiểm thử nội bộ.
ALLOWED_CLIENT_IPS = {
    "192.168.100.135",
    "127.0.0.1",
}

# Giới hạn kích thước tối đa của một JSON event.
# Event vượt giới hạn sẽ bị từ chối để tránh tiêu thụ bộ nhớ không cần thiết.
MAX_EVENT_BYTES = 65_536


# ---------------------------------------------------------------------------
# Analysis report files
# ---------------------------------------------------------------------------

SUMMARY_JSON_FILE = OUTPUT_DIR / "summary.json"
