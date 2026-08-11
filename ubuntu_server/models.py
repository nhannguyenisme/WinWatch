"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : ubuntu_server/models.py

Chức năng:
    Định nghĩa các mô hình dữ liệu chính của WinWatch.

    SecurityEvent đại diện cho một sự kiện bảo mật hoặc sự kiện hệ thống
    được thu thập từ Windows Client thông qua Windows Security Log hoặc Sysmon.

    Lớp chịu trách nhiệm:
        - Lưu trữ các thuộc tính của sự kiện.
        - Chuẩn hóa dữ liệu đầu vào.
        - Kiểm tra tính hợp lệ của dữ liệu.
        - Chuyển object thành dictionary để lưu CSV/JSON.
        - Tạo nội dung tóm tắt phục vụ realtime monitoring.

Author:
    Nguyễn Thành Nhân
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import Any

from ubuntu_server.settings import EVENT_TYPES


class SecurityEvent:
    """
    Mô hình hóa một sự kiện được WinWatch nhận từ Windows Client.

    Mỗi object SecurityEvent đại diện cho một event duy nhất, ví dụ:
    process creation, login failure, network connection hoặc DNS query.
    """

    def __init__(
        self,
        timestamp: str,
        hostname: str,
        event_id: int,
        source: str,
        username: str = "",
        process_name: str = "",
        command_line: str = "",
        source_ip: str = "",
        destination_ip: str = "",
        destination_port: int | None = None,
        target_file: str = "",
        dns_query: str = "",
    ) -> None:
        self.timestamp = self._normalize_text(timestamp)
        self.hostname = self._normalize_text(hostname)
        self.event_id = int(event_id)
        self.source = self._normalize_text(source).lower()

        self.username = self._normalize_text(username)
        self.process_name = self._normalize_path(process_name)
        self.command_line = self._normalize_text(command_line)

        self.source_ip = self._normalize_text(source_ip)
        self.destination_ip = self._normalize_text(destination_ip)
        self.destination_port = destination_port

        self.target_file = self._normalize_path(target_file)
        self.dns_query = self._normalize_text(dns_query).lower()

        # Event type được xác định tập trung từ settings.py để tránh
        # hard-code Event ID ở nhiều module khác nhau.
        self.event_type = EVENT_TYPES.get(
            self.event_id,
            f"UNKNOWN_{self.event_id}",
        )

    @staticmethod
    def _normalize_text(value: Any) -> str:
        """
        Chuẩn hóa một giá trị về chuỗi và loại bỏ khoảng trắng dư thừa.

        Args:
            value: Giá trị đầu vào cần chuẩn hóa.

        Returns:
            Chuỗi đã được chuẩn hóa.
        """
        if value is None:
            return ""

        return str(value).strip()

    @classmethod
    def _normalize_path(cls, value: Any) -> str:
        """
        Chuẩn hóa đường dẫn Windows để dữ liệu thống nhất khi phân tích.

        Args:
            value: Đường dẫn hoặc tên process/file.

        Returns:
            Đường dẫn đã loại bỏ khoảng trắng dư thừa.
        """
        return cls._normalize_text(value)

    def validate(self) -> tuple[bool, list[str]]:
        """
        Kiểm tra các ràng buộc dữ liệu quan trọng của sự kiện.

        Returns:
            Tuple gồm:
                - True/False thể hiện event hợp lệ hay không.
                - Danh sách lỗi phát hiện được.
        """
        errors: list[str] = []

        if not self.hostname:
            errors.append("Hostname không được để trống.")

        if self.event_id <= 0:
            errors.append("Event ID phải lớn hơn 0.")

        if self.source not in {"sysmon", "security", "csv"}:
            errors.append(
                "Nguồn sự kiện phải là sysmon, security hoặc csv."
            )

        if self.destination_port is not None:
            if not 0 <= self.destination_port <= 65535:
                errors.append(
                    "Destination port phải nằm trong khoảng 0-65535."
                )

        for field_name, ip_value in (
            ("source_ip", self.source_ip),
            ("destination_ip", self.destination_ip),
        ):
            if ip_value and not self._is_valid_ip(ip_value):
                errors.append(
                    f"{field_name} không phải địa chỉ IP hợp lệ: "
                    f"{ip_value}"
                )

        return len(errors) == 0, errors

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        """
        Kiểm tra một chuỗi có phải địa chỉ IPv4/IPv6 hợp lệ hay không.

        Args:
            value: Chuỗi địa chỉ IP.

        Returns:
            True nếu hợp lệ, ngược lại False.
        """
        try:
            ip_address(value)
            return True
        except ValueError:
            return False

    def is_login_event(self) -> bool:
        """
        Kiểm tra event hiện tại có thuộc nhóm đăng nhập hay không.
        """
        return self.event_type in {
            "LOGIN_SUCCESS",
            "LOGIN_FAILURE",
        }

    def is_network_event(self) -> bool:
        """
        Kiểm tra event hiện tại có phải kết nối mạng hay không.
        """
        return self.event_type == "NETWORK_CONNECT"

    def is_file_event(self) -> bool:
        """
        Kiểm tra event hiện tại có phải hoạt động file hay không.
        """
        return self.event_type in {
            "FILE_CREATE",
            "FILE_DELETE",
        }

    def process_basename(self) -> str:
        """
        Lấy tên executable từ đường dẫn đầy đủ của process.

        Ví dụ:
            C:\\Windows\\System32\\cmd.exe
            -> cmd.exe
        """
        if not self.process_name:
            return ""

        normalized = self.process_name.replace("\\", "/")

        return normalized.rsplit("/", maxsplit=1)[-1].lower()

    def summary(self) -> str:
        """
        Sinh nội dung tóm tắt ngắn phục vụ màn hình realtime.

        Returns:
            Chuỗi mô tả sự kiện theo từng event type.
        """
        if self.event_type == "PROCESS_CREATE":
            process = self.process_basename()
            return f"{process} {self.command_line}".strip()

        if self.event_type == "PROCESS_TERMINATE":
            return self.process_basename()

        if self.event_type in {
            "LOGIN_SUCCESS",
            "LOGIN_FAILURE",
        }:
            username = self.username or "unknown"
            source_ip = self.source_ip or "-"

            return f"user={username} src={source_ip}"

        if self.event_type == "NETWORK_CONNECT":
            process = self.process_basename() or "unknown"

            destination = self.destination_ip or "-"
            if self.destination_port is not None:
                destination = (
                    f"{destination}:{self.destination_port}"
                )

            return f"{process} -> {destination}"

        if self.event_type in {
            "FILE_CREATE",
            "FILE_DELETE",
        }:
            return self.target_file

        if self.event_type == "DNS_QUERY":
            process = self.process_basename() or "unknown"
            return f"{process} -> {self.dns_query}"

        return self.event_type

    def to_dict(self) -> dict[str, Any]:
        """
        Chuyển SecurityEvent object thành dictionary.

        Dictionary này sẽ được tái sử dụng khi:
            - Xuất CSV.
            - Xuất JSON.
            - Lưu event.
            - Phân tích thống kê.

        Returns:
            Dictionary chứa toàn bộ dữ liệu của event.
        """
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "username": self.username,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "target_file": self.target_file,
            "dns_query": self.dns_query,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityEvent:
        """
        Tạo SecurityEvent object từ dictionary.

        Phương thức này được sử dụng cho cả dữ liệu realtime và dữ liệu
        được đọc lại từ file CSV/JSON.

        Args:
            data: Dictionary chứa dữ liệu event.

        Returns:
            SecurityEvent object.

        Raises:
            ValueError:
                Khi event_id hoặc destination_port không thể chuyển
                thành kiểu số hợp lệ.
        """
        raw_port = data.get("destination_port")

        destination_port: int | None = None

        if raw_port not in (None, ""):
            try:
                destination_port = int(raw_port)
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"Destination port không hợp lệ: {raw_port}"
                ) from error

        try:
            event_id = int(data.get("event_id", 0))
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"Event ID không hợp lệ: {data.get('event_id')}"
            ) from error

        return cls(
            timestamp=data.get("timestamp", ""),
            hostname=data.get("hostname", ""),
            event_id=event_id,
            source=data.get("source", ""),
            username=data.get("username", ""),
            process_name=data.get("process_name", ""),
            command_line=data.get("command_line", ""),
            source_ip=data.get("source_ip", ""),
            destination_ip=data.get("destination_ip", ""),
            destination_port=destination_port,
            target_file=data.get("target_file", ""),
            dns_query=data.get("dns_query", ""),
        )

    def __repr__(self) -> str:
        """
        Biểu diễn object ngắn gọn phục vụ debug.
        """
        return (
            "SecurityEvent("
            f"hostname={self.hostname!r}, "
            f"event_id={self.event_id}, "
            f"event_type={self.event_type!r}"
            ")"
        )


def current_timestamp() -> str:
    """
    Trả về timestamp hiện tại theo chuẩn ISO 8601.

    Returns:
        Timestamp dạng YYYY-MM-DDTHH:MM:SS.
    """
    return datetime.now().astimezone().isoformat(
        timespec="seconds"
    )
