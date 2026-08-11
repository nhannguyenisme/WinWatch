"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : ubuntu_server/analyzer.py

Chức năng:
    Phân tích các SecurityEvent do WinWatch thu thập.

    Module cung cấp:
        - Thống kê số event theo loại.
        - Thống kê đăng nhập thất bại theo username.
        - Thống kê process.
        - Thống kê destination IP.
        - Thống kê DNS query.
        - Xác định process và IP duy nhất.
        - Xếp hạng các giá trị xuất hiện nhiều nhất.

Cấu trúc dữ liệu được sử dụng:
    dict:
        Gom nhóm và đếm dữ liệu.

    set:
        Loại bỏ giá trị trùng lặp.

    tuple:
        Biểu diễn các cặp (giá trị, số lần xuất hiện)
        trong kết quả xếp hạng.
"""

from __future__ import annotations

from typing import Any

from ubuntu_server.models import SecurityEvent


class EventAnalyzer:
    """
    Phân tích một tập SecurityEvent.
    """

    def __init__(
        self,
        events: list[SecurityEvent] | None = None,
    ) -> None:
        self.events: list[SecurityEvent] = []

        if events:
            for event in events:
                self.add_event(event)

    def add_event(
        self,
        event: SecurityEvent,
    ) -> None:
        """
        Thêm một event hợp lệ vào tập dữ liệu phân tích.
        """
        if not isinstance(
            event,
            SecurityEvent,
        ):
            raise TypeError(
                "event phải là SecurityEvent object."
            )

        is_valid, errors = event.validate()

        if not is_valid:
            raise ValueError(
                "Event không hợp lệ: "
                + "; ".join(errors)
            )

        self.events.append(event)

    def event_counts(self) -> dict[str, int]:
        """
        Đếm số lượng event theo từng event_type.
        """
        counts: dict[str, int] = {}

        for event in self.events:
            event_type = event.event_type

            counts[event_type] = (
                counts.get(event_type, 0)
                + 1
            )

        return counts

    def process_counts(self) -> dict[str, int]:
        """
        Đếm số lần process xuất hiện trong dữ liệu.
        """
        counts: dict[str, int] = {}

        for event in self.events:
            process_name = (
                event.process_basename()
            )

            if not process_name:
                continue

            counts[process_name] = (
                counts.get(process_name, 0)
                + 1
            )

        return counts

    def login_failure_counts(
        self,
    ) -> dict[str, int]:
        """
        Đếm số lần đăng nhập thất bại theo username.
        """
        counts: dict[str, int] = {}

        for event in self.events:
            if (
                event.event_type
                != "LOGIN_FAILURE"
            ):
                continue

            username = (
                event.username
                or "unknown"
            )

            counts[username] = (
                counts.get(username, 0)
                + 1
            )

        return counts

    def destination_ip_counts(
        self,
    ) -> dict[str, int]:
        """
        Đếm số lần kết nối tới từng destination IP.
        """
        counts: dict[str, int] = {}

        for event in self.events:
            destination_ip = (
                event.destination_ip
            )

            if not destination_ip:
                continue

            counts[destination_ip] = (
                counts.get(destination_ip, 0)
                + 1
            )

        return counts

    def dns_query_counts(
        self,
    ) -> dict[str, int]:
        """
        Đếm số lần từng domain được truy vấn.
        """
        counts: dict[str, int] = {}

        for event in self.events:
            query = event.dns_query

            if not query:
                continue

            query = query.lower()

            counts[query] = (
                counts.get(query, 0)
                + 1
            )

        return counts

    def unique_processes(self) -> set[str]:
        """
        Trả về tập hợp process không trùng lặp.
        """
        processes: set[str] = set()

        for event in self.events:
            process_name = (
                event.process_basename()
            )

            if process_name:
                processes.add(process_name)

        return processes

    def unique_destination_ips(
        self,
    ) -> set[str]:
        """
        Trả về tập hợp destination IP không trùng lặp.
        """
        destination_ips: set[str] = set()

        for event in self.events:
            if event.destination_ip:
                destination_ips.add(
                    event.destination_ip
                )

        return destination_ips

    @staticmethod
    def rank_counts(
        counts: dict[str, int],
        limit: int = 5,
    ) -> list[tuple[str, int]]:
        """
        Xếp hạng dictionary theo số lần xuất hiện giảm dần.

        Args:
            counts:
                Dictionary cần xếp hạng.

            limit:
                Số kết quả tối đa.

        Returns:
            Danh sách tuple:
                (giá trị, số lần xuất hiện)
        """
        if limit <= 0:
            return []

        ranked_items = sorted(
            counts.items(),
            key=lambda item: (
                -item[1],
                item[0],
            ),
        )

        return ranked_items[:limit]

    def top_processes(
        self,
        limit: int = 5,
    ) -> list[tuple[str, int]]:
        """
        Trả về các process xuất hiện nhiều nhất.
        """
        return self.rank_counts(
            self.process_counts(),
            limit,
        )

    def top_destination_ips(
        self,
        limit: int = 5,
    ) -> list[tuple[str, int]]:
        """
        Trả về các destination IP xuất hiện nhiều nhất.
        """
        return self.rank_counts(
            self.destination_ip_counts(),
            limit,
        )

    def build_summary(self) -> dict[str, Any]:
        """
        Tạo báo cáo thống kê tổng hợp.

        Returns:
            Dictionary chứa các kết quả phân tích chính.
        """
        return {
            "total_events": len(self.events),
            "event_counts": self.event_counts(),
            "unique_process_count": len(
                self.unique_processes()
            ),
            "unique_destination_ip_count": len(
                self.unique_destination_ips()
            ),
            "login_failures": (
                self.login_failure_counts()
            ),
            "top_processes": (
                self.top_processes()
            ),
            "top_destination_ips": (
                self.top_destination_ips()
            ),
            "dns_queries": (
                self.dns_query_counts()
            ),
        }
