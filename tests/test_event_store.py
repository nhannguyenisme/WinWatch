"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : tests/test_event_store.py

Chức năng:
    Kiểm thử chức năng lưu SecurityEvent xuống JSONL và CSV.
"""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from ubuntu_server.event_store import EventStore
from ubuntu_server.models import SecurityEvent


class TestEventStore(unittest.TestCase):
    """Kiểm thử các chức năng chính của EventStore."""

    def setUp(self) -> None:
        """
        Tạo thư mục tạm riêng cho từng test.

        Cách này tránh làm thay đổi dữ liệu thật trong thư mục
        data/ và output/ của project.
        """
        self.temp_directory = tempfile.TemporaryDirectory()

        temp_path = Path(
            self.temp_directory.name
        )

        self.jsonl_file = temp_path / "events.jsonl"
        self.csv_file = temp_path / "events.csv"

        self.store = EventStore(
            jsonl_file=self.jsonl_file,
            csv_file=self.csv_file,
        )

    def tearDown(self) -> None:
        """Xóa dữ liệu tạm sau mỗi test."""
        self.temp_directory.cleanup()

    @staticmethod
    def create_sample_event() -> SecurityEvent:
        """Tạo event mẫu hợp lệ dùng chung cho các test."""
        return SecurityEvent(
            timestamp="2026-08-10T22:45:00+07:00",
            hostname="WIN-CLIENT",
            event_id=3,
            source="sysmon",
            username="Nhan",
            process_name=(
                r"C:\Program Files\Google\Chrome"
                r"\Application\chrome.exe"
            ),
            source_ip="192.168.100.135",
            destination_ip="1.1.1.1",
            destination_port=443,
        )

    def test_save_event_creates_files(self) -> None:
        event = self.create_sample_event()

        self.store.save_event(event)

        self.assertTrue(
            self.jsonl_file.exists()
        )

        self.assertTrue(
            self.csv_file.exists()
        )

    def test_jsonl_contains_event(self) -> None:
        event = self.create_sample_event()

        self.store.save_event(event)

        with self.jsonl_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            stored_data = json.loads(
                file.readline()
            )

        self.assertEqual(
            stored_data["event_type"],
            "NETWORK_CONNECT",
        )

        self.assertEqual(
            stored_data["source_ip"],
            "192.168.100.135",
        )

    def test_csv_contains_event(self) -> None:
        event = self.create_sample_event()

        self.store.save_event(event)

        with self.csv_file.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as file:
            rows = list(
                csv.DictReader(file)
            )

        self.assertEqual(
            len(rows),
            1,
        )

        self.assertEqual(
            rows[0]["event_type"],
            "NETWORK_CONNECT",
        )

    def test_multiple_events_are_appended(self) -> None:
        first_event = self.create_sample_event()

        second_event = SecurityEvent(
            timestamp="2026-08-10T22:46:00+07:00",
            hostname="WIN-CLIENT",
            event_id=22,
            source="sysmon",
            username="Nhan",
            process_name=(
                r"C:\Windows\System32"
                r"\WindowsPowerShell\v1.0"
                r"\powershell.exe"
            ),
            dns_query="example.com",
        )

        self.store.save_event(first_event)
        self.store.save_event(second_event)

        self.assertEqual(
            self.store.count_jsonl_events(),
            2,
        )

        self.assertEqual(
            self.store.count_csv_events(),
            2,
        )

    def test_invalid_event_is_rejected(self) -> None:
        event = SecurityEvent(
            timestamp="2026-08-10T22:47:00+07:00",
            hostname="",
            event_id=3,
            source="sysmon",
            destination_port=70000,
        )

        with self.assertRaises(ValueError):
            self.store.save_event(event)

    def test_wrong_object_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.store.save_event(
                {"event_id": 1}  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
