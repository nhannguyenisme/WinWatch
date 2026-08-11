"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : tests/test_analyzer.py

Chức năng:
    Kiểm thử các chức năng phân tích dữ liệu của EventAnalyzer.
"""

import unittest

from ubuntu_server.analyzer import EventAnalyzer
from ubuntu_server.models import SecurityEvent


class TestEventAnalyzer(unittest.TestCase):
    """Kiểm thử EventAnalyzer."""

    def setUp(self) -> None:
        self.events = [
            SecurityEvent(
                timestamp="2026-08-10T22:00:00+07:00",
                hostname="WIN-CLIENT",
                event_id=1,
                source="sysmon",
                username="Nhan",
                process_name=(
                    r"C:\Windows\System32"
                    r"\notepad.exe"
                ),
            ),
            SecurityEvent(
                timestamp="2026-08-10T22:01:00+07:00",
                hostname="WIN-CLIENT",
                event_id=1,
                source="sysmon",
                username="Nhan",
                process_name=(
                    r"C:\Windows\System32"
                    r"\notepad.exe"
                ),
            ),
            SecurityEvent(
                timestamp="2026-08-10T22:02:00+07:00",
                hostname="WIN-CLIENT",
                event_id=3,
                source="sysmon",
                process_name=(
                    r"C:\Program Files\Google"
                    r"\Chrome\Application"
                    r"\chrome.exe"
                ),
                source_ip="192.168.100.135",
                destination_ip="1.1.1.1",
                destination_port=443,
            ),
            SecurityEvent(
                timestamp="2026-08-10T22:03:00+07:00",
                hostname="WIN-CLIENT",
                event_id=4625,
                source="security",
                username="Nhan",
                source_ip="192.168.100.135",
            ),
            SecurityEvent(
                timestamp="2026-08-10T22:04:00+07:00",
                hostname="WIN-CLIENT",
                event_id=4625,
                source="security",
                username="Nhan",
                source_ip="192.168.100.135",
            ),
            SecurityEvent(
                timestamp="2026-08-10T22:05:00+07:00",
                hostname="WIN-CLIENT",
                event_id=22,
                source="sysmon",
                process_name=(
                    r"C:\Windows\System32"
                    r"\nslookup.exe"
                ),
                dns_query="example.com",
            ),
        ]

        self.analyzer = EventAnalyzer(
            self.events
        )

    def test_event_counts(self) -> None:
        counts = self.analyzer.event_counts()

        self.assertEqual(
            counts["PROCESS_CREATE"],
            2,
        )

        self.assertEqual(
            counts["LOGIN_FAILURE"],
            2,
        )

    def test_login_failure_counts(self) -> None:
        counts = (
            self.analyzer
            .login_failure_counts()
        )

        self.assertEqual(
            counts["Nhan"],
            2,
        )

    def test_unique_processes_returns_set(
        self,
    ) -> None:
        processes = (
            self.analyzer
            .unique_processes()
        )

        self.assertIsInstance(
            processes,
            set,
        )

        self.assertIn(
            "notepad.exe",
            processes,
        )

    def test_unique_destination_ips(
        self,
    ) -> None:
        destination_ips = (
            self.analyzer
            .unique_destination_ips()
        )

        self.assertEqual(
            destination_ips,
            {"1.1.1.1"},
        )

    def test_top_processes_returns_tuples(
        self,
    ) -> None:
        top_processes = (
            self.analyzer
            .top_processes()
        )

        self.assertTrue(
            top_processes
        )

        self.assertIsInstance(
            top_processes[0],
            tuple,
        )

        self.assertEqual(
            top_processes[0],
            ("notepad.exe", 2),
        )

    def test_summary(self) -> None:
        summary = (
            self.analyzer
            .build_summary()
        )

        self.assertEqual(
            summary["total_events"],
            6,
        )

        self.assertEqual(
            summary[
                "unique_destination_ip_count"
            ],
            1,
        )

    def test_wrong_object_is_rejected(
        self,
    ) -> None:
        analyzer = EventAnalyzer()

        with self.assertRaises(TypeError):
            analyzer.add_event(
                "not-an-event"  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
