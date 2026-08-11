"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : tests/test_report_exporter.py

Chức năng:
    Kiểm thử chức năng xuất báo cáo TXT và JSON.
"""

import json
import tempfile
import unittest
from pathlib import Path

from ubuntu_server.analyzer import EventAnalyzer
from ubuntu_server.models import SecurityEvent
from ubuntu_server.report_exporter import (
    ReportExporter,
)


class TestReportExporter(unittest.TestCase):
    """Kiểm thử ReportExporter."""

    def setUp(self) -> None:
        self.temp_directory = (
            tempfile.TemporaryDirectory()
        )

        temp_path = Path(
            self.temp_directory.name
        )

        self.text_file = (
            temp_path / "summary.txt"
        )

        self.json_file = (
            temp_path / "summary.json"
        )

        events = [
            SecurityEvent(
                timestamp="2026-08-10T22:00:00+07:00",
                hostname="WIN-CLIENT",
                event_id=1,
                source="sysmon",
                process_name=(
                    r"C:\Windows\System32"
                    r"\notepad.exe"
                ),
            ),
            SecurityEvent(
                timestamp="2026-08-10T22:01:00+07:00",
                hostname="WIN-CLIENT",
                event_id=3,
                source="sysmon",
                process_name=(
                    r"C:\Windows\System32"
                    r"\powershell.exe"
                ),
                destination_ip="1.1.1.1",
                destination_port=443,
            ),
            SecurityEvent(
                timestamp="2026-08-10T22:02:00+07:00",
                hostname="WIN-CLIENT",
                event_id=4625,
                source="security",
                username="WinWatchDemo",
                source_ip="127.0.0.1",
            ),
        ]

        self.analyzer = EventAnalyzer(
            events
        )

        self.exporter = ReportExporter(
            text_file=self.text_file,
            json_file=self.json_file,
        )

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def test_export_creates_both_files(
        self,
    ) -> None:
        self.exporter.export(
            self.analyzer,
            "test.csv",
        )

        self.assertTrue(
            self.text_file.exists()
        )

        self.assertTrue(
            self.json_file.exists()
        )

    def test_text_report_contains_summary(
        self,
    ) -> None:
        self.exporter.export(
            self.analyzer,
            "test.csv",
        )

        content = self.text_file.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "Total Events : 3",
            content,
        )

        self.assertIn(
            "PROCESS_CREATE",
            content,
        )

        self.assertIn(
            "Nguyễn Thành Nhân",
            content,
        )

    def test_json_report_contains_summary(
        self,
    ) -> None:
        self.exporter.export(
            self.analyzer,
            "test.csv",
        )

        with self.json_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            report = json.load(file)

        self.assertEqual(
            report["author"],
            "Nguyễn Thành Nhân",
        )

        self.assertEqual(
            report["summary"]["total_events"],
            3,
        )

    def test_wrong_analyzer_type_is_rejected(
        self,
    ) -> None:
        with self.assertRaises(TypeError):
            self.exporter.export(
                "invalid"  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
