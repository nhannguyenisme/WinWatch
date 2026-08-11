"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : tests/test_dashboard.py

Chức năng:
    Kiểm thử logic dữ liệu của WinWatch Web Dashboard.
"""

import json
import tempfile
import unittest
from pathlib import Path

from ubuntu_server.dashboard import (
    build_dashboard_snapshot,
    load_runtime_events,
)
from ubuntu_server.models import SecurityEvent


class TestWinWatchDashboard(
    unittest.TestCase
):
    """Kiểm thử Dashboard data layer."""

    def test_snapshot_contains_statistics(
        self,
    ) -> None:
        events = [
            SecurityEvent(
                timestamp="2026-08-11T00:00:00+07:00",
                hostname="WIN-CLIENT",
                event_id=1,
                source="sysmon",
                process_name=(
                    r"C:\Windows\System32"
                    r"\notepad.exe"
                ),
            ),
            SecurityEvent(
                timestamp="2026-08-11T00:01:00+07:00",
                hostname="WIN-CLIENT",
                event_id=4625,
                source="security",
                username="Nhan",
                source_ip="127.0.0.1",
            ),
        ]

        snapshot = (
            build_dashboard_snapshot(
                events
            )
        )

        self.assertEqual(
            snapshot["total_events"],
            2,
        )

        self.assertEqual(
            snapshot["login_failures"],
            1,
        )

        self.assertEqual(
            snapshot["unique_processes"],
            1,
        )

    def test_recent_events_are_newest_first(
        self,
    ) -> None:
        events = [
            SecurityEvent(
                timestamp="2026-08-11T00:00:00+07:00",
                hostname="PC1",
                event_id=1,
                source="sysmon",
                process_name="old.exe",
            ),
            SecurityEvent(
                timestamp="2026-08-11T00:01:00+07:00",
                hostname="PC1",
                event_id=1,
                source="sysmon",
                process_name="new.exe",
            ),
        ]

        snapshot = (
            build_dashboard_snapshot(
                events
            )
        )

        self.assertEqual(
            snapshot[
                "recent_events"
            ][0]["process"],
            "new.exe",
        )

    def test_load_runtime_events(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jsonl_file = (
                Path(temp)
                / "events.jsonl"
            )

            event = SecurityEvent(
                timestamp="2026-08-11T00:00:00+07:00",
                hostname="PC1",
                event_id=3,
                source="sysmon",
                process_name="chrome.exe",
                destination_ip="1.1.1.1",
                destination_port=443,
            )

            with jsonl_file.open(
                "w",
                encoding="utf-8",
            ) as file:
                file.write(
                    json.dumps(
                        event.to_dict()
                    )
                    + "\n"
                )

            events, errors = (
                load_runtime_events(
                    jsonl_file
                )
            )

            self.assertEqual(
                len(events),
                1,
            )

            self.assertEqual(
                errors,
                [],
            )

    def test_invalid_json_is_skipped(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jsonl_file = (
                Path(temp)
                / "events.jsonl"
            )

            jsonl_file.write_text(
                "{invalid json}\n",
                encoding="utf-8",
            )

            events, errors = (
                load_runtime_events(
                    jsonl_file
                )
            )

            self.assertEqual(
                events,
                [],
            )

            self.assertEqual(
                len(errors),
                1,
            )


if __name__ == "__main__":
    unittest.main()
