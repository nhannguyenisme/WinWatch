"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : tests/test_file_loader.py

Chức năng:
    Kiểm thử chức năng đọc và chuẩn hóa dữ liệu CSV.
"""

import tempfile
import unittest
from pathlib import Path

from ubuntu_server.file_loader import (
    CSVLoadError,
    EventFileLoader,
    MissingColumnsError,
    normalize_column_name,
)


class TestEventFileLoader(unittest.TestCase):
    """Kiểm thử EventFileLoader."""

    def setUp(self) -> None:
        self.temp_directory = (
            tempfile.TemporaryDirectory()
        )

        self.temp_path = Path(
            self.temp_directory.name
        )

        self.loader = EventFileLoader()

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def write_file(
        self,
        filename: str,
        content: str,
    ) -> Path:
        """Tạo file CSV tạm dùng trong test."""
        file_path = (
            self.temp_path / filename
        )

        file_path.write_text(
            content,
            encoding="utf-8",
        )

        return file_path

    def test_load_valid_csv(self) -> None:
        file_path = self.write_file(
            "valid.csv",
            (
                "timestamp,hostname,event_id,source,"
                "source_ip,destination_ip,"
                "destination_port\n"
                "2026-08-10T22:00:00+07:00,"
                "WIN-CLIENT,3,sysmon,"
                "192.168.100.135,1.1.1.1,443\n"
            ),
        )

        events, errors = self.loader.load_csv(
            file_path
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])

        self.assertEqual(
            events[0].event_type,
            "NETWORK_CONNECT",
        )

    def test_missing_file_raises_error(self) -> None:
        missing_file = (
            self.temp_path / "missing.csv"
        )

        with self.assertRaises(CSVLoadError):
            self.loader.load_csv(
                missing_file
            )

    def test_missing_column_is_rejected(self) -> None:
        file_path = self.write_file(
            "missing_column.csv",
            (
                "timestamp,hostname,event_id\n"
                "2026-08-10T22:00:00+07:00,"
                "WIN-CLIENT,1\n"
            ),
        )

        with self.assertRaises(
            MissingColumnsError
        ):
            self.loader.load_csv(
                file_path
            )

    def test_invalid_ip_row_is_skipped(self) -> None:
        file_path = self.write_file(
            "invalid_ip.csv",
            (
                "timestamp,hostname,event_id,source,"
                "source_ip\n"
                "2026-08-10T22:00:00+07:00,"
                "WIN-CLIENT,3,sysmon,"
                "999.999.999.999\n"
            ),
        )

        events, errors = self.loader.load_csv(
            file_path
        )

        self.assertEqual(events, [])
        self.assertEqual(len(errors), 1)

        self.assertIn(
            "source_ip",
            errors[0],
        )

    def test_invalid_port_row_is_skipped(self) -> None:
        file_path = self.write_file(
            "invalid_port.csv",
            (
                "timestamp,hostname,event_id,source,"
                "destination_port\n"
                "2026-08-10T22:00:00+07:00,"
                "WIN-CLIENT,3,sysmon,ABC\n"
            ),
        )

        events, errors = self.loader.load_csv(
            file_path
        )

        self.assertEqual(events, [])
        self.assertEqual(len(errors), 1)

        self.assertIn(
            "Destination port",
            errors[0],
        )

    def test_column_name_normalization(self) -> None:
        result = normalize_column_name(
            " Event ID "
        )

        self.assertEqual(
            result,
            "event_id",
        )


if __name__ == "__main__":
    unittest.main()
