"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : tests/test_models.py

Chức năng:
    Kiểm thử model SecurityEvent và các quy tắc validation cơ bản.
"""

import unittest

from ubuntu_server.models import SecurityEvent


class TestSecurityEvent(unittest.TestCase):
    """Kiểm thử các chức năng chính của SecurityEvent."""

    def test_process_create_event(self) -> None:
        event = SecurityEvent(
            timestamp="2026-08-10T22:30:00+07:00",
            hostname="WIN-CLIENT",
            event_id=1,
            source="sysmon",
            username="Nhan",
            process_name=r"C:\Windows\System32\notepad.exe",
            command_line="notepad.exe",
        )

        self.assertEqual(
            event.event_type,
            "PROCESS_CREATE",
        )

        self.assertEqual(
            event.process_basename(),
            "notepad.exe",
        )

    def test_network_event_is_valid(self) -> None:
        event = SecurityEvent(
            timestamp="2026-08-10T22:31:00+07:00",
            hostname="WIN-CLIENT",
            event_id=3,
            source="sysmon",
            process_name=r"C:\Windows\System32\curl.exe",
            source_ip="192.168.100.135",
            destination_ip="1.1.1.1",
            destination_port=443,
        )

        valid, errors = event.validate()

        self.assertTrue(valid)
        self.assertEqual(errors, [])

    def test_invalid_ip_is_rejected(self) -> None:
        event = SecurityEvent(
            timestamp="2026-08-10T22:32:00+07:00",
            hostname="WIN-CLIENT",
            event_id=3,
            source="sysmon",
            source_ip="999.999.999.999",
        )

        valid, errors = event.validate()

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "source_ip" in error
                for error in errors
            )
        )

    def test_invalid_port_is_rejected(self) -> None:
        event = SecurityEvent(
            timestamp="2026-08-10T22:33:00+07:00",
            hostname="WIN-CLIENT",
            event_id=3,
            source="sysmon",
            destination_port=70000,
        )

        valid, errors = event.validate()

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "Destination port" in error
                for error in errors
            )
        )

    def test_login_event_detection(self) -> None:
        event = SecurityEvent(
            timestamp="2026-08-10T22:34:00+07:00",
            hostname="WIN-CLIENT",
            event_id=4625,
            source="security",
            username="Nhan",
            source_ip="192.168.100.135",
        )

        self.assertTrue(event.is_login_event())
        self.assertEqual(
            event.event_type,
            "LOGIN_FAILURE",
        )

    def test_to_dict_returns_dictionary(self) -> None:
        event = SecurityEvent(
            timestamp="2026-08-10T22:35:00+07:00",
            hostname="WIN-CLIENT",
            event_id=22,
            source="sysmon",
            process_name=r"C:\Windows\System32\ping.exe",
            dns_query="example.com",
        )

        result = event.to_dict()

        self.assertIsInstance(result, dict)
        self.assertEqual(
            result["event_type"],
            "DNS_QUERY",
        )

    def test_from_dict_invalid_port_raises_value_error(
        self,
    ) -> None:
        data = {
            "timestamp": "2026-08-10T22:36:00+07:00",
            "hostname": "WIN-CLIENT",
            "event_id": "3",
            "source": "csv",
            "destination_port": "INVALID",
        }

        with self.assertRaises(ValueError):
            SecurityEvent.from_dict(data)


if __name__ == "__main__":
    unittest.main()
