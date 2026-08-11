"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : tests/test_server.py

Chức năng:
    Kiểm thử quá trình decode JSON và nhận SecurityEvent qua TCP.
"""

import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ubuntu_server.analyzer import EventAnalyzer
from ubuntu_server.event_store import EventStore
from ubuntu_server.server import (
    create_server,
    decode_event_payload,
)


class TestWinWatchServer(unittest.TestCase):
    """Kiểm thử các chức năng TCP cơ bản."""

    @staticmethod
    def valid_payload() -> dict:
        """Tạo JSON event mẫu hợp lệ."""
        return {
            "timestamp": (
                "2026-08-10T23:00:00+07:00"
            ),
            "hostname": "WIN-CLIENT",
            "event_id": 3,
            "source": "sysmon",
            "username": "Nhan",
            "process_name": (
                r"C:\Program Files\Google"
                r"\Chrome\Application\chrome.exe"
            ),
            "source_ip": "192.168.100.135",
            "destination_ip": "1.1.1.1",
            "destination_port": 443,
        }

    def test_decode_valid_json(self) -> None:
        payload = json.dumps(
            self.valid_payload()
        ).encode("utf-8")

        event = decode_event_payload(
            payload
        )

        self.assertEqual(
            event.event_type,
            "NETWORK_CONNECT",
        )

        self.assertEqual(
            event.destination_port,
            443,
        )

    def test_invalid_json_is_rejected(
        self,
    ) -> None:
        with self.assertRaises(
            json.JSONDecodeError
        ):
            decode_event_payload(
                b"{not-valid-json}"
            )

    def test_json_array_is_rejected(
        self,
    ) -> None:
        with self.assertRaises(ValueError):
            decode_event_payload(
                b"[1, 2, 3]"
            )

    def test_tcp_event_is_received_and_stored(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            store = EventStore(
                jsonl_file=(
                    temp_path / "events.jsonl"
                ),
                csv_file=(
                    temp_path / "events.csv"
                ),
            )

            analyzer = EventAnalyzer()

            server = create_server(
                host="127.0.0.1",
                port=0,
                event_store=store,
                analyzer=analyzer,
                allowed_client_ips={
                    "127.0.0.1"
                },
            )

            server_thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
            )

            server_thread.start()

            host, port = server.server_address

            payload = json.dumps(
                self.valid_payload()
            ).encode("utf-8") + b"\n"

            try:
                with socket.create_connection(
                    (host, port),
                    timeout=2,
                ) as client:
                    client.sendall(payload)

                deadline = (
                    time.monotonic() + 2
                )

                while (
                    store.count_jsonl_events()
                    < 1
                    and time.monotonic()
                    < deadline
                ):
                    time.sleep(0.01)

                self.assertEqual(
                    store.count_jsonl_events(),
                    1,
                )

                self.assertEqual(
                    store.count_csv_events(),
                    1,
                )

                self.assertEqual(
                    len(analyzer.events),
                    1,
                )

                self.assertEqual(
                    analyzer.events[0].event_type,
                    "NETWORK_CONNECT",
                )

            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
