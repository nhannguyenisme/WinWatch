"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : ubuntu_server/server.py

Chức năng:
    Cung cấp TCP server cho Ubuntu Monitoring Server.

    Server thực hiện:
        - Lắng nghe kết nối từ Windows Client.
        - Giới hạn client được phép kết nối.
        - Nhận từng JSON event theo giao thức một dòng / một event.
        - Kiểm tra UTF-8 và JSON.
        - Chuyển dữ liệu thành SecurityEvent object.
        - Validate dữ liệu.
        - Lưu event xuống JSONL/CSV.
        - Đưa event vào EventAnalyzer.
        - Hiển thị sự kiện theo thời gian thực.

Giao thức:
    Mỗi sự kiện được gửi dưới dạng một JSON object UTF-8
    và kết thúc bằng ký tự newline (\\n).

Tác giả:
    Nguyễn Thành Nhân
"""

from __future__ import annotations

import json
import logging
import socketserver
import threading
from typing import Any

from ubuntu_server.analyzer import EventAnalyzer
from ubuntu_server.event_store import (
    EventStorageError,
    EventStore,
)
from ubuntu_server.models import SecurityEvent
from ubuntu_server.settings import (
    ALLOWED_CLIENT_IPS,
    MAX_EVENT_BYTES,
    SERVER_HOST,
    SERVER_PORT,
)


logger = logging.getLogger(__name__)


def decode_event_payload(
    raw_payload: bytes,
) -> SecurityEvent:
    """
    Chuyển một JSON payload nhận qua TCP thành SecurityEvent.

    Args:
        raw_payload:
            Dữ liệu UTF-8 JSON nhận từ Windows Agent.

    Returns:
        SecurityEvent đã được tạo từ payload.

    Raises:
        UnicodeDecodeError:
            Khi payload không phải UTF-8 hợp lệ.

        json.JSONDecodeError:
            Khi payload không phải JSON hợp lệ.

        ValueError:
            Khi JSON không phải object hoặc dữ liệu event sai kiểu.
    """
    payload_text = raw_payload.decode("utf-8")

    payload: Any = json.loads(payload_text)

    if not isinstance(payload, dict):
        raise ValueError(
            "JSON event phải là một object."
        )

    return SecurityEvent.from_dict(payload)


def format_realtime_event(
    event: SecurityEvent,
) -> str:
    """
    Tạo một dòng thông tin ngắn để hiển thị realtime.
    """
    return (
        f"[{event.timestamp}] "
        f"{event.hostname:<18} "
        f"{event.event_type:<20} "
        f"{event.summary()}"
    )


class WinWatchRequestHandler(
    socketserver.StreamRequestHandler
):
    """
    Xử lý một kết nối TCP từ Windows Agent.
    """

    def handle(self) -> None:
        client_ip = self.client_address[0]

        logger.info(
            "Client connected: %s",
            client_ip,
        )

        while True:
            # Đọc tối đa MAX_EVENT_BYTES + 1 để phát hiện payload
            # vượt giới hạn mà không nạp dữ liệu tùy ý vào bộ nhớ.
            raw_payload = self.rfile.readline(
                MAX_EVENT_BYTES + 1
            )

            if not raw_payload:
                break

            if len(raw_payload) > MAX_EVENT_BYTES:
                logger.warning(
                    "Rejected oversized event from %s",
                    client_ip,
                )

                # Kết thúc connection vì phần còn lại của event dài
                # có thể khiến framing newline không còn đồng bộ.
                break

            raw_payload = raw_payload.strip()

            if not raw_payload:
                continue

            try:
                event = decode_event_payload(
                    raw_payload
                )

                # EventStore validate trước khi ghi dữ liệu.
                self.server.event_store.save_event(
                    event
                )

                # Analyzer được chia sẻ giữa các handler.
                # Lock đảm bảo cập nhật danh sách event có kiểm soát.
                with self.server.analyzer_lock:
                    self.server.analyzer.add_event(
                        event
                    )

                print(
                    format_realtime_event(event),
                    flush=True,
                )

            except UnicodeDecodeError as error:
                logger.warning(
                    "Invalid UTF-8 from %s: %s",
                    client_ip,
                    error,
                )

            except json.JSONDecodeError as error:
                logger.warning(
                    "Invalid JSON from %s: %s",
                    client_ip,
                    error,
                )

            except (
                TypeError,
                ValueError,
                EventStorageError,
            ) as error:
                logger.warning(
                    "Rejected event from %s: %s",
                    client_ip,
                    error,
                )

        logger.info(
            "Client disconnected: %s",
            client_ip,
        )


class WinWatchTCPServer(
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
):
    """
    TCP server đa luồng của WinWatch.

    EventStore và EventAnalyzer được chia sẻ cho tất cả client handler.
    """

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        event_store: EventStore,
        analyzer: EventAnalyzer,
        allowed_client_ips: set[str] | None = None,
    ) -> None:
        self.event_store = event_store
        self.analyzer = analyzer
        self.analyzer_lock = threading.Lock()

        self.allowed_client_ips = (
            set(allowed_client_ips)
            if allowed_client_ips is not None
            else set()
        )

        super().__init__(
            server_address,
            WinWatchRequestHandler,
        )

    def verify_request(
        self,
        request: Any,
        client_address: tuple[str, int],
    ) -> bool:
        """
        Kiểm tra IP client trước khi tạo request handler.

        Nếu allowed_client_ips rỗng, server cho phép mọi client.
        Trong lab WinWatch, danh sách này được cấu hình giới hạn.
        """
        client_ip = client_address[0]

        if not self.allowed_client_ips:
            return True

        is_allowed = (
            client_ip
            in self.allowed_client_ips
        )

        if not is_allowed:
            logger.warning(
                "Rejected connection from unauthorized IP: %s",
                client_ip,
            )

        return is_allowed


def create_server(
    host: str = SERVER_HOST,
    port: int = SERVER_PORT,
    event_store: EventStore | None = None,
    analyzer: EventAnalyzer | None = None,
    allowed_client_ips: set[str] | None = None,
) -> WinWatchTCPServer:
    """
    Khởi tạo WinWatchTCPServer.

    Hàm factory giúp unit test có thể sử dụng localhost,
    port ngẫu nhiên và file dữ liệu tạm.
    """
    store = (
        event_store
        if event_store is not None
        else EventStore()
    )

    event_analyzer = (
        analyzer
        if analyzer is not None
        else EventAnalyzer()
    )

    allowed_ips = (
        ALLOWED_CLIENT_IPS
        if allowed_client_ips is None
        else allowed_client_ips
    )

    return WinWatchTCPServer(
        (host, port),
        event_store=store,
        analyzer=event_analyzer,
        allowed_client_ips=allowed_ips,
    )
