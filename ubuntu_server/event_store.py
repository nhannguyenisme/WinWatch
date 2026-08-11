"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : ubuntu_server/event_store.py

Chức năng:
    Lưu các SecurityEvent mà WinWatch nhận được xuống tệp.

    Module hỗ trợ:
        - Lưu dữ liệu gốc dạng JSON Lines (.jsonl).
        - Lưu dữ liệu dạng bảng CSV.
        - Kiểm tra event trước khi ghi.
        - Xử lý lỗi I/O rõ ràng.
        - Hỗ trợ nhiều luồng ghi dữ liệu an toàn.

    JSONL được sử dụng để lưu từng event theo từng dòng JSON.
    CSV được sử dụng cho chức năng phân tích offline và xuất báo cáo.
"""

from __future__ import annotations

import csv
import json
import threading
from pathlib import Path
from typing import Any

from ubuntu_server.models import SecurityEvent
from ubuntu_server.settings import (
    EVENTS_CSV_FILE,
    EVENTS_JSONL_FILE,
    ensure_project_directories,
)


class EventStorageError(RuntimeError):
    """Lỗi xảy ra khi WinWatch không thể ghi dữ liệu xuống tệp."""


class EventStore:
    """
    Quản lý việc lưu SecurityEvent xuống JSONL và CSV.

    Một EventStore object có thể được tái sử dụng trong toàn bộ thời gian
    Ubuntu Monitoring Server hoạt động.
    """

    def __init__(
        self,
        jsonl_file: Path = EVENTS_JSONL_FILE,
        csv_file: Path = EVENTS_CSV_FILE,
    ) -> None:
        self.jsonl_file = Path(jsonl_file)
        self.csv_file = Path(csv_file)

        # TCP server sau này có thể xử lý nhiều Windows client bằng thread.
        # Lock giúp tránh hai thread ghi vào cùng một file đồng thời.
        self._write_lock = threading.Lock()

        ensure_project_directories()

        self.jsonl_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.csv_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def save_event(self, event: SecurityEvent) -> None:
        """
        Kiểm tra và lưu một SecurityEvent xuống JSONL và CSV.

        Args:
            event: SecurityEvent cần lưu.

        Raises:
            TypeError:
                Nếu đối tượng truyền vào không phải SecurityEvent.

            ValueError:
                Nếu dữ liệu event không hợp lệ.

            EventStorageError:
                Nếu xảy ra lỗi khi ghi file.
        """
        if not isinstance(event, SecurityEvent):
            raise TypeError(
                "event phải là một SecurityEvent object."
            )

        is_valid, errors = event.validate()

        if not is_valid:
            error_message = "; ".join(errors)
            raise ValueError(
                f"Không thể lưu event không hợp lệ: {error_message}"
            )

        event_data = event.to_dict()

        try:
            with self._write_lock:
                self._append_jsonl(event_data)
                self._append_csv(event_data)

        except OSError as error:
            raise EventStorageError(
                f"Không thể ghi dữ liệu event: {error}"
            ) from error

    def _append_jsonl(
        self,
        event_data: dict[str, Any],
    ) -> None:
        """
        Ghi một dictionary thành một dòng JSON trong file JSONL.
        """
        with self.jsonl_file.open(
            "a",
            encoding="utf-8",
        ) as file:
            json.dump(
                event_data,
                file,
                ensure_ascii=False,
            )
            file.write("\n")

    def _append_csv(
        self,
        event_data: dict[str, Any],
    ) -> None:
        """
        Ghi một dictionary thành một dòng trong file CSV.

        Header chỉ được tạo khi file chưa tồn tại hoặc đang rỗng.
        """
        file_has_data = (
            self.csv_file.exists()
            and self.csv_file.stat().st_size > 0
        )

        with self.csv_file.open(
            "a",
            encoding="utf-8",
            newline="",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=list(event_data.keys()),
            )

            if not file_has_data:
                writer.writeheader()

            writer.writerow(event_data)

    def count_jsonl_events(self) -> int:
        """
        Đếm số event hiện đang lưu trong JSONL.

        Returns:
            Số dòng dữ liệu hợp lệ trong file.
        """
        if not self.jsonl_file.exists():
            return 0

        with self.jsonl_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            return sum(
                1
                for line in file
                if line.strip()
            )

    def count_csv_events(self) -> int:
        """
        Đếm số event trong CSV, không tính dòng header.

        Returns:
            Số event đã lưu.
        """
        if not self.csv_file.exists():
            return 0

        with self.csv_file.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as file:
            reader = csv.DictReader(file)
            return sum(1 for _ in reader)
