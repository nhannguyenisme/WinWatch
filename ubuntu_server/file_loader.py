"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : ubuntu_server/file_loader.py

Chức năng:
    Đọc dữ liệu sự kiện từ file CSV để phục vụ chế độ Offline Analysis.

    Module thực hiện:
        - Kiểm tra file tồn tại và quyền truy cập.
        - Kiểm tra các cột bắt buộc.
        - Chuẩn hóa tên cột và dữ liệu chuỗi.
        - Chuyển từng dòng CSV thành SecurityEvent object.
        - Bỏ qua dòng lỗi nhưng vẫn tiếp tục xử lý các dòng hợp lệ.
        - Trả về danh sách event và danh sách lỗi để người dùng kiểm tra.

Tác giả:
    Nguyễn Thành Nhân
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from ubuntu_server.models import SecurityEvent


REQUIRED_COLUMNS = {
    "timestamp",
    "hostname",
    "event_id",
    "source",
}


class CSVLoadError(RuntimeError):
    """Lỗi xảy ra khi WinWatch không thể đọc file CSV."""


class MissingColumnsError(CSVLoadError):
    """Lỗi xảy ra khi file CSV thiếu cột bắt buộc."""


def normalize_column_name(value: str) -> str:
    """
    Chuẩn hóa tên cột CSV.

    Ví dụ:
        " Event ID " -> "event_id"

    Args:
        value: Tên cột cần chuẩn hóa.

    Returns:
        Tên cột theo dạng lowercase và snake_case đơn giản.
    """
    return (
        value
        .strip()
        .lower()
        .replace(" ", "_")
        .replace("-", "_")
        .replace("\ufeff", "")
    )


def normalize_csv_value(value: Any) -> str:
    """
    Chuẩn hóa giá trị đọc từ CSV.

    Args:
        value: Giá trị cần xử lý.

    Returns:
        Chuỗi đã loại bỏ khoảng trắng thừa.
    """
    if value is None:
        return ""

    return str(value).strip()


class EventFileLoader:
    """
    Đọc và chuyển dữ liệu CSV thành danh sách SecurityEvent.
    """

    def __init__(
        self,
        required_columns: set[str] | None = None,
    ) -> None:
        self.required_columns = (
            set(required_columns)
            if required_columns is not None
            else set(REQUIRED_COLUMNS)
        )

    def load_csv(
        self,
        file_path: str | Path,
    ) -> tuple[list[SecurityEvent], list[str]]:
        """
        Đọc file CSV và tạo SecurityEvent objects.

        Args:
            file_path:
                Đường dẫn tới file CSV.

        Returns:
            Tuple gồm:
                - Danh sách SecurityEvent hợp lệ.
                - Danh sách thông báo lỗi của các dòng không hợp lệ.

        Raises:
            CSVLoadError:
                Khi file không tồn tại, không có quyền đọc hoặc
                có lỗi định dạng CSV.

            MissingColumnsError:
                Khi file thiếu cột bắt buộc.
        """
        csv_path = Path(file_path)

        events: list[SecurityEvent] = []
        errors: list[str] = []

        try:
            with csv_path.open(
                "r",
                encoding="utf-8-sig",
                newline="",
            ) as file:
                reader = csv.DictReader(file)

                if reader.fieldnames is None:
                    raise CSVLoadError(
                        "File CSV không có dòng tiêu đề."
                    )

                normalized_headers = [
                    normalize_column_name(header)
                    for header in reader.fieldnames
                ]

                reader.fieldnames = normalized_headers

                self._validate_columns(
                    normalized_headers
                )

                for row_number, row in enumerate(
                    reader,
                    start=2,
                ):
                    normalized_row = self._normalize_row(
                        row
                    )

                    # Bỏ qua dòng trống hoàn toàn.
                    if not any(normalized_row.values()):
                        continue

                    try:
                        event = SecurityEvent.from_dict(
                            normalized_row
                        )

                        is_valid, validation_errors = (
                            event.validate()
                        )

                        if not is_valid:
                            errors.append(
                                f"Dòng {row_number}: "
                                + "; ".join(
                                    validation_errors
                                )
                            )
                            continue

                        events.append(event)

                    except ValueError as error:
                        errors.append(
                            f"Dòng {row_number}: {error}"
                        )

        except FileNotFoundError as error:
            raise CSVLoadError(
                f"Không tìm thấy file CSV: {csv_path}"
            ) from error

        except PermissionError as error:
            raise CSVLoadError(
                f"Không có quyền đọc file: {csv_path}"
            ) from error

        except csv.Error as error:
            raise CSVLoadError(
                f"File CSV không hợp lệ: {error}"
            ) from error

        return events, errors

    def _validate_columns(
        self,
        headers: list[str],
    ) -> None:
        """
        Kiểm tra các cột bắt buộc có tồn tại hay không.
        """
        available_columns = set(headers)

        missing_columns = (
            self.required_columns
            - available_columns
        )

        if missing_columns:
            missing_text = ", ".join(
                sorted(missing_columns)
            )

            raise MissingColumnsError(
                "File CSV thiếu các cột bắt buộc: "
                f"{missing_text}"
            )

    @staticmethod
    def _normalize_row(
        row: dict[str, Any],
    ) -> dict[str, str]:
        """
        Chuẩn hóa toàn bộ key/value của một dòng CSV.
        """
        normalized_row: dict[str, str] = {}

        for key, value in row.items():
            normalized_key = normalize_column_name(
                key or ""
            )

            normalized_value = normalize_csv_value(
                value
            )

            normalized_row[
                normalized_key
            ] = normalized_value

        return normalized_row
