"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : ubuntu_server/main.py

Chức năng:
    Điểm khởi chạy chính của Ubuntu WinWatch Monitoring Server.

    Chương trình hỗ trợ hai chế độ:
        1. Real-Time Monitoring.
        2. Offline CSV Analysis.

Tác giả:
    Nguyễn Thành Nhân
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from ubuntu_server.analyzer import EventAnalyzer
from ubuntu_server.event_store import EventStore
from ubuntu_server.file_loader import (
    CSVLoadError,
    EventFileLoader,
)
from ubuntu_server.report_exporter import (
    ReportExporter,
)
from ubuntu_server.server import create_server
from ubuntu_server.settings import (
    ALLOWED_CLIENT_IPS,
    DATA_DIR,
    SERVER_HOST,
    SERVER_PORT,
    ensure_project_directories,
)


def configure_logging() -> None:
    """Cấu hình logging của Ubuntu server."""
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(message)s"
        ),
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def display_banner() -> None:
    """Hiển thị thông tin project."""
    print("=" * 72)
    print(
        " WINWATCH - REAL-TIME WINDOWS "
        "ACTIVITY MONITORING SYSTEM"
    )
    print("=" * 72)
    print(
        " Author        : Nguyễn Thành Nhân"
    )
    print(
        f" Listen        : "
        f"{SERVER_HOST}:{SERVER_PORT}"
    )
    print(
        " Allowed IPs   : "
        + ", ".join(
            sorted(ALLOWED_CLIENT_IPS)
        )
    )
    print("=" * 72)


def run_realtime_server() -> None:
    """Khởi chạy chế độ giám sát realtime."""
    event_store = EventStore()
    analyzer = EventAnalyzer()

    try:
        with create_server(
            event_store=event_store,
            analyzer=analyzer,
        ) as server:
            print(
                "[+] WinWatch server is running."
            )
            print(
                "[+] Press Ctrl+C to stop.\n"
            )

            server.serve_forever()

    except KeyboardInterrupt:
        print(
            "\n[+] WinWatch server stopped by user."
        )

    except OSError as error:
        logging.error(
            "Cannot start WinWatch server: %s",
            error,
        )


def run_offline_analysis(
    csv_file: str | Path,
) -> int:
    """
    Đọc dataset CSV, phân tích và xuất báo cáo.

    Returns:
        0 nếu thành công, 1 nếu không thể đọc dataset.
    """
    loader = EventFileLoader()

    try:
        events, errors = loader.load_csv(
            csv_file
        )

    except CSVLoadError as error:
        logging.error(
            "Offline analysis failed: %s",
            error,
        )
        return 1

    analyzer = EventAnalyzer(
        events
    )

    summary = analyzer.build_summary()

    print("=" * 72)
    print(" WINWATCH - OFFLINE CSV ANALYSIS")
    print("=" * 72)
    print(f" Dataset       : {csv_file}")
    print(f" Valid Events  : {len(events)}")
    print(f" Invalid Rows  : {len(errors)}")
    print("-" * 72)

    for event_type in sorted(
        summary["event_counts"]
    ):
        print(
            f" {event_type:<24} "
            f"{summary['event_counts'][event_type]}"
        )

    if errors:
        print("\nData Errors:")

        for error in errors:
            print(
                f" - {error}"
            )

    exporter = ReportExporter()

    text_file, json_file = (
        exporter.export(
            analyzer,
            source_name=str(csv_file),
        )
    )

    print("-" * 72)
    print(
        f" TXT Report    : {text_file}"
    )
    print(
        f" JSON Report   : {json_file}"
    )
    print("=" * 72)

    return 0


def build_argument_parser() -> argparse.ArgumentParser:
    """Tạo command-line interface của WinWatch."""
    parser = argparse.ArgumentParser(
        description=(
            "WinWatch - Windows Activity "
            "Monitoring System"
        )
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    subparsers.add_parser(
        "realtime",
        help=(
            "Start the real-time "
            "Windows monitoring server."
        ),
    )

    analyze_parser = (
        subparsers.add_parser(
            "analyze",
            help=(
                "Analyze a CSV dataset "
                "and export reports."
            ),
        )
    )

    analyze_parser.add_argument(
        "csv_file",
        nargs="?",
        default=str(
            DATA_DIR
            / "sample_events.csv"
        ),
        help=(
            "CSV dataset path. "
            "Default: data/sample_events.csv"
        ),
    )

    return parser


def main() -> None:
    """Điểm khởi chạy chính của WinWatch."""
    configure_logging()
    ensure_project_directories()

    parser = build_argument_parser()
    args = parser.parse_args()

    # Giữ hành vi cũ: không có tham số thì chạy realtime.
    if args.command in {
        None,
        "realtime",
    }:
        display_banner()
        run_realtime_server()
        return

    if args.command == "analyze":
        raise SystemExit(
            run_offline_analysis(
                args.csv_file
            )
        )


if __name__ == "__main__":
    main()
