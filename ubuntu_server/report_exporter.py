"""
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
Module  : ubuntu_server/report_exporter.py

Chức năng:
    Xuất kết quả phân tích của WinWatch ra các tệp báo cáo dễ đọc.

    Module sử dụng kết quả từ EventAnalyzer và tạo:
        - summary.txt  : báo cáo dành cho người đọc.
        - summary.json : báo cáo có cấu trúc dành cho xử lý tự động.

Tác giả:
    Nguyễn Thành Nhân
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ubuntu_server.analyzer import EventAnalyzer
from ubuntu_server.settings import (
    SUMMARY_FILE,
    SUMMARY_JSON_FILE,
)


class ReportExporter:
    """
    Xuất kết quả phân tích của EventAnalyzer thành TXT và JSON.
    """

    def __init__(
        self,
        text_file: Path = SUMMARY_FILE,
        json_file: Path = SUMMARY_JSON_FILE,
    ) -> None:
        self.text_file = Path(text_file)
        self.json_file = Path(json_file)

        self.text_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.json_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def export(
        self,
        analyzer: EventAnalyzer,
        source_name: str = "runtime",
    ) -> tuple[Path, Path]:
        """
        Xuất kết quả phân tích ra TXT và JSON.

        Args:
            analyzer:
                EventAnalyzer chứa tập event đã được phân tích.

            source_name:
                Tên nguồn dữ liệu, ví dụ sample_events.csv.

        Returns:
            Tuple gồm đường dẫn file TXT và JSON.

        Raises:
            TypeError:
                Nếu analyzer không phải EventAnalyzer.
        """
        if not isinstance(
            analyzer,
            EventAnalyzer,
        ):
            raise TypeError(
                "analyzer phải là EventAnalyzer object."
            )

        report = {
            "project": (
                "WinWatch - Real-Time Windows "
                "Activity Monitoring System"
            ),
            "author": "Nguyễn Thành Nhân",
            "source": source_name,
            "summary": analyzer.build_summary(),
        }

        self._write_text_report(report)
        self._write_json_report(report)

        return (
            self.text_file,
            self.json_file,
        )

    def _write_json_report(
        self,
        report: dict[str, Any],
    ) -> None:
        """Ghi báo cáo có cấu trúc dưới dạng JSON."""
        with self.json_file.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                report,
                file,
                ensure_ascii=False,
                indent=4,
            )

    def _write_text_report(
        self,
        report: dict[str, Any],
    ) -> None:
        """Ghi báo cáo tổng hợp dạng văn bản."""
        summary = report["summary"]

        lines = [
            "=" * 68,
            "WINWATCH - WINDOWS ACTIVITY MONITORING SUMMARY",
            "=" * 68,
            f"Project : {report['project']}",
            f"Author  : {report['author']}",
            f"Source  : {report['source']}",
            "",
            f"Total Events : {summary['total_events']}",
            "",
            "EVENT STATISTICS",
            "-" * 68,
        ]

        event_counts = summary[
            "event_counts"
        ]

        if event_counts:
            for event_type in sorted(
                event_counts
            ):
                lines.append(
                    f"{event_type:<24} "
                    f": {event_counts[event_type]}"
                )
        else:
            lines.append(
                "No events available."
            )

        lines.extend(
            [
                "",
                "PROCESS STATISTICS",
                "-" * 68,
                (
                    "Unique Processes        : "
                    f"{summary['unique_process_count']}"
                ),
            ]
        )

        top_processes = summary[
            "top_processes"
        ]

        if top_processes:
            for position, (
                process_name,
                count,
            ) in enumerate(
                top_processes,
                start=1,
            ):
                lines.append(
                    f"{position}. "
                    f"{process_name:<30} "
                    f"{count}"
                )

        lines.extend(
            [
                "",
                "NETWORK STATISTICS",
                "-" * 68,
                (
                    "Unique Destination IPs  : "
                    f"{summary['unique_destination_ip_count']}"
                ),
            ]
        )

        top_ips = summary[
            "top_destination_ips"
        ]

        if top_ips:
            for position, (
                destination_ip,
                count,
            ) in enumerate(
                top_ips,
                start=1,
            ):
                lines.append(
                    f"{position}. "
                    f"{destination_ip:<30} "
                    f"{count}"
                )

        lines.extend(
            [
                "",
                "LOGIN FAILURE STATISTICS",
                "-" * 68,
            ]
        )

        login_failures = summary[
            "login_failures"
        ]

        if login_failures:
            for username in sorted(
                login_failures
            ):
                lines.append(
                    f"{username:<30} "
                    f": {login_failures[username]}"
                )
        else:
            lines.append(
                "No login failures."
            )

        lines.extend(
            [
                "",
                "DNS QUERY STATISTICS",
                "-" * 68,
            ]
        )

        dns_queries = summary[
            "dns_queries"
        ]

        if dns_queries:
            ranked_dns = sorted(
                dns_queries.items(),
                key=lambda item: (
                    -item[1],
                    item[0],
                ),
            )[:5]

            for position, (
                domain,
                count,
            ) in enumerate(
                ranked_dns,
                start=1,
            ):
                lines.append(
                    f"{position}. "
                    f"{domain:<38} "
                    f"{count}"
                )
        else:
            lines.append(
                "No DNS queries."
            )

        lines.extend(
            [
                "",
                "=" * 68,
                "END OF REPORT",
                "=" * 68,
            ]
        )

        with self.text_file.open(
            "w",
            encoding="utf-8",
        ) as file:
            file.write(
                "\n".join(lines)
                + "\n"
            )
