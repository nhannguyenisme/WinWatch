/*
============================================================================
Project : WinWatch - Real-Time Windows Activity Monitoring System
Author  : Nguyễn Thành Nhân
File    : dashboard/app.js
Purpose : Client-side logic for WinWatch Security Dashboard
============================================================================
*/

"use strict";

const REFRESH_INTERVAL = 2000;

let dashboardData = null;

const palette = [
    "#39bdf8",
    "#5d8cff",
    "#3ddc97",
    "#a78bfa",
    "#ffb454",
    "#ff647c",
    "#55d6be",
    "#809cff"
];


function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function getCount(data, eventType) {
    return Number(
        data.event_counts?.[eventType] ?? 0
    );
}


function eventBadgeClass(eventType) {

    if (eventType === "LOGIN_FAILURE") {
        return "event-login-failure";
    }

    if (eventType === "LOGIN_SUCCESS") {
        return "event-login-success";
    }

    if (eventType.includes("NETWORK")) {
        return "event-network";
    }

    if (eventType.includes("PROCESS")) {
        return "event-process";
    }

    if (eventType.includes("DNS")) {
        return "event-dns";
    }

    if (eventType.includes("FILE")) {
        return "event-file";
    }

    return "event-default";
}


function formatTimestamp(timestamp) {

    if (!timestamp) {
        return "-";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleTimeString(
        [],
        {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    );
}


function renderKpis(data) {

    const processEvents =
        getCount(
            data,
            "PROCESS_CREATE"
        )
        +
        getCount(
            data,
            "PROCESS_TERMINATE"
        );

    document.getElementById(
        "kpi-total"
    ).textContent =
        data.total_events ?? 0;

    document.getElementById(
        "kpi-process"
    ).textContent =
        processEvents;

    document.getElementById(
        "kpi-network"
    ).textContent =
        data.network_connections ?? 0;

    document.getElementById(
        "kpi-login"
    ).textContent =
        data.login_failures ?? 0;

    document.getElementById(
        "kpi-process-unique"
    ).textContent =
        data.unique_processes ?? 0;
}


function renderDistribution(data) {

    const counts =
        Object.entries(
            data.event_counts ?? {}
        )
        .filter(
            ([, count]) =>
                Number(count) > 0
        )
        .sort(
            (a, b) =>
                b[1] - a[1]
        );

    const total =
        counts.reduce(
            (sum, [, count]) =>
                sum + Number(count),
            0
        );

    document.getElementById(
        "donut-total"
    ).textContent =
        total;

    const donut =
        document.getElementById(
            "event-donut"
        );

    const distribution =
        document.getElementById(
            "distribution"
        );

    if (counts.length === 0) {

        donut.style.background =
            "#15243a";

        distribution.innerHTML =
            '<div class="empty">' +
            'Chưa có sự kiện.' +
            '</div>';

        return;
    }

    let cursor = 0;

    const segments = counts.map(
        ([, count], index) => {

            const start = cursor;

            const angle =
                total > 0
                    ? (
                        Number(count)
                        / total
                    ) * 360
                    : 0;

            cursor += angle;

            const color =
                palette[
                    index % palette.length
                ];

            return (
                `${color} ` +
                `${start}deg ` +
                `${cursor}deg`
            );
        }
    );

    donut.style.background =
        `conic-gradient(${segments.join(",")})`;

    const maxValue =
        Math.max(
            ...counts.map(
                ([, count]) =>
                    Number(count)
            ),
            1
        );

    distribution.innerHTML =
        counts.map(
            ([name, count], index) => {

                const percentage =
                    (
                        Number(count)
                        / maxValue
                    )
                    * 100;

                const color =
                    palette[
                        index % palette.length
                    ];

                return `
                    <div class="distribution-row">

                        <div
                            class="distribution-name"
                            title="${escapeHtml(name)}"
                        >
                            ${escapeHtml(name)}
                        </div>

                        <div class="track">
                            <div
                                class="track-fill"
                                style="
                                    width:${percentage}%;
                                    background:
                                        linear-gradient(
                                            90deg,
                                            ${color},
                                            ${color}aa
                                        );
                                "
                            ></div>
                        </div>

                        <div class="distribution-count">
                            ${count}
                        </div>

                    </div>
                `;
            }
        )
        .join("");
}


function renderRanking(
    elementId,
    rows
) {

    const element =
        document.getElementById(
            elementId
        );

    if (!rows || rows.length === 0) {

        element.innerHTML =
            '<li class="empty">' +
            'Chưa có dữ liệu.' +
            '</li>';

        return;
    }

    const topRows =
        rows.slice(0, 6);

    const maximum =
        Math.max(
            ...topRows.map(
                row => Number(row[1])
            ),
            1
        );

    element.innerHTML =
        topRows.map(
            ([name, count], index) => {

                const width =
                    (
                        Number(count)
                        / maximum
                    )
                    * 100;

                return `
                    <li class="ranking-item">

                        <span class="rank-number">
                            ${index + 1}
                        </span>

                        <div class="rank-info">

                            <div
                                class="rank-name"
                                title="${escapeHtml(name)}"
                            >
                                ${escapeHtml(name)}
                            </div>

                            <div class="rank-bar">
                                <div
                                    class="rank-bar-fill"
                                    style="width:${width}%"
                                ></div>
                            </div>

                        </div>

                        <span class="rank-count">
                            ${count}
                        </span>

                    </li>
                `;
            }
        )
        .join("");
}


function parseTelemetryTimestamp(timestamp) {

    if (!timestamp) {
        return null;
    }

    /*
     * Sysmon may produce timestamps with seven
     * fractional-second digits, for example:
     *
     * 2026-08-10T17:13:16.6987159Z
     *
     * JavaScript engines are most reliable with
     * millisecond precision, so truncate the
     * fractional part to three digits.
     */
    const normalized =
        String(timestamp)
        .trim()
        .replace(
            /(\.\d{3})\d+(Z|[+-]\d{2}:\d{2})$/,
            "$1$2"
        );

    const milliseconds =
        Date.parse(normalized);

    if (
        Number.isNaN(
            milliseconds
        )
    ) {
        return null;
    }

    return milliseconds;
}


function formatTelemetryAge(ageSeconds) {

    if (ageSeconds < 60) {
        return `${ageSeconds} giây trước`;
    }

    const minutes =
        Math.floor(
            ageSeconds / 60
        );

    if (minutes < 60) {

        const remainingSeconds =
            ageSeconds % 60;

        if (remainingSeconds === 0) {
            return `${minutes} phút trước`;
        }

        return (
            `${minutes} phút ` +
            `${remainingSeconds} giây trước`
        );
    }

    const hours =
        Math.floor(
            minutes / 60
        );

    const remainingMinutes =
        minutes % 60;

    if (remainingMinutes === 0) {
        return `${hours} giờ trước`;
    }

    return (
        `${hours} giờ ` +
        `${remainingMinutes} phút trước`
    );
}


function getTelemetryStatus(timestamp) {

    if (!timestamp) {
        return {
            label: "WAITING",
            text: "Chưa nhận được telemetry",
            color: "var(--muted)"
        };
    }

    const eventTime =
        parseTelemetryTimestamp(
            timestamp
        );

    if (eventTime === null) {
        return {
            label: "UNKNOWN",
            text: "Mốc thời gian không hợp lệ",
            color: "var(--muted)"
        };
    }

    const ageSeconds =
        Math.max(
            0,
            Math.floor(
                (
                    Date.now()
                    - eventTime
                )
                / 1000
            )
        );

    if (ageSeconds <= 15) {
        return {
            label: "ACTIVE",
            text: formatTelemetryAge(
                ageSeconds
            ),
            color: "var(--green)"
        };
    }

    if (ageSeconds <= 60) {
        return {
            label: "IDLE",
            text: formatTelemetryAge(
                ageSeconds
            ),
            color: "var(--orange)"
        };
    }

    return {
        label: "STALE",
        text: formatTelemetryAge(
            ageSeconds
        ),
        color: "var(--red)"
    };
}


function renderEndpoint(data) {

    const latest =
        data.recent_events?.[0];

    document.getElementById(
        "host-name"
    ).innerHTML =
        latest?.hostname
            ? (
                escapeHtml(
                    latest.hostname
                )
                +
                "<span>" +
                "Thiết bị Windows được giám sát gần nhất" +
                "</span>"
            )
            : (
                "Đang chờ thiết bị..." +
                "<span>" +
                "Chưa nhận được sự kiện Windows" +
                "</span>"
            );

    const telemetryStatus =
        getTelemetryStatus(
            data.last_event_timestamp
        );

    const telemetryActivity =
        document.getElementById(
            "agent-health"
        );

    telemetryActivity.textContent =
        telemetryStatus.label;

    telemetryActivity.style.color =
        telemetryStatus.color;

    document.getElementById(
        "last-telemetry"
    ).textContent =
        telemetryStatus.text;


    document.getElementById(
        "unique-ip"
    ).textContent =
        data.unique_destination_ips ?? 0;

    document.getElementById(
        "data-errors"
    ).textContent =
        data.data_errors?.length ?? 0;
}


function populateEventFilter(data) {

    const select =
        document.getElementById(
            "event-filter"
        );

    const previousValue =
        select.value;

    const eventTypes =
        Object.keys(
            data.event_counts ?? {}
        )
        .sort();

    select.innerHTML =
        '<option value="">' +
        'Tất cả sự kiện' +
        '</option>'
        +
        eventTypes.map(
            eventType => `
                <option
                    value="${escapeHtml(eventType)}"
                >
                    ${escapeHtml(eventType)}
                </option>
            `
        )
        .join("");

    if (
        eventTypes.includes(
            previousValue
        )
    ) {
        select.value =
            previousValue;
    }
}


function renderEvents() {

    const table =
        document.getElementById(
            "event-table"
        );

    if (!dashboardData) {
        return;
    }

    const searchValue =
        document.getElementById(
            "event-search"
        )
        .value
        .trim()
        .toLowerCase();

    const eventType =
        document.getElementById(
            "event-filter"
        ).value;

    const events =
        dashboardData.recent_events
        ?? [];

    const filtered =
        events.filter(
            event => {

                if (
                    eventType
                    &&
                    event.event_type
                    !== eventType
                ) {
                    return false;
                }

                if (!searchValue) {
                    return true;
                }

                const searchable = [
                    event.timestamp,
                    event.hostname,
                    event.event_type,
                    event.username,
                    event.process,
                    event.source_ip,
                    event.destination_ip,
                    event.target_file,
                    event.dns_query,
                    event.summary
                ]
                .join(" ")
                .toLowerCase();

                return searchable.includes(
                    searchValue
                );
            }
        );

    if (filtered.length === 0) {

        table.innerHTML = `
            <tr>
                <td
                    colspan="5"
                    class="empty"
                >
                    Không có sự kiện phù hợp.
                </td>
            </tr>
        `;

        return;
    }

    table.innerHTML =
        filtered.map(
            event => {

                const identity =
                    event.username
                    ||
                    event.process
                    ||
                    "-";

                return `
                    <tr>

                        <td class="mono">
                            ${escapeHtml(
                                formatTimestamp(
                                    event.timestamp
                                )
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                event.hostname
                            )}
                        </td>

                        <td>
                            <span
                                class="
                                    event-badge
                                    ${eventBadgeClass(
                                        event.event_type
                                    )}
                                "
                            >
                                ${escapeHtml(
                                    event.event_type
                                )}
                            </span>
                        </td>

                        <td class="mono">
                            ${escapeHtml(identity)}
                        </td>

                        <td>
                            ${escapeHtml(
                                event.summary
                            )}
                        </td>

                    </tr>
                `;
            }
        )
        .join("");
}


function renderDashboard(data) {

    dashboardData = data;

    renderKpis(data);
    renderDistribution(data);

    renderRanking(
        "process-ranking",
        data.top_processes
    );

    renderRanking(
        "ip-ranking",
        data.top_destination_ips
    );

    renderEndpoint(data);
    populateEventFilter(data);
    renderEvents();

    document.getElementById(
        "last-update"
    ).textContent =
        "Cập nhật lần cuối: "
        +
        new Date()
            .toLocaleTimeString();

    document.getElementById(
        "status-text"
    ).textContent =
        "Giám sát ONLINE";

    document.getElementById(
        "api-health"
    ).textContent =
        "ONLINE";
}


async function refreshDashboard() {

    const statusText =
        document.getElementById(
            "status-text"
        );

    const statusDot =
        document.getElementById(
            "status-dot"
        );

    try {

        const response =
            await fetch(
                "/api/dashboard",
                {
                    cache: "no-store"
                }
            );

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }

        const data =
            await response.json();

        statusDot.style.background =
            "var(--green)";

        renderDashboard(data);

    } catch (error) {

        statusText.textContent =
            "Dashboard API OFFLINE";

        statusDot.style.background =
            "var(--red)";

        document.getElementById(
            "api-health"
        ).textContent =
            "OFFLINE";

        console.error(
            "Dashboard refresh failed:",
            error
        );
    }
}


document.getElementById(
    "event-search"
).addEventListener(
    "input",
    renderEvents
);


document.getElementById(
    "event-filter"
).addEventListener(
    "change",
    renderEvents
);


refreshDashboard();

setInterval(
    refreshDashboard,
    REFRESH_INTERVAL
);
