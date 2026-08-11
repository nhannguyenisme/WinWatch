# WINWATCH - FLOWCHART

**Project:** WinWatch - Real-Time Windows Activity Monitoring System  
**Tác giả:** Nguyễn Thành Nhân

---

## 1. Flowchart Realtime Monitoring

```mermaid
flowchart TD
    A([Start Windows Agent])
    B[Subscribe Sysmon and Security Log]
    C{New Event?}
    D[Render Windows Event XML]
    E[Parse and Normalize Event]
    F{Event Accepted?}
    G[Sanitize Sensitive Command Line]
    H[Put Event into Queue]
    I{Ubuntu Connected?}
    J[Connect or Reconnect TCP]
    K[Serialize Event to JSON]
    L[Send Event to Ubuntu]
    M[Ubuntu Receives JSON]
    N{JSON and Event Valid?}
    O[Create SecurityEvent Object]
    P[Save Event to JSONL and CSV]
    Q[Add Event to EventAnalyzer]
    R[Display Realtime Event]
    S([Continue Monitoring])

    A --> B
    B --> C

    C -- No --> C
    C -- Yes --> D

    D --> E
    E --> F

    F -- No --> C
    F -- Yes --> G

    G --> H
    H --> I

    I -- No --> J
    J --> I

    I -- Yes --> K
    K --> L
    L --> M
    M --> N

    N -- No --> C
    N -- Yes --> O

    O --> P
    P --> Q
    Q --> R
    R --> S
    S --> C
```

---

## 2. Flowchart Offline CSV Analysis

```mermaid
flowchart TD
    A([Start])
    B[Open CSV File]
    C{File Exists?}
    D[Display File Error]
    E[Read CSV Header]
    F{Required Columns Exist?}
    G[Display Missing Column Error]
    H[Read Next CSV Row]
    I{More Rows?}
    J[Normalize Column and Values]
    K[Create SecurityEvent Object]
    L{Event Valid?}
    M[Store Row Error]
    N[Add Event to List]
    O[Analyze Events]
    P[Count Events with Dictionary]
    Q[Find Unique Values with Set]
    R[Create Rankings with Tuples]
    S[Build Analysis Summary]
    T[Export summary.txt and summary.json]
    U([End])

    A --> B
    B --> C

    C -- No --> D
    D --> U

    C -- Yes --> E
    E --> F

    F -- No --> G
    G --> U

    F -- Yes --> H
    H --> I

    I -- Yes --> J
    J --> K
    K --> L

    L -- No --> M
    M --> H

    L -- Yes --> N
    N --> H

    I -- No --> O
    O --> P
    P --> Q
    Q --> R
    R --> S
    S --> T
    T --> U
```

---

## 3. Ý nghĩa ký hiệu

- Hình oval / rounded: Start hoặc End.
- Hình chữ nhật: bước xử lý.
- Hình thoi: điều kiện hoặc quyết định.
- Mũi tên: hướng luồng xử lý.
- Nhánh Yes/No: xử lý rẽ nhánh.
- Luồng quay lại: thể hiện vòng lặp xử lý event hoặc dòng CSV.

---

## 4. Luồng chính của WinWatch

Realtime:

Windows Event
→ Sysmon/Security Log
→ Windows Python Agent
→ Parser
→ Queue
→ TCP/JSON
→ Ubuntu Server
→ SecurityEvent
→ Validation
→ Storage
→ Analyzer
→ Realtime Output

Offline:

CSV
→ File Loader
→ Normalize
→ Validate
→ SecurityEvent List
→ EventAnalyzer
→ Statistics
→ TXT/JSON Report
