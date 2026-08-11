# WinWatch

**Project:** WinWatch - Real-Time Windows Activity Monitoring System

**Tác giả:** Nguyễn Thành Nhân

**Lĩnh vực:** An ninh mạng

## Mục tiêu

WinWatch là hệ thống Python giám sát các sự kiện hệ thống và an ninh
quan trọng trên Windows Client theo thời gian thực.

Windows Agent thu thập Windows Security Log và Sysmon Event Log,
chuẩn hóa sự kiện và truyền dữ liệu về Ubuntu Monitoring Server.

Ubuntu Server tiếp nhận, lưu trữ, thống kê, phân tích, phát hiện
bất thường và xuất báo cáo.

## Các nhóm hoạt động được giám sát

1. Process Create
2. Process Terminate
3. Login Success
4. Login Failure
5. Network Connect
6. File Create
7. File Delete
8. DNS Query

## Chế độ hoạt động

- Real-Time Monitoring
- Offline CSV Analysis
- Event Statistics
- Detection and Alerts
- CSV / JSON / TXT Reporting

