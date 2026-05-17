# 🔒 MS SQL Server Cryptography Implementation (Python & HTML)

**Đồ án/Đề tài môn học:** Mật mã ứng dụng  
**Học kỳ - Năm học:** Học kỳ 2 (2025 - 2026) | Năm 2  
**Trường:** Đại học Sư phạm Kỹ thuật TP.HCM (HCMUTE)

---

## 📝 Giới thiệu dự án
Dự án **Nghiên cứu các thuật toán mật mã được ứng dụng trong Hệ quản trị cơ sở dữ liệu Microsoft SQL Server** được cụ thể hóa bằng một ứng dụng Web trực quan. Hệ thống sử dụng Python làm Backend để kết nối, cấu hình và thực nghiệm các cơ chế mã hóa dữ liệu trong SQL Server, kết hợp giao diện HTML giúp người dùng dễ dàng thao tác và quan sát kết quả.

### Các nội dung nghiên cứu và thực nghiệm cốt lõi:
- **Mã hóa dữ liệu trong suốt (Transparent Data Encryption - TDE):** Thực nghiệm kích hoạt mã hóa toàn bộ tệp tin cơ sở dữ liệu (`.mdf`, `.ldf`) bằng thuật toán **AES-256** nhằm bảo vệ dữ liệu ở trạng thái lưu trữ (Data-at-Rest).
- **Luôn mã hóa (Always Encrypted):** Mô phỏng cơ chế mã hóa dữ liệu từ phía Client sử dụng thư viện Python để mã hóa trước khi đẩy vào SQL Server, đảm bảo dữ liệu truyền đi (Data-in-Transit) luôn an toàn.
- **Hàm băm dữ liệu (Hashing):** Minh họa cơ chế băm mật khẩu bằng hàm `HASHBYTES` với thuật toán **SHA-256 / SHA-512** trực tiếp dưới database và so sánh kết quả.
- **Quản lý phân cấp khóa:** Mô phỏng quy trình khởi tạo Service Master Key, Database Master Key và Certificates để quản lý vòng đời của khóa mã hóa.

## 🛠️ Công nghệ sử dụng
- **Backend:** Python 3.10+ (Sử dụng thư viện `pyodbc` hoặc `pymssql` để kết nối và thực thi lệnh T-SQL vào SQL Server).
- **Frontend:** HTML5, CSS3, JavaScript (Giao diện Dashboard điều khiển và hiển thị dữ liệu trước/sau khi mã hóa).
- **Database:** Microsoft SQL Server (2019 / 2022).
- **Công cụ quản lý:** Git & GitHub.

## 🚀 Hướng dẫn cài đặt & Chạy ứng dụng

1. **Tải mã nguồn về máy:**
   ```bash
   git clone [https://github.com/an-ngnvi/mssql-crypto-research.git](https://github.com/an-ngnvi/mssql-crypto-research.git)
   cd mssql-crypto-research