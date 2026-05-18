# 🔒 Nghiên Cứu Mật Mã Ứng Dụng Trong MS SQL Server

**Đồ án môn học:** Mật mã ứng dụng  
**Học kỳ - Năm học:** Học kỳ 2 (2024 - 2025)  
**Trường:** Đại học Sư phạm Kỹ thuật TP.HCM (HCMUTE)  
**GVHD:** Trần Đắc Tốt  

---

## 📝 Giới thiệu dự án

Đề tài nghiên cứu các thuật toán mật mã được tích hợp trong hệ quản trị cơ sở dữ liệu **Microsoft SQL Server**, được minh họa thực tế qua một ứng dụng web quản lý người dùng. Dữ liệu nhạy cảm được mã hóa và băm trực tiếp ở tầng database thông qua các cơ chế bảo mật của SQL Server.

### Nội dung nghiên cứu:
* **Mã hóa đối xứng:** Mã hóa thông tin người dùng (địa chỉ, số điện thoại, email) bằng Symmetric Key (`ENCRYPTBYKEY` / `DECRYPTBYKEY`) với thuật toán AES.
* **Hàm băm:** Băm mật khẩu bằng `HASHBYTES` với SHA-256/SHA-512 trực tiếp trong SQL Server qua Stored Procedure.
* **Mã hóa bất đối xứng:** Nghiên cứu RSA và các thuật toán bất đối xứng trong SQL Server.
* **Quản lý khóa:** Hệ thống phân cấp khóa gồm Service Master Key, Database Master Key, Certificate và Symmetric Key.

### Tính năng ứng dụng:
* Đăng ký / Đăng nhập, đổi mật khẩu, quên mật khẩu (gửi email reset link).
* Mã hóa/giải mã dữ liệu người dùng hoàn toàn phía SQL Server.
* Bảo mật session (HTTPS, HttpOnly cookie, session timeout).
* Admin dashboard: xem, sửa, xóa tài khoản người dùng.

---

## 🛠️ Công nghệ sử dụng

* **Backend:** Python 3, Flask, pyodbc, ezgmail
* **Frontend:** HTML5, CSS3, JavaScript, Bootstrap
* **Database:** Microsoft SQL Server (Symmetric Key, Stored Procedures, HASHBYTES)

---

## 🚀 Hướng dẫn cài đặt & Chạy

### 1. Yêu cầu hệ thống
* Python 3.10+
* Microsoft SQL Server (yêu cầu cài đặt sẵn ODBC Driver 17)
* Đã khởi tạo cấu trúc database và các Stored Procedure tương ứng

### 2. Cài đặt các thư viện phụ thuộc
```bash
pip install flask pyodbc ezgmail