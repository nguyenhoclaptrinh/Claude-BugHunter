# HỆ THỐNG TÀI LIỆU TRA CỨU BẢO MẬT TOÀN DIỆN (SECURITY CHEAT SHEETS)

Bộ tài liệu này được biên soạn và cấu trúc trực tiếp từ hơn **71 kỹ năng** và **24 thư viện báo cáo thực chiến** trong dự án **Claude-BugHunter**. Đây là cẩm nang tra cứu nhanh (cheat sheets) đầy đủ, trực quan và không viết tắt, giúp bạn nắm bắt toàn bộ tư duy và kỹ thuật tấn công từ cơ bản đến nâng cao.

---

## 📂 CHỈ MỤC HỆ THỐNG TÀI LIỆU

Bộ tài liệu được chia thành 5 chuyên đề chuyên sâu để bạn dễ dàng tra cứu nhanh khi đang thực hiện kiểm thử:

1.  **[01. Quy Trình Kiểm Thử & Xác Minh Lỗi (01_methodology_triage.md)](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/01_methodology_triage.md)**
    *   Quy trình kiểm thử 5 pha: *Recon ➔ Map ➔ Hunt ➔ Prove ➔ Report*.
    *   Chốt chặn chất lượng: Cổng 7 Câu Hỏi (7-Question Gate) tự động lọc lỗi False Positive.
    *   Quy tắc kiểm tra chéo (Statistical-Sample, Body-Diff, Marker Discipline).
    *   Hướng dẫn vận hành công cụ `cbh` CLI và kết nối Burp Suite Proxy.
2.  **[02. Các Lỗ Hổng Ứng Dụng Web (02_web_vulnerabilities.md)](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/02_web_vulnerabilities.md)**
    *   Cơ chế hoạt động, mã nguồn lỗi và cách vá lỗi của **24 lớp lỗ hổng web**.
    *   Bảng tổng hợp payload thực chiến, 11 cách bypass IP cho **SSRF**, bypass bộ lọc **File Upload**, WAF bypass cho **SQLi**, và **XSS JavaScript Sinks**.
3.  **[03. Bảo Mật Web Framework & Quét Mã Nguồn Tĩnh (03_frameworks_languages.md)](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/03_frameworks_languages.md)**
    *   Đánh giá an toàn các framework: **Laravel** (Horizon, App_Key, Ignition RCE), **Spring Boot** (Actuators, SpEL), **Next.js**, **Node.js** (Prototype Pollution), **ASP.NET** (ViewState), và **SharePoint**.
    *   Bảng tra cứu các lệnh **`grep` kiểm thử hộp trắng (White-box SAST)** tìm lỗi trong mã nguồn của 6 ngôn ngữ: PHP, Python, JavaScript, Go, Ruby, và Rust.
4.  **[04. Bảo Mật Hạ Tầng Doanh Nghiệp, CI/CD & Đám Mây (04_infra_cloud_cicd.md)](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/04_infra_cloud_cicd.md)**
    *   Tấn công hệ thống định danh: **Okta**, **M365 & Entra ID** (Azure AD).
    *   Khai thác lỗ hổng thiết bị đầu cuối: **VMware vCenter** và **SSL VPN** (Fortinet, Palo Alto, Ivanti...).
    *   Bảo mật chuỗi cung ứng **GitHub Actions CI/CD** (Expression Injection, Untrusted Checkout, Cache Poisoning).
    *   Leo thang đặc quyền đám mây (**AWS, Azure, GCP IAM Privilege Escalation**).
    *   Kiểm thử bảo mật **Smart Contracts** (Solidity/Foundry) và ứng dụng di động **Android APK**.
5.  **[05. Hướng Dẫn Cài Đặt Các Công Cụ Kiểm Thử (05_tools_installation.md)](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/05_tools_installation.md)**
    *   Hướng dẫn lệnh tải và cài đặt các công cụ: `subfinder`, `httpx`, `katana`, `naabu`, `nuclei`, `dnsx`, `interactsh`, `notify`, `anew`, `gau`, `uro`, `trufflehog`, `arjun`, `ghauri`, `sqlmap`, `ffuf`, `sisakulint`, `jadx`, `frida`, `foundry`.
    *   Cách khởi chạy các môi trường lab thực hành cục bộ bằng Docker (Juice Shop, DVWA).

---

## 🗺️ LỘ TRÌNH TỰ HỌC BẢO MẬT TỪ CON SỐ 0

Để biến bộ tài liệu này thành lộ trình học tập, bạn hãy làm theo các bước phân chia theo tuần như sau:

### Tuần 1-2: Kiến thức mạng cơ bản & Sử dụng Burp Suite
*   **Mục tiêu:** Hiểu cách trình duyệt gửi dữ liệu lên máy chủ và cách bắt request.
*   **Nội dung cần đọc:**
    *   Đọc kỹ tệp [01_methodology_triage.md](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/01_methodology_triage.md) phần hướng dẫn chạy `cbh` CLI và kết nối proxy.
    *   Mở phần mềm **Burp Suite**, thực hành bắt và chỉnh sửa request của chính bạn trong mục Proxy -> HTTP History.
*   **Thực hành:** Cài đặt Docker và khởi chạy phòng lab **Juice Shop** hoặc **DVWA**:
    ```bash
    docker run -d -p 3000:3000 bkimminich/juice-shop
    ```

### Tuần 3-6: Làm chủ các lỗ hổng Web cốt lõi (OWASP Top 10)
*   **Mục tiêu:** Hiểu nguyên lý và biết cách tự tay khai thác các lỗi web thông dụng.
*   **Nội dung cần đọc:**
    *   Mở tệp [02_web_vulnerabilities.md](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/02_web_vulnerabilities.md) làm tài liệu tra cứu chính.
    *   Học lần lượt theo thứ tự: **IDOR** (hiểu về phân quyền) ➔ **XSS** (hiểu về tương tác client) ➔ **SQL Injection** (hiểu về tương tác cơ sở dữ liệu) ➔ **SSRF & XXE** (hiểu về tương tác mạng nội bộ).
*   **Thực hành:** Tìm kiếm và giải quyết các thử thách tương ứng trên phòng lab Juice Shop.

### Tuần 7-9: Kiểm thử hộp trắng (White-box) & Cấu hình Framework
*   **Mục tiêu:** Học cách đọc mã nguồn của lập trình viên để tìm ra lỗi trước khi ứng dụng chạy.
*   **Nội dung cần đọc:**
    *   Tệp [03_frameworks_languages.md](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/03_frameworks_languages.md).
    *   Học cách chạy lệnh `grep` để tìm kiếm các hàm nguy hiểm trong mã nguồn của dự án thực tế.
    *   Tìm hiểu cấu hình sai trên các framework phổ biến (Spring Boot Actuator, Laravel Debug Mode).

### Tuần 10-12: Tấn công hạ tầng, CI/CD và Đám mây
*   **Mục tiêu:** Học cách chiếm quyền kiểm soát toàn bộ máy chủ doanh nghiệp và hạ tầng Cloud sau khi đã có được tài khoản hoặc API key ban đầu.
*   **Nội dung cần đọc:**
    *   Tệp [04_infra_cloud_cicd.md](file:///d:/Backup_Nguyen/Workspaces/Sercurity/Claude-BugHunter/cheatseat/04_infra_cloud_cicd.md).
    *   Học cách rải mật khẩu (Password Spraying) doanh nghiệp, khai thác lỗi trên GitHub Actions để đánh cắp Secrets, và leo thang đặc quyền AWS/Azure/GCP IAM.

---

## 🌳 CÂY QUYẾT ĐỊNH QUY TRÌNH HACK TỔNG QUAN

Mỗi khi tiếp cận một mục tiêu kiểm thử mới, hãy di chuyển theo các nhánh quyết định sau:

```
[BẮT ĐẦU KIỂM THỬ MỤC TIÊU]
  │
  ├── 1. Xác định luật chơi (Scope): Host X có trong Scope được phép hack không?
  │     ├── Không ➔ DỪNG LẠI NGAY LẬP TỨC.
  │     └── Có ➔ Bước tiếp theo.
  │
  ├── 2. Trinh sát (Recon): Tìm kiếm dịch vụ đang chạy trên Host X.
  │     ├── Có cổng quản trị mở (Jenkins, vCenter, VPN, Spring Actuator, WordPress)?
  │     │     └── [NHÁNH A]: Tra cứu CVE tương ứng và thử cấu hình mặc định.
  │     └── Chỉ hiển thị trang web thông thường?
  │           └── [NHÁNH B]: Tải các file JavaScript tĩnh để tìm API ẩn.
  │
  ├── 3. Phân loại tham số đầu vào (Hunt):
  │     ├── Có tham số dạng ID (như `invoice_id=99`)? ➔ Test lỗi phân quyền [IDOR].
  │     ├── Có tham số nhận URL (như `url=https://...`)? ➔ Test lỗi truy cập mạng [SSRF].
  │     ├── Có ô tìm kiếm/sắp xếp dữ liệu (như `sort=`)? ➔ Test lỗi cơ sở dữ liệu [SQLi].
  │     ├── Có chức năng tải lên file? ➔ Test lỗi thực thi mã độc [File Upload Webshell].
  │     └── Có các trường văn bản phản chiếu lên giao diện? ➔ Test lỗi chèn script [XSS].
  │
  ├── 4. Xác minh lỗi (Validate): Lỗ hổng có đọc được dữ liệu thật hoặc thay đổi trạng thái thật không?
  │     ├── Không (Chỉ là lỗi lý thuyết hoặc trang báo lỗi 500 thông thường) ➔ FALSE POSITIVE. Bỏ qua.
  │     └── Có ➔ Vượt qua Cổng 7 Câu Hỏi (7-Question Gate) và tiến hành chụp ảnh minh chứng an toàn (Redact Cookie/PII).
  │
  └── 5. Báo cáo (Report): Chọn mẫu báo cáo thích hợp (HackerOne, Bugcrowd) để nộp lỗi.
```
