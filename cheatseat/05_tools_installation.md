# 05. HƯỚNG DẪN CÀI ĐẶT CÁC CÔNG CỤ KIỂM THỬ (TOOLS INSTALLATION GUIDE)

Tài liệu này cung cấp danh sách lệnh tải và cài đặt chi tiết cho tất cả các công cụ bảo mật được sử dụng xuyên suốt bộ tài liệu kiểm thử. Hướng dẫn bao gồm các câu lệnh cài đặt trên các nền tảng phổ biến (Linux/macOS, Windows).

---

## 1. CÁC THƯ VIỆN & TRÌNH QUẢN LÝ GÓI TIÊN QUYẾT (PREREQUISITES)

Trước khi cài đặt các công cụ chuyên dụng, máy chủ/máy ảo kiểm thử của bạn cần cài đặt sẵn các môi trường chạy sau:

### Linux / Debian / Ubuntu:
```bash
sudo apt update && sudo apt install -y golang-go python3 python3-pip nodejs npm git curl build-essential libpcap-dev
```

### Windows (Sử dụng PowerShell Run as Administrator):
Khuyến khích cài đặt trình quản lý gói [Chocolatey](https://chocolatey.org/) để cài đặt nhanh:
```powershell
# Cài đặt các môi trường qua Chocolatey
choco install -y golang python nodejs git curl jadx
```

---

## 2. CÀI ĐẶT CÁC CÔNG CỤ CỦA PROJECTDISCOVERY

Hầu hết các công cụ của ProjectDiscovery được viết bằng ngôn ngữ Go. Cách cài đặt nhanh nhất là sử dụng lệnh `go install`.

| Công cụ | Lệnh cài đặt (Linux / macOS / Windows Go) | Lệnh cài đặt qua Binary / Package Manager |
|---|---|---|
| **subfinder** | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `sudo apt install subfinder` (Hoặc `brew install subfinder`) |
| **httpx** | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` | `brew install httpx` |
| **katana** | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | `brew install katana` |
| **naabu** | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | Yêu cầu `libpcap-dev` trên Linux trước khi chạy |
| **nuclei** | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | `brew install nuclei` |
| **dnsx** | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` | `brew install dnsx` |
| **interactsh-client** | `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` | Tải client tương tác ngoài băng tần OOB |
| **notify** | `go install -v github.com/projectdiscovery/notify/cmd/notify@latest` | Dùng để bắn thông báo kết quả |

---

## 3. CÁC CÔNG CỤ TRINH SÁT & ĐÀO BỚI THÔNG TIN (RECON & CRAWLING)

### anew (Gộp tệp lọc trùng)
```bash
go install github.com/tomnomnom/anew@latest
```

### assetfinder (Tìm subdomain thụ động phụ)
```bash
go install github.com/tomnomnom/assetfinder@latest
```

### gau (Get All URLs từ archive)
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

### waybackurls (Lấy URL lịch sử từ Wayback Machine)
```bash
go install github.com/tomnomnom/waybackurls@latest
```

### uro (Lọc trùng lặp cấu trúc tham số URL)
Yêu cầu Python 3:
```bash
pip3 install uro
# Hoặc cài đặt trực tiếp từ kho mã nguồn
pip3 install git+https://github.com/s0md3v/uro.git
```

### jsluice (Trích xuất URL/Secrets từ tệp JS tĩnh)
```bash
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
```

### trufflehog (Quét rò rỉ secrets và API Keys)
```bash
# Cài đặt qua script tự động (Linux/macOS)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Cài đặt qua Homebrew (macOS)
brew install trufflehog
```

### SecretFinder (Python tool quét secrets trong JS)
```bash
git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder
cd /opt/SecretFinder
pip3 install -r requirements.txt
# Tạo liên kết tượng trưng để chạy nhanh từ terminal
sudo ln -s /opt/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder
```

### subzy (Quét lỗi Subdomain Takeover)
```bash
go install -v github.com/LukaSikic/subzy@latest
```

---

## 4. CÔNG CỤ SĂN TÌM LỖ HỔNG & KHAI THÁC (HUNT & EXPLOIT)

### arjun (Dò tìm tham số ẩn)
```bash
pip3 install arjun
# Hoặc cài qua pipx (khuyên dùng để tránh xung đột môi trường Python)
pipx install arjun
```

### ghauri (Khai thác lỗi SQL Injection nâng cao)
```bash
pip3 install ghauri
# Hoặc cài qua kho mã nguồn
pip3 install git+https://github.com/r0oth3x49/ghauri.git
```

### sqlmap (Khai thác lỗi SQL Injection tự động)
```bash
# Cài đặt trên Linux
sudo apt install -y sqlmap
# Hoặc qua Homebrew / Chocolatey
brew install sqlmap
choco install sqlmap
```

### ffuf (Brute force & Fuzzing tham số cực nhanh)
```bash
go install github.com/ffuf/ffuf/v2@latest
```

---

## 5. BẢO MẬT HẠ TẦNG, CI/CD, DI ĐỘNG & WEB3

### sisakulint (Quét lỗi file cấu hình CI/CD GitHub Actions)
```bash
go install github.com/cyberark/sisakulint@latest
```

### jadx (Dịch ngược file APK di động)
*   **macOS / Linux:** `brew install jadx`
*   **Windows:** `choco install jadx`
*   **Tải bản ZIP:** [Releases Page GitHub JADX](https://github.com/skylot/jadx/releases)

### Frida & Frida-tools (Kiểm thử động ứng dụng di động)
Yêu cầu Python:
```bash
pip3 install frida-tools
# Tải frida-server khớp phiên bản về điện thoại/giả lập Android qua:
# https://github.com/frida/frida/releases
```

### Foundry (Kiểm thử an toàn Smart Contracts Solidity)
```bash
# Trình cài đặt tự động (Linux/macOS)
curl -L https://foundry.paradigm.xyz | bash
# Khởi động lại terminal và chạy lệnh để nạp Foundry
foundryup
```
Đối với Windows:
```powershell
# Chạy trong PowerShell
curl -L https://foundry.paradigm.xyz | iwr -useb | iex
foundryup
```

---

## 6. KHỞI CHẠY LAB THỰC HÀNH CỤC BỘ (LAB DOCKER)

Để thực hành các kỹ năng trong cheat sheet mà không làm ảnh hưởng đến hệ thống thật, bạn nên chạy các lab cục bộ bằng Docker.

### Cài đặt Docker:
*   **Ubuntu:** `sudo apt install docker.io docker-compose`
*   **macOS/Windows:** Tải [Docker Desktop](https://www.docker.com/products/docker-desktop/).

### Khởi chạy phòng Lab OWASP Juice Shop:
```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
# Truy cập lab tại: http://localhost:3000
```

### Khởi chạy phòng Lab DVWA (Damn Vulnerable Web Application):
```bash
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa
# Truy cập lab tại: http://localhost (Mật khẩu/tài khoản mặc định: admin / password)
```
