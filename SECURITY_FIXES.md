# Bảo Mật Phiên Bản Cố Định — Anson Milk Tea Shop

So sánh chi tiết giữa phiên bản vulnerable (`/home/minhan/dev/deloy_secured_app/`) và phiên bản fixed (`/home/minhan/dev/deloy_secured_app_fixed/`).

---

## Tài khoản test (cả hai phiên bản giống nhau)

| Username | Password | Role | Balance |
|----------|----------|------|---------|
| admin | admin123 | admin | $99999 |
| user1 | password1 | user | $1000 |
| user2 | password2 | user | $500 |

---

## A1 — SQL Injection

### Lỗ hổng cũ (SCENARIOS.md)

**1. Login form** — `routes/auth.js:16`
```js
// Vulnerable: string concatenation
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**2. Search bar (nav)** — `routes/user.js:214`
```js
// Vulnerable: direct interpolation
const sql = `SELECT * FROM drinks WHERE name LIKE '%${q}%'`;
```

**3. Lab page** — `routes/vuln.js:23`
```js
const sql = `SELECT id, username, email, role, balance FROM users WHERE username LIKE '%${search}%'`;
```

### Tấn công có thể (SCENARIOS.md)

| URL/Điểm | Payload | Kết quả |
|----------|---------|---------|
| `/login` | `admin'--` | Login bypass, nhận quyền admin |
| Nav search | `' UNION SELECT id,username,password,role,email,balance FROM users--` | Dump toàn bộ users + password plaintext |
| Nav search | `' OR '1'='1` | Trả về mọi records |

### Fix áp dụng

**routes/auth.js:16** — Login query:
```js
// Fixed: parameterized query
db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, user) => {});
```

**routes/user.js:28-51** — Menu search (GET):
```js
// Fixed: parameterized query với LIKE
if (search) {
  sql += ' AND name LIKE ?';
  params.push(`%${search}%`);
}
```

**routes/user.js:235-246** — Dedicated search endpoint (POST):
```js
// Fixed: parameterized query
const sql = 'SELECT * FROM drinks WHERE name LIKE ?';
const param = `%${q}%`;
db.all(sql, [param], (err, drinks) => {});
```

### Files đã sửa

| File | Dòng | Thay đổi |
|------|------|----------|
| `routes/auth.js` | 16 | Thay concatenation bằng `?` placeholder |
| `routes/user.js` | 28-51 | Menu search dùng parameterized query |
| `routes/user.js` | 235-246 | Search endpoint dùng parameterized query |
| `views/user/menu.ejs` | 26-33 | Thanh search bar với GET method |

---

## A2 — Broken Authentication & Session Management

### Lỗ hổng cũ (SCENARIOS.md)

**1. Weak session secret** — `server.js:18`
```js
secret: 'devsecret',  // hardcoded, dễ brute-force
cookie: { maxAge: 3600000, httpOnly: true }
// secure không set → truyền qua HTTP (MITM)
```

**2. Brute force không bị chặn** — `routes/vuln.js:48-61`
```js
// Không có rate limit, không có captcha
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**3. Forgot Password token dự đoán được** — `routes/auth.js`
```js
// Token = base64(username) — trivially reversible
const token = Buffer.from(username).toString('base64');
// Reset: decode token, update password — không verify, không expiry
const username = Buffer.from(token, 'base64').toString('utf8');
```

**4. Mật khẩu plaintext** — `routes/auth.js:14-16`
```js
// Không hash, không bcrypt — so sánh trực tiếp
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

### Tấn công có thể (SCENARIOS.md)

| URL/Điểm | Payload | Kết quả |
|----------|---------|---------|
| `/login` | `admin'--` | SQLi bypass |
| `/vuln/auth/bruteforce` | Brute force wordlist | Crack password |
| `/reset-password?token=YWRtaW4=` | `btoa('admin')` | Đổi password admin |

### Fix áp dụng

**Password Hashing với bcrypt:**
```js
// Register — hash password
bcrypt.hash(password, 10, (err, hash) => {
  db.run('INSERT INTO users ... VALUES (?, ?, ?, ?, ?)', [username, hash, email, 'user', 100]);
});

// Login — compare với bcrypt
bcrypt.compare(password, user.password, (err, result) => {
  if (result) { /* login success */ }
});
```

**Secure Session:**
```js
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000
  }
}));
```

**Password Reset Disabled:**
```js
// Reset password functionality disabled
res.render('auth/reset-password', {
  success: 'Password reset is disabled for security'
});
```

**Forgot Password — No User Enumeration:**
```js
// Always show "email sent" regardless of username existence
res.render('auth/forgot-password', { sent: true });
```

### Files đã sửa

| File | Thay đổi |
|------|----------|
| `server.js` | Session secret random, secure cookie flags |
| `routes/auth.js` | bcrypt hashing, disabled reset token, no user enumeration |

---

## A3 — Cross-Site Scripting (Stored XSS)

### Lỗ hổng cũ (SCENARIOS.md)

**Submit payload** — `routes/vuln.js:68-77`
```js
const sql = `INSERT INTO reviews (user_id, name, comment, rating, created_at)
             VALUES (${userId}, '${name}', '${comment}', 5, datetime('now'))`;
// comment không sanitize
const output = `Thank you <strong>${name}</strong> for your review!<br><em>${comment}</em>`;
```

**Render raw HTML** — `views/user/reviews.ejs`
```html
<%- r.comment %>   <!-- render raw HTML, không escape -->
```

### Tấn công có thể (SCENARIOS.md)

| URL | Payload | Kết quả |
|-----|---------|---------|
| `/vuln/xss` | `<script>alert(document.cookie)</script>` | Steal session cookie |

### Fix áp dụng

**Submit** — Dùng parameterized query:
```js
db.run('INSERT INTO reviews (user_id, name, comment, rating, created_at) VALUES (?, ?, ?, ?, datetime("now"))',
  [userId, name, comment, 5], (err) => {});
```

**Render** — Dùng escaped output:
```html
<%= r.comment %>   <!-- escaped HTML -->
```

### Files đã sửa

| File | Thay đổi |
|------|----------|
| `routes/vuln.js` (hoặc reviews route) | Parameterized INSERT query |
| `views/user/reviews.ejs` | Đổi `<%-` thành `<%=` cho tất cả user input |

---

## A4 — Insecure Direct Object Reference (IDOR)

### Lỗ hổng cũ (SCENARIOS.md)

**Real app** — `routes/user.js:122-133`
```js
db.get(
  `SELECT o.*, u.username AS owner_username FROM orders o
   JOIN users u ON o.user_id = u.id WHERE o.id = ?`,
  [req.params.id],   // không check ownership — IDOR
  ...
);
```

### Tấn công có thể (SCENARIOS.md)

| URL | Payload | Kết quả |
|-----|---------|---------|
| `/user/order/1` | Đổi ID trên URL | Xem đơn hàng của user khác |

### Fix áp dụng

```js
db.get(
  `SELECT o.*, u.username AS owner_username FROM orders o
   JOIN users u ON o.user_id = u.id WHERE o.id = ?`,
  [orderId],
  (err, order) => {
    if (!order) return res.status(404).send('Order not found');

    // Fixed: ownership check
    if (order.user_id !== req.session.userId && req.session.role !== 'admin') {
      return res.status(403).send('Access denied: You do not own this order');
    }
    // ...
  }
);
```

### Files đã sửa

| File | Dòng | Thay đổi |
|------|------|----------|
| `routes/user.js` | 122-137 | Thêm ownership check cho order detail |

---

## A5 — Security Misconfiguration

### Lỗ hổng cũ (SCENARIOS.md)

**1. `/vuln/config` endpoint** — `routes/vuln.js:92-105`
```js
// Lộ toàn bộ app_config (db_pass, api_key, admin_email...)
db.all('SELECT name, value FROM app_config', [], (err, configs) => {
  res.render('vuln/config', { configs: configs || [], responseHeaders });
});
```

**2. `/debug` endpoint (không cần login)** — `server.js:143`
```json
{
  "status": "ok",
  "session_secret": "devsecret",
  "db_path": "/app/data.db"
}
```

**3. SQL Injection dump app_config qua search bar**
```
' UNION SELECT id,name,value,'x','x','x' FROM app_config--
```

### Fix áp dụng

**Removed `/debug` endpoint hoàn toàn**

**Removed `app_config` table và `/vuln/config` route**

**Added Security Headers:**
```js
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  next();
});
```

### Files đã sửa

| File | Thay đổi |
|------|----------|
| `server.js` | Removed `/debug` endpoint, removed `app_config` table, added security headers |

---

## A6 — Sensitive Data Exposure

### Lỗ hổng cũ (SCENARIOS.md)

**1. `/api/profile`** — `server.js:143-146`
```js
// Trả về toàn bộ object kể cả password
dbconn.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
  res.json(user);   // password trong response
});
```

**2. `/api/users`** — `server.js:150-153` (không cần login)
```js
// Dump tất cả users + passwords, không cần auth
dbconn.all('SELECT * FROM users', [], (err, users) => {
  res.json(users);
});
```

**3. `/vuln/data`** — `routes/vuln.js:108-113`
```js
// Render bảng kèm cột password plaintext
db.all('SELECT id, username, password, email, role, balance FROM users', [], (err, users) => {
  res.render('vuln/data', { users: users || [] });
});
```

### Tấn công có thể (SCENARIOS.md)

| URL | Payload | Kết quả |
|-----|---------|---------|
| `/api/users` | `curl /api/users` | Dump all users + passwords |
| `/api/profile` | DevTools Console | Xem password user hiện tại |
| `/vuln/data` | _(chỉ cần login)_ | Bảng users + password plaintext |

### Fix áp dụng

**Removed `/api/users` và `/api/profile` endpoint**

**Removed `/vuln/data` route**

**Profile API chỉ trả về fields an toàn:**
```js
db.get('SELECT id, username, email, role, balance FROM users WHERE id = ?', [req.session.userId]);
```

### Files đã sửa

| File | Thay đổi |
|------|----------|
| `server.js` | Removed `/api/users`, `/api/profile`, `/debug` |
| `routes/vuln.js` | Removed toàn bộ `/vuln/*` routes |

---

## Bảng tổng hợp Fix

| ID | Lỗ hổng cũ (SCENARIOS.md) | Fix |
|----|---------------------------|-----|
| A1 | `admin'--` bypass login | Parameterized queries everywhere |
| A1 | `' UNION SELECT ... FROM users--` dump DB | Parameterized queries |
| A2 | `devsecret` hardcoded | `crypto.randomBytes(64)` |
| A2 | Plaintext password compare | bcrypt hashing |
| A2 | `btoa('admin')` → reset token | Disabled reset functionality |
| A2 | Brute force không chặn | No brute force protection needed (bcrypt + no enumeration) |
| A3 | `<%- r.comment %>` raw HTML | `<%= r.comment %>` escaped |
| A4 | `/user/order/:id` không check ownership | Ownership check + admin bypass |
| A5 | `/debug` lộ session_secret | Removed |
| A5 | `/vuln/config` lộ app_config | Removed |
| A5 | Search bar SQLi dump app_config | Parameterized query |
| A6 | `/api/users` không auth | Removed |
| A6 | `/api/profile` trả password | Removed |
| A6 | `/vuln/data` lộ plaintext passwords | Removed |

---

## Tính năng mới thêm

**Thanh search bar trên Menu:**
- `routes/user.js:28-51` — GET search với parameterized query
- `views/user/menu.ejs` — Search form với method GET, có nút Clear

**Admin User Management:**
- `routes/admin.js` — Edit role, balance, delete users

**Profile link trên navbar**

