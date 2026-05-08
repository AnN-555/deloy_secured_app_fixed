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

### Code vulnerable (SCENARIOS.md:25-26)

**routes/auth.js:16**
```js
// ❌ Vulnerable: string concatenation
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.get(query, (err, user) => { ... });
```

**routes/auth.js:33**
```js
// ❌ Vulnerable: password stored as plaintext
db.get(`SELECT id FROM users WHERE username = ?`, [username], ...);
db.run(`INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, 'user', 100)`,
  [username, password, email], ...); // password không hash
```

**routes/user.js:214**
```js
// ❌ Vulnerable: direct interpolation vào LIKE
const sql = `SELECT * FROM drinks WHERE name LIKE '%${q}%'`;
```

### Code fixed

**routes/auth.js:21-37**
```js
// ✅ Fixed: parameterized query + bcrypt compare
db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
  if (err || !user) {
    return res.render('auth/login', { error: 'Invalid credentials' });
  }
  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) {
      return res.render('auth/login', { error: 'Invalid credentials' });
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    req.session.email = user.email;
    return res.redirect('/user/dashboard');
  });
});
```

**routes/user.js:28-51** (menu search)
```js
// ✅ Fixed: parameterized query với LIKE
let sql = 'SELECT * FROM drinks WHERE 1=1';
let params = [];

if (category !== 'all') {
  sql += ' AND category = ?';
  params.push(category);
}

if (search) {
  sql += ' AND name LIKE ?';
  params.push(`%${search}%`);
}

db.all(sql, params, (err, drinks) => { ... });
```

**routes/user.js:235-246** (dedicated search endpoint)
```js
// ✅ Fixed: parameterized query
router.post('/search', requireAuth, (req, res) => {
  const { q } = req.body;
  const db = req.db;
  const sql = 'SELECT * FROM drinks WHERE name LIKE ?';
  const param = `%${q}%`;
  db.all(sql, [param], (err, drinks) => { ... });
});
```

---

## A2 — Broken Authentication & Session Management

### Code vulnerable

**server.js:17-22**
```js
// ❌ Vulnerable: hardcoded secret, httpOnly only
app.use(session({
  secret: 'devsecret',  // hardcoded — dễ brute-force
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 3600000 }  // httpOnly only, secure không set
}));
```

**routes/auth.js:14-16** (login)
```js
// ❌ Vulnerable: plaintext password compare
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**routes/auth.js:70-71** (forgot password)
```js
// ❌ Vulnerable: token = base64(username) — trivially reversible
const token = Buffer.from(username).toString('base64');
const resetLink = `http://localhost:3000/reset-password?token=${token}`;
```

**routes/auth.js:90-91** (reset password)
```js
// ❌ Vulnerable: decode token, update password — không verify, không expiry
const username = Buffer.from(token, 'base64').toString('utf8');
const sql = `UPDATE users SET password = '${newPassword}' WHERE username = '${username}'`;
```

### Code fixed

**server.js:10,19-29**
```js
// ✅ Fixed: random secret từ crypto
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 3600000,
    httpOnly: true,
    secure: false,  // true in production
    sameSite: 'lax'
  }
}));
```

**routes/auth.js:57-68** (register)
```js
// ✅ Fixed: bcrypt hash password
bcrypt.hash(password, 10, (err, hash) => {
  if (err) {
    return res.render('auth/register', { error: 'Registration failed' });
  }
  db.run('INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)',
    [username, hash, email, 'user', 100], (err) => { ... });
});
```

**routes/auth.js:82-91** (forgot password)
```js
// ✅ Fixed: no user enumeration — always show "email sent"
router.post('/forgot-password', (req, res) => {
  const { username } = req.body;
  const db = req.db;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    // Không reveal username exists — luôn render sent: true
    res.render('auth/forgot-password', { error: null, sent: true });
  });
});
```

**routes/auth.js:100-116** (reset password disabled)
```js
// ✅ Fixed: password reset disabled for security
router.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.render('auth/reset-password', {
      error: 'Password must be at least 6 characters',
      success: null, token
    });
  }
  res.render('auth/reset-password', {
    error: null,
    success: 'Password reset is disabled for security',
    token
  });
});
```

### So sánh lưu trữ Password: Plaintext vs bcrypt

#### Vulnerable App — Plaintext

```js
// server.js:84-86 (vulnerable)
stmtInsertUser.run('admin', 'admin123', 'admin', 'admin@milktea.com', 99999);
stmtInsertUser.run('user1', 'password1', 'user', 'user1@milktea.com', 1000);
stmtInsertUser.run('user2', 'password2', 'user', 'user2@milktea.com', 500);
```

**Database lưu trữ:**
| id | username | password | role |
|----|----------|----------|------|
| 1 | admin | `admin123` | admin |
| 2 | user1 | `password1` | user |
| 3 | user2 | `password2` | user |

→ **Plaintext** — ai đọc được DB là biết ngay mật khẩu

#### Secured App — bcrypt Hash

```js
// server.js:109-115 (secured)
const bcrypt = require('bcryptjs');
const salt = bcrypt.genSaltSync(10);

stmtInsertUser.run('admin', bcrypt.hashSync('admin123', salt), 'admin', ...);
stmtInsertUser.run('user1', bcrypt.hashSync('password1', salt), 'user', ...);
stmtInsertUser.run('user2', bcrypt.hashSync('password2', salt), 'user', ...);
```

**Database lưu trữ:**
| id | username | password | role |
|----|----------|----------|------|
| 1 | admin | `$2a$10$N9qo8uLOickgx2ZMRZoHK.bn4pTqlHKbE9x5R9z3FxJaXj8Z2JYKq` | admin |
| 2 | user1 | `$2a$10$Xv4HD8Y7RsH9Z5d7Z5Y8LO4yU6Yp3VVT6N3K9Z5Y8Z4Z5Y8Z4Y8` | user |
| 3 | user2 | `$2a$10$Yx5WT9Z8T1H8Y6d6Z4X7Y9M6Z5Y6X8W7V6U5T4S3R2Q1P0O9N8M7` | user |

→ **bcrypt hash** — không thể đọc ra mật khẩu gốc

#### Cách bcrypt hoạt động

```
Input password: "admin123"
         │
         ▼
   bcrypt.hash(password, saltRounds=10)
         │
         ▼
   Output: $2a$10$N9qo8uLOickgx2ZMRZoHK.bn4pTqlHKbE9x5R9z3FxJaXj8Z2JYKq
```

**Cấu trúc hash bcrypt:**
| Thành phần | Giải thích |
|------------|------------|
| `$2a$` | Algorithm identifier (bcrypt) |
| `10$` | Cost factor (2^10 = 1024 iterations) |
| `N9qo8uLOickgx2ZMRZoHK.` | 22-char salt (random, unique mỗi lần hash) |
| `bn4pTqlHKbE9x5R9z3FxJaXj8Z2JYKq` | 31-char hash (derived from password + salt) |

**Đặc điểm quan trọng của bcrypt:**
1. **Salt random** — cùng password hash mỗi lần sẽ ra kết quả khác nhau
2. **One-way** — không thể đảo ngược để ra password gốc
3. **Slow by design** — designed to be expensive to compute (chống brute force)

#### So sánh chi tiết

| Yếu tố | Plaintext | bcrypt |
|---------|-----------|--------|
| Đọc DB trực tiếp | Biết ngay password | Không đọc được |
| Rainbow table attack | Crack ngay lập tức | Không áp dụng (đã có salt) |
| Brute force | Nhanh (MD5/SHA1 speed) | Chậm (10^3-10^6 lần chậm hơn) |
| User reuse password | Dùng lại được | Không ảnh hưởng (vì hash khác nhau) |
| Server breach | Passwords bị lộ hoàn toàn | Passwords vẫn an toàn (nếu cost factor đủ cao) |

#### Cách login so sánh

```js
// Vulnerable: so sánh trực tiếp plaintext
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
if (password === user.password) { /* login */ }

// Secured: dùng bcrypt.compare (hash rồi so sánh)
bcrypt.compare(password, user.password, (err, result) => {
  if (result) { /* login */ }
});
```

`bcrypt.compare()` thực hiện:
1. Hash password nhập vào với salt từ hash trong DB
2. So sánh hash kết quả với hash trong DB
3. Không bao giờ so sánh plaintext

#### Tấn công có thể trên bản plaintext

| Tấn công | Kết quả |
|----------|---------|
| SQL Injection dump DB | Đọc toàn bộ password |
| DB backup leak | Passwords bị lộ hoàn toàn |
| Insider threat | Passwords visible |
| Same password across sites | Attacker thử password trên site khác |

---

## A3 — Cross-Site Scripting (Stored XSS)

### Code vulnerable

**routes/vuln.js:68-76**
```js
// ❌ Vulnerable: string interpolation + raw HTML output
const sql = `INSERT INTO reviews (user_id, name, comment, rating, created_at)
             VALUES (${userId}, '${name}', '${comment}', 5, datetime('now'))`;
db.run(sql, ...);
const output = `Thank you <strong>${name}</strong> for your review!<br><em>${comment}</em>`;
res.render('vuln/xss', { output, name, comment });
```

**views/user/reviews.ejs:53-54**
```html
<!-- ❌ Vulnerable: <%- renders raw HTML -->
<div style="color:var(--text);line-height:1.7;"><%- r.comment %></div>
```

### Code fixed

**routes/user.js:212-226**
```js
// ✅ Fixed: parameterized INSERT query
router.post('/reviews', requireAuth, (req, res) => {
  const { comment } = req.body;
  const db = req.db;
  const userId = req.session.userId;

  db.run(`INSERT INTO reviews (user_id, name, comment, rating, created_at) VALUES (?, ?, ?, ?, datetime('now'))`,
    [userId, req.session.username, comment, 5], (err) => {
      if (err) console.error(err);
      res.redirect('/user/reviews');
    });
});
```

**views/user/reviews.ejs:47**
```html
<!-- ✅ Fixed: <%= escapes HTML -->
<div style="color:var(--text);line-height:1.7;"><%= r.comment %></div>
```

---

## A4 — Insecure Direct Object Reference (IDOR)

### Code vulnerable

**routes/user.js:121-136**
```js
// ❌ Vulnerable: không có ownership check
router.get('/order/:id', requireAuth, (req, res) => {
  db.get(
    `SELECT o.*, u.username AS owner_username FROM orders o
     JOIN users u ON o.user_id = u.id WHERE o.id = ?`,
    [req.params.id],  // attacker có thể thay đổi order ID
    (err, order) => {
      if (!order) return res.status(404).send('Order not found');
      db.all(`SELECT oi.*, d.name, d.image FROM order_items oi ...`, [order.id], (err, items) => {
        res.render('user/order-detail', { order, items, currentUserId: req.session.userId });
        // KHÔNG kiểm tra order.user_id === req.session.userId
      });
    }
  );
});
```

### Code fixed

**routes/user.js:122-145**
```js
// ✅ Fixed: ownership check + admin bypass
router.get('/order/:id', requireAuth, (req, res) => {
  const db = req.db;
  const orderId = parseInt(req.params.id);

  db.get(
    `SELECT o.*, u.username AS owner_username FROM orders o
     JOIN users u ON o.user_id = u.id WHERE o.id = ?`,
    [orderId],
    (err, order) => {
      if (!order) return res.status(404).send('Order not found');

      // ✅ Fixed: ownership check
      if (order.user_id !== req.session.userId && req.session.role !== 'admin') {
        return res.status(403).send('Access denied: You do not own this order');
      }

      db.all(`SELECT oi.*, d.name, d.image FROM order_items oi
              JOIN drinks d ON oi.drink_id = d.id
              WHERE oi.order_id = ?`, [orderId], (err, items) => {
        res.render('user/order-detail', { order, items, currentUserId: req.session.userId, user: req.session });
      });
    }
  );
});
```

---

## A5 — Security Misconfiguration

### Code vulnerable

**server.js:108-120** (app_config table)
```js
// ❌ Vulnerable: secrets stored in DB, exposed via /vuln/config
dbconn.exec(`CREATE TABLE IF NOT EXISTS app_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  value TEXT
)`);

const stmtInsertConfig = dbconn.prepare(`INSERT OR IGNORE INTO app_config (name, value) VALUES (?, ?)`);
stmtInsertConfig.run('db_host', 'localhost');
stmtInsertConfig.run('db_user', 'root');
stmtInsertConfig.run('db_pass', 'password123');      // ❌ lộ DB password
stmtInsertConfig.run('api_key', 'sk_live_secret_key_12345');  // ❌ lộ API key
stmtInsertConfig.run('admin_email', 'admin@milktea.com');
stmtInsertConfig.run('debug_mode', 'true');
```

**server.js:143-158** (debug endpoint)
```js
// ❌ Vulnerable: /debug endpoint — không cần auth, lộ session_secret
app.get('/debug', (req, res) => {
  res.json({
    status: 'ok',
    session_secret: 'devsecret',  // ❌ lộ session secret
    db_path: require('path').resolve('./data.db'),  // ❌ lộ DB path
    ...
  });
});
```

**routes/vuln.js:92-105**
```js
// ❌ Vulnerable: /vuln/config — lộ toàn bộ app_config
router.get('/config', requireAuth, (req, res) => {
  db.all('SELECT name, value FROM app_config', [], (err, configs) => {
    res.render('vuln/config', { configs: configs || [], responseHeaders });
  });
});
```

### Code fixed

**server.js:31-38**
```js
// ✅ Fixed: security headers added
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  next();
});
```

**server.js:133-139**
```js
// ✅ Fixed: /debug endpoint removed, /vuln/* routes removed
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');
// ❌ vulnRoutes removed — no /vuln/* routes

app.use('/', authRoutes);
app.use('/user', userRoutes);
app.use('/admin', adminRoutes);
// ✅ /debug endpoint completely removed
```

---

## A6 — Sensitive Data Exposure

### Code vulnerable

**server.js:161-166** (api/profile)
```js
// ❌ Vulnerable: returns entire user object including password
app.get('/api/profile', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  dbconn.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    res.json(user || {});  // ❌ password in response
  });
});
```

**server.js:169-173** (api/users)
```js
// ❌ Vulnerable: no auth required, returns all users + passwords
app.get('/api/users', (req, res) => {
  dbconn.all('SELECT * FROM users', [], (err, users) => {
    res.json(users || []);  // ❌ all passwords exposed
  });
});
```

**routes/vuln.js:108-113** (vuln/data)
```js
// ❌ Vulnerable: renders plaintext passwords in table
router.get('/data', requireAuth, (req, res) => {
  db.all('SELECT id, username, password, email, role, balance FROM users', [], (err, users) => {
    res.render('vuln/data', { users: users || [] });  // ❌ password in table
  });
});
```

### Code fixed

**server.js:145-147**
```js
// ✅ Fixed: /api/* endpoints completely removed
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});
```

**routes/vuln.js removed completely** — no `/vuln/*` routes in secured version.

---

## Bảng tổng hợp Fix

| ID | File (Vulnerable) | Dòng | Lỗ hổng | Fix |
|----|-------------------|------|----------|-----|
| A1 | `routes/auth.js` | 16 | String concatenation SQL | Parameterized `?` placeholder |
| A1 | `routes/user.js` | 214 | `LIKE '%${q}%'` | Parameterized `LIKE ?` |
| A2 | `server.js` | 18 | `secret: 'devsecret'` | `crypto.randomBytes(64)` |
| A2 | `routes/auth.js` | 16 | Plaintext password compare | `bcrypt.compare()` |
| A2 | `routes/auth.js` | 70-71 | `base64(username)` token | Reset disabled |
| A2 | `routes/auth.js` | 60-67 | User enumeration | Always show "email sent" |
| A3 | `views/user/reviews.ejs` | 54 | `<%- r.comment %>` raw HTML | `<%= r.comment %>` escaped |
| A3 | `routes/vuln.js` | 72-73 | String interpolation INSERT | Parameterized INSERT |
| A4 | `routes/user.js` | 121-136 | No ownership check | Check `order.user_id !== req.session.userId` |
| A5 | `server.js` | 143-158 | `/debug` endpoint | Removed |
| A5 | `server.js` | 108-120 | `app_config` table | Removed |
| A5 | `routes/vuln.js` | 92-105 | `/vuln/config` | Removed |
| A6 | `server.js` | 161-166 | `/api/profile` returns password | Removed |
| A6 | `server.js` | 169-173 | `/api/users` no auth | Removed |
| A6 | `routes/vuln.js` | 108-113 | `/vuln/data` plaintext passwords | Removed |

---

## Tính năng mới thêm

**Admin User Management:**
- `routes/admin.js` — Edit role, balance, delete users

**Profile link trên navbar**

