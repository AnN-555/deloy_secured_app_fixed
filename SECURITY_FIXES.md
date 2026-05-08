# Security Fixes — Milk Tea Shop Secured Version

## A1 — SQL Injection

### Problem
String concatenation in SQL queries allowed attackers to inject malicious SQL.

```js
// Vulnerable
const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

### Fix
Use parameterized queries with `?` placeholders:

```js
// Fixed
db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, user) => {});
```

### Files Changed
- `routes/auth.js:16` — login query
- `routes/auth.js:33` — register check
- `routes/user.js:211` — search query

---

## A2 — Broken Authentication & Session Management

### Problems
1. Plaintext password storage and comparison
2. Weak hardcoded session secret `devsecret`
3. Session cookie without security flags
4. Predictable password reset token (base64 of username)
5. No brute force protection

### Fixes

**Password Hashing:**
```js
// Register — hash password with bcrypt
bcrypt.hash(password, 10, (err, hash) => {
  db.run('INSERT INTO users ... VALUES (?, ?, ?, ?, ?)', [username, hash, email, 'user', 100]);
});

// Login — compare with bcrypt
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
// Reset password functionality disabled for security
res.render('auth/reset-password', {
  success: 'Password reset is disabled for security'
});
```

**Forgot Password — No User Enumeration:**
```js
// Always show "email sent" regardless of username existence
res.render('auth/forgot-password', { sent: true });
```

---

## A3 — Cross-Site Scripting (XSS)

### Problem
User input rendered as raw HTML without escaping.

```html
<!-- Vulnerable: raw HTML -->
<%- r.comment %>
```

### Fix
Use escaped output in all user-facing templates:

```html
<!-- Fixed: escaped HTML -->
<%= r.comment %>
```

### Files Changed
- `views/user/reviews.ejs` — all user comments use `<%=`
- `views/user/menu.ejs` — drink names escaped

---

## A4 — Insecure Direct Object Reference (IDOR)

### Problem
Users could access other users' orders by changing the ID in URL.

```js
// Vulnerable: no ownership check
db.get('SELECT * FROM orders WHERE id = ?', [req.params.id], (err, order) => {});
```

### Fix
Verify order ownership before returning data:

```js
// Fixed: ownership check
db.get('SELECT * FROM orders WHERE id = ?', [orderId], (err, order) => {
  if (order.user_id !== req.session.userId && req.session.role !== 'admin') {
    return res.status(403).send('Access denied: You do not own this order');
  }
});
```

### Files Changed
- `routes/user.js:121-137` — order detail endpoint

---

## A5 — Security Misconfiguration

### Problems
1. `/debug` endpoint exposed `session_secret` and DB path publicly
2. `app_config` table stored hardcoded secrets
3. Missing security headers

### Fixes

**Removed `/debug` endpoint:**
```js
// Removed — was exposing secrets
// app.get('/debug', ...)
```

**Removed `app_config` table and `/vuln/config` route:**
```js
// Removed from server.js:
// - app_config table creation
// - stmtInsertConfig for secrets
// - /vuln/config route
```

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

### Files Changed
- `server.js` — removed `/debug`, removed `app_config` table, added headers

---

## A6 — Sensitive Data Exposure

### Problems
1. `/api/users` returned all users with plaintext passwords — no auth required
2. `/api/profile` returned password in JSON response
3. `/vuln/data` page showed plaintext passwords

### Fixes

**Removed Vulnerable Endpoints:**
```js
// Removed from server.js:
// - /api/users (no auth, exposed all passwords)
// - /api/profile (included password in response)

// Removed from routes:
// - /vuln/data (showed plaintext passwords)
// - /vuln/* (all vuln lab pages removed)
```

**API Now Returns Safe Data:**
```js
// Profile only returns safe fields
db.get('SELECT id, username, email, role, balance FROM users WHERE id = ?', [req.session.userId]);
```

**Removed `/vuln` Routes Entirely:**
```js
// Removed from server.js:
// const vulnRoutes = require('./routes/vuln');
// app.use('/vuln', vulnRoutes);
```

---

## Summary of Changes

| File | Changes |
|------|---------|
| `server.js` | Security headers, secure session, removed debug/API endpoints, removed app_config |
| `routes/auth.js` | bcrypt hashing, parameterized queries, disabled reset token |
| `routes/user.js` | Parameterized queries, ownership check for orders |
| `routes/admin.js` | Admin-only access control |
| `views/` | All use `<%=` for user input (XSS protection) |

## Test Accounts (Same as Vulnerable Version)

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| user1 | password1 | user |
| user2 | password2 | user |

**Note:** Passwords are hashed with bcrypt — same plaintext passwords but stored securely.
