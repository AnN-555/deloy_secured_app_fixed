const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

router.get('/login', (req, res) => {
  res.render('auth/login', { error: null });
});

router.get('/register', (req, res) => {
  res.render('auth/register', { error: null });
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const db = req.db;

  if (!username || !password) {
    return res.render('auth/login', { error: 'Username and password are required' });
  }

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
});

router.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  const db = req.db;

  if (!username || !password || !email) {
    return res.render('auth/register', { error: 'All fields are required' });
  }

  if (password.length < 6) {
    return res.render('auth/register', { error: 'Password must be at least 6 characters' });
  }

  db.get('SELECT id FROM users WHERE username = ?', [username], (err, check) => {
    if (check) {
      return res.render('auth/register', { error: 'Username already exists' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        return res.render('auth/register', { error: 'Registration failed' });
      }

      db.run('INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)',
        [username, hash, email, 'user', 100], (err) => {
          if (err) {
            return res.render('auth/register', { error: 'Registration failed' });
          }
          res.redirect('/login');
        });
    });
  });
});

router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

router.get('/forgot-password', (req, res) => {
  res.render('auth/forgot-password', { error: null, sent: false });
});

router.post('/forgot-password', (req, res) => {
  const { username } = req.body;
  const db = req.db;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    res.render('auth/forgot-password', {
      error: null,
      sent: true
    });
  });
});

router.get('/reset-password', (req, res) => {
  const { token } = req.query;
  if (!token) return res.redirect('/forgot-password');
  res.render('auth/reset-password', { error: null, success: null, token });
});

router.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!newPassword || newPassword.length < 6) {
    return res.render('auth/reset-password', {
      error: 'Password must be at least 6 characters',
      success: null,
      token
    });
  }

  res.render('auth/reset-password', {
    error: null,
    success: 'Password reset is disabled for security',
    token
  });
});

module.exports = router;
