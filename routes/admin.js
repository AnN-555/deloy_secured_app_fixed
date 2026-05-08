const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  if (req.session.role !== 'admin') {
    return res.status(403).send('Admin access required');
  }
  next();
}

router.get('/users', requireAuth, (req, res) => {
  const db = req.db;
  db.all('SELECT id, username, email, role, balance FROM users ORDER BY id', [], (err, users) => {
    res.render('admin/users', { users: users || [], user: req.session });
  });
});

router.get('/drinks', requireAuth, (req, res) => {
  const db = req.db;
  db.all('SELECT * FROM drinks ORDER BY id', [], (err, drinks) => {
    res.render('admin/drinks', { drinks: drinks || [], user: req.session });
  });
});

router.get('/orders', requireAuth, (req, res) => {
  const db = req.db;
  db.all('SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.order_date DESC', [], (err, orders) => {
    res.render('admin/orders', { orders: orders || [], user: req.session });
  });
});

module.exports = router;
