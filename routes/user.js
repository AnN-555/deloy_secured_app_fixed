const express = require('express');
const router = express.Router();
const escapeHtml = require('escape-html');

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

router.get('/dashboard', requireAuth, (req, res) => {
  const db = req.db;
  db.all('SELECT * FROM drinks ORDER BY id LIMIT 4', [], (err, featuredDrinks) => {
    db.get('SELECT SUM(total) as total FROM orders WHERE user_id = ?', [req.session.userId], (err, stats) => {
      db.get('SELECT COUNT(*) as count FROM orders WHERE user_id = ?', [req.session.userId], (err, orderCount) => {
        res.render('user/dashboard', {
          user: req.session,
          featuredDrinks: featuredDrinks || [],
          totalSpent: stats?.total || 0,
          orderCount: orderCount?.count || 0
        });
      });
    });
  });
});

router.get('/menu', requireAuth, (req, res) => {
  const db = req.db;
  const category = req.query.category || 'all';
  const search = req.query.q || '';

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

  db.all(sql, params, (err, drinks) => {
    db.all('SELECT * FROM drinks GROUP BY category', [], (err, categories) => {
      res.render('user/menu', { drinks, categories, selectedCategory: category, searchQuery: search, user: req.session });
    });
  });
});

router.get('/cart', requireAuth, (req, res) => {
  const db = req.db;
  db.get('SELECT * FROM carts WHERE user_id = ?', [req.session.userId], (err, cart) => {
    if (!cart) {
      return res.render('user/cart', { cartItems: [], cart: null, total: 0, user: req.session });
    }
    db.all(`SELECT ci.*, d.name, d.price, d.image FROM cart_items ci
            JOIN drinks d ON ci.drink_id = d.id
            WHERE ci.cart_id = ?`, [cart.id], (err, cartItems) => {
      const total = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);
      res.render('user/cart', { cartItems, cart, total, user: req.session });
    });
  });
});

router.post('/cart/add', requireAuth, (req, res) => {
  const { drink_id, quantity } = req.body;
  const db = req.db;

  db.get('SELECT * FROM carts WHERE user_id = ?', [req.session.userId], (err, cart) => {
    if (!cart) {
      db.run('INSERT INTO carts (user_id) VALUES (?)', [req.session.userId], function(err) {
        addItemToCart(this.lastID);
      });
    } else {
      addItemToCart(cart.id);
    }
  });

  function addItemToCart(cartId) {
    db.get('SELECT * FROM cart_items WHERE cart_id = ? AND drink_id = ?', [cartId, drink_id], (err, existing) => {
      if (existing) {
        db.run('UPDATE cart_items SET quantity = quantity + ? WHERE id = ?', [quantity || 1, existing.id], (err) => {
          res.redirect('/user/cart');
        });
      } else {
        db.run('INSERT INTO cart_items (cart_id, drink_id, quantity) VALUES (?, ?, ?)',
          [cartId, drink_id, quantity || 1], (err) => {
            res.redirect('/user/cart');
          });
      }
    });
  }
});

router.post('/cart/update', requireAuth, (req, res) => {
  const { item_id, quantity } = req.body;
  const db = req.db;

  if (parseInt(quantity) <= 0) {
    db.run('DELETE FROM cart_items WHERE id = ?', [item_id], (err) => {
      res.redirect('/user/cart');
    });
  } else {
    db.run('UPDATE cart_items SET quantity = ? WHERE id = ?', [quantity, item_id], (err) => {
      res.redirect('/user/cart');
    });
  }
});

router.post('/cart/remove', requireAuth, (req, res) => {
  const { item_id } = req.body;
  const db = req.db;
  db.run('DELETE FROM cart_items WHERE id = ?', [item_id], (err) => {
    res.redirect('/user/cart');
  });
});

router.get('/orders', requireAuth, (req, res) => {
  const db = req.db;
  db.all('SELECT * FROM orders WHERE user_id = ? ORDER BY order_date DESC', [req.session.userId], (err, orders) => {
    res.render('user/orders', { orders, user: req.session });
  });
});

router.get('/order/:id', requireAuth, (req, res) => {
  const db = req.db;
  const orderId = parseInt(req.params.id);

  db.get(
    `SELECT o.*, u.username AS owner_username FROM orders o
     JOIN users u ON o.user_id = u.id WHERE o.id = ?`,
    [orderId],
    (err, order) => {
      if (!order) return res.status(404).send('Order not found');

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

router.post('/order/checkout', requireAuth, (req, res) => {
  const { delivery_address, notes } = req.body;
  const db = req.db;

  db.get('SELECT * FROM carts WHERE user_id = ?', [req.session.userId], (err, cart) => {
    if (!cart) return res.redirect('/user/cart');

    db.all(`SELECT ci.*, d.name, d.price, d.image FROM cart_items ci
            JOIN drinks d ON ci.drink_id = d.id
            WHERE ci.cart_id = ?`, [cart.id], (err, cartItems) => {
      if (!cartItems || cartItems.length === 0) return res.redirect('/user/cart');

      const total = cartItems.reduce((sum, item) => sum + ((item.price || 0) * item.quantity), 0);

      db.get('SELECT balance FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (!user || user.balance < total) {
          return res.redirect('/user/cart?error=insufficient_balance');
        }

        const orderDate = new Date().toISOString();

        const stmt = db.prepare(`INSERT INTO orders (user_id, total, status, order_date, delivery_address, notes) VALUES (?, ?, 'pending', ?, ?, ?)`);
        stmt.run([req.session.userId, total, orderDate, delivery_address || '', notes || ''], function(err) {
          if (err) {
            stmt.finalize();
            return res.redirect('/user/cart');
          }

          const orderId = this.lastID;

          cartItems.forEach(function(item) {
            db.run('INSERT INTO order_items (order_id, drink_id, quantity, price) VALUES (?, ?, ?, ?)',
              [orderId, item.drink_id, item.quantity, item.price || 0]);
            db.run('UPDATE drinks SET stock = stock - ? WHERE id = ?', [item.quantity, item.drink_id]);
          });

          db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [total, req.session.userId]);
          db.run('DELETE FROM cart_items WHERE cart_id = ?', [cart.id]);

          stmt.finalize();
          res.redirect('/user/order/' + orderId);
        });
      });
    });
  });
});

router.get('/reviews', requireAuth, (req, res) => {
  const db = req.db;
  db.all(
    `SELECT r.*, u.username FROM reviews r
     LEFT JOIN users u ON r.user_id = u.id
     ORDER BY r.created_at DESC`,
    [],
    (err, reviews) => {
      res.render('user/reviews', { reviews: reviews || [], user: req.session });
    }
  );
});

router.post('/reviews', requireAuth, (req, res) => {
  const { comment } = req.body;
  const db = req.db;

  if (!comment || comment.trim().length === 0) {
    return res.redirect('/user/reviews');
  }

  db.run(
    `INSERT INTO reviews (user_id, name, comment, rating, created_at) VALUES (?, ?, ?, ?, datetime('now'))`,
    [req.session.userId, req.session.username, comment.trim(), 5],
    (err) => {
      if (err) console.error(err);
      res.redirect('/user/reviews');
    }
  );
});

router.get('/profile', requireAuth, (req, res) => {
  const db = req.db;
  db.get('SELECT id, username, email, role, balance FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    res.render('user/profile', { user });
  });
});

router.get('/search', requireAuth, (req, res) => {
  res.render('user/search', { drinks: [], query: '', user: req.session });
});

router.post('/search', requireAuth, (req, res) => {
  const { q } = req.body;
  const db = req.db;

  const sql = 'SELECT * FROM drinks WHERE name LIKE ?';
  const param = `%${q}%`;

  db.all(sql, [param], (err, drinks) => {
    if (err) drinks = [];
    res.render('user/search', { drinks, query: q, user: req.session });
  });
});

module.exports = router;
