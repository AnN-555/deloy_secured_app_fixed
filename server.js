const express = require('express');
const session = require('express-session');
const path = require('path');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('combined'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 3600000,
    httpOnly: true,
    secure: false,
    sameSite: 'lax'
  }
}));

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  next();
});

const sqlite3 = require('sqlite3').verbose();
const dbconn = new sqlite3.Database('./data.db');

dbconn.serialize(() => {
  dbconn.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    email TEXT,
    balance INTEGER DEFAULT 0
  )`);

  dbconn.exec(`CREATE TABLE IF NOT EXISTS drinks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    category TEXT,
    image TEXT,
    stock INTEGER DEFAULT 50
  )`);

  dbconn.exec(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    total REAL,
    status TEXT DEFAULT 'pending',
    order_date TEXT,
    delivery_address TEXT,
    notes TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  dbconn.exec(`CREATE TABLE IF NOT EXISTS carts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  dbconn.exec(`CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cart_id INTEGER,
    drink_id INTEGER,
    quantity INTEGER DEFAULT 1,
    FOREIGN KEY(cart_id) REFERENCES carts(id),
    FOREIGN KEY(drink_id) REFERENCES drinks(id)
  )`);

  dbconn.exec(`CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER,
    drink_id INTEGER,
    quantity INTEGER,
    price REAL,
    FOREIGN KEY(order_id) REFERENCES orders(id),
    FOREIGN KEY(drink_id) REFERENCES drinks(id)
  )`);

  dbconn.exec(`CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    comment TEXT,
    rating INTEGER DEFAULT 5,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  const bcrypt = require('bcryptjs');
  const salt = bcrypt.genSaltSync(10);

  const stmtInsertUser = dbconn.prepare(`INSERT OR IGNORE INTO users (username, password, role, email, balance) VALUES (?, ?, ?, ?, ?)`);
  stmtInsertUser.run('admin', bcrypt.hashSync('admin123', salt), 'admin', 'admin@milktea.com', 99999);
  stmtInsertUser.run('user1', bcrypt.hashSync('password1', salt), 'user', 'user1@milktea.com', 1000);
  stmtInsertUser.run('user2', bcrypt.hashSync('password2', salt), 'user', 'user2@milktea.com', 500);

  const stmtInsertDrink = dbconn.prepare(`INSERT OR IGNORE INTO drinks (id, name, price, category, image, stock) VALUES (?, ?, ?, ?, ?, ?)`);
  stmtInsertDrink.run(1, 'Classic Milk Tea', 5.99, 'milk-tea', '🧋', 100);
  stmtInsertDrink.run(2, 'Strawberry Cheese Tea', 6.99, 'fruit-tea', '🍓', 80);
  stmtInsertDrink.run(3, 'Brown Sugar Milk Tea', 6.49, 'milk-tea', '🧋', 90);
  stmtInsertDrink.run(4, 'Mango Green Tea', 5.49, 'fruit-tea', '🥭', 75);
  stmtInsertDrink.run(5, 'Taro Milk Tea', 5.99, 'milk-tea', '🧋', 85);
  stmtInsertDrink.run(6, 'Matcha Latte', 6.99, 'specialty', '🍵', 60);
  stmtInsertDrink.run(7, 'Wintermelon Tea', 4.99, 'classic', '🍵', 95);
  stmtInsertDrink.run(8, 'Thai Tea', 5.49, 'classic', '🧋', 88);
});

app.use((req, res, next) => {
  req.db = dbconn;
  next();
});

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');

app.use('/', authRoutes);
app.use('/user', userRoutes);
app.use('/admin', adminRoutes);

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`MilkTea Shop (Secured) running on http://localhost:${PORT}`);
});
