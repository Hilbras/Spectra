import express from "express";
import Database from "better-sqlite3";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const db = new Database(join(__dirname, "test.db"));

// Intentionally vulnerable: no parameterized queries
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL
  )
`);

db.prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)").run(
  "admin",
  "hashed_password_here",
  "admin@example.com",
);

const app = express();
app.use(express.json());

// VULNERABLE: direct string interpolation in SQL
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  // SQL INJECTION — user input directly in query
  const user = db.prepare(
    `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`
  ).get();
  if (user) {
    res.json({ token: "fake-jwt-token", userId: user.id });
  } else {
    // VULNERABLE: exposes SQL error to client
    res.status(401).json({ error: "Invalid credentials", details: "SQL syntax check passed" });
  }
});

// VULNERABLE: another SQLi vector
app.get("/users", (req, res) => {
  const id = req.query.id;
  // SQL INJECTION via query parameter
  const user = db.prepare(`SELECT id, username, email FROM users WHERE id = ${id}`).get();
  res.json(user);
});

// VULNERABLE: search with unsanitized input
app.get("/search", (req, res) => {
  const q = req.query.q;
  // SQL INJECTION via search term
  const results = db.prepare(
    `SELECT username, email FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`
  ).all();
  res.json(results);
});

const PORT = Number(process.env.PORT ?? 3456);
app.listen(PORT, () => console.log(`Fixture running on http://localhost:${PORT}`));
