import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { OAuth2Client } from "google-auth-library";
import pool from "./db.js";

dotenv.config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ─── CONFIG ENDPOINT ──────────────────────────────────────────────────────────
app.get("/api/config", (req, res) => {
  res.json({ GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID });
});

// ─── Middleware: Verify JWT token ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res.status(401).json({ error: "No token, please sign in" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ─── SIGNUP ───────────────────────────────────────────────────────────────────
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res
      .status(400)
      .json({ error: "Name, email and password are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashedPassword],
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.status(201).json({ message: "Account created!", token, user });
  } catch (err) {
    if (err.code === "23505") {
      res.status(400).json({ error: "Email already exists. Please sign in." });
    } else {
      res.status(500).json({ error: "Server error: " + err.message });
    }
  }
});

// ─── SIGNIN ───────────────────────────────────────────────────────────────────
app.post("/api/signin", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password are required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];
    if (!user)
      return res
        .status(400)
        .json({ error: "No account found with this email" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.json({
      message: "Signed in!",
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// ─── GOOGLE LOGIN ─────────────────────────────────────────────────────────────
app.post("/api/auth/google", async (req, res) => {
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: "No credential provided" });

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name } = payload;

    // Check if user exists
    let result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    let user = result.rows[0];

    // If user doesn't exist, create them with a random password
    if (!user) {
      const randomPassword = await bcrypt.hash(Math.random().toString(36).slice(-10), 10);
      const insertResult = await pool.query(
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
        [name, email, randomPassword]
      );
      user = insertResult.rows[0];
    }

    // Sign JWT
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      message: "Signed in with Google!",
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("Google Auth Error:", err);
    res.status(500).json({ error: "Google Authentication failed" });
  }
});

// ─── LOGOUT (client just deletes token, this just confirms) ──────────────────
app.post("/api/logout", authMiddleware, (req, res) => {
  res.json({ message: "Logged out successfully" });
});

// ─── DEBUG: See all users in DB (remove this in production!) ─────────────────
app.get("/api/debug/users", async (req, res) => {
  const result = await pool.query(
    "SELECT id, name, email, created_at FROM users ORDER BY id DESC",
  );
  res.json({ total: result.rows.length, users: result.rows });
});

// ─── Get current user (protected) ────────────────────────────────────────────
app.get("/api/me", authMiddleware, async (req, res) => {
  const result = await pool.query(
    "SELECT id, name, email FROM users WHERE id = $1",
    [req.user.id],
  );
  res.json(result.rows[0]);
});

// ─── TODO ROUTES (protected) ──────────────────────────────────────────────────
let todos = [];

app.get("/api/todos", authMiddleware, (req, res) => {
  res.json(todos);
});

app.post("/api/todos", authMiddleware, (req, res) => {
  const { text } = req.body;
  const newTodo = { id: Date.now(), text, userId: req.user.id };
  todos.push(newTodo);
  res.json(newTodo);
});

app.delete("/api/todos/:id", authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  todos = todos.filter((t) => t.id !== id);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
