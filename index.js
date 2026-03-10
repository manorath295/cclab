import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = 3000;

// fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let todos = [];

// ✅ get all todos
app.get("/api/todos", (req, res) => {
  res.json(todos);
});

// ✅ add todo
app.post("/api/todos", (req, res) => {
  const { text } = req.body;
  const newTodo = {
    id: Date.now(),
    text,
  };
  todos.push(newTodo);
  res.json(newTodo);
});

// ✅ delete todo
app.delete("/api/todos/:id", (req, res) => {
  const id = Number(req.params.id);
  todos = todos.filter((t) => t.id !== id);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on ${PORT}`);
});
