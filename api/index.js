// api/index.js
const express = require("express");
const path = require("path");

const app = express();

app.use(express.json());

// 让 Vercel 能返回静态首页
app.get("/", (req, res) => {
  res.sendFile(path.join(process.cwd(), "index.html"));
});

// Demo：先用内存 todos（部署演示用）
let todos = [{ id: 1, text: "学习 Cursor", completed: false }];

app.get("/todos", (req, res) => res.json(todos));

app.post("/todos", (req, res) => {
  const { text } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ message: "text 不能为空" });
  const t = { id: Date.now(), text: String(text).trim(), completed: false };
  todos.unshift(t);
  res.status(201).json(t);
});

app.put("/todos/:id", (req, res) => {
  const id = Number(req.params.id);
  const t = todos.find(x => x.id === id);
  if (!t) return res.status(404).json({ message: "未找到任务" });
  t.completed = !t.completed;
  res.json(t);
});

app.delete("/todos/:id", (req, res) => {
  const id = Number(req.params.id);
  const before = todos.length;
  todos = todos.filter(x => x.id !== id);
  if (todos.length === before) return res.status(404).json({ message: "未找到任务" });
  res.json({ message: "删除成功" });
});

module.exports = app;