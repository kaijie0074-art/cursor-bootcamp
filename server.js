const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(__dirname));

app.use(session({
  secret: 'cursor-bootcamp-secret',
  resave: false,
  saveUninitialized: false,
}));

const db = new Database(path.join(__dirname, 'todos.db'));

// 建表：users + todos（带 user_id）
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    completed INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )
`).run();

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ message: '请先登录' });
  next();
}

// 注册
app.post('/auth/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !username.trim()) return res.status(400).json({ message: 'username 不能为空' });
  if (!password || String(password).length < 6) return res.status(400).json({ message: 'password 至少 6 位' });

  const hash = bcrypt.hashSync(String(password), 10);

  try {
    const info = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username.trim(), hash);
    req.session.userId = info.lastInsertRowid;
    res.json({ id: info.lastInsertRowid, username: username.trim() });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ message: '用户名已存在' });
    return res.status(500).json({ message: '注册失败' });
  }
});

// 登录
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get((username || '').trim());
  if (!user) return res.status(401).json({ message: '用户名或密码错误' });

  const ok = bcrypt.compareSync(String(password || ''), user.password_hash);
  if (!ok) return res.status(401).json({ message: '用户名或密码错误' });

  req.session.userId = user.id;
  res.json({ id: user.id, username: user.username });
});

// 当前用户
app.get('/auth/me', (req, res) => {
  if (!req.session.userId) return res.json(null);
  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId);
  res.json(user || null);
});

// 退出
app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: '已退出' }));
});

// Todos：只操作自己的
app.get('/todos', requireLogin, (req, res) => {
  const rows = db.prepare('SELECT * FROM todos WHERE user_id = ? ORDER BY id DESC').all(req.session.userId);
  res.json(rows.map(r => ({ ...r, completed: !!r.completed })));
});

app.post('/todos', requireLogin, (req, res) => {
  const { text } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ message: 'text 不能为空' });

  const info = db.prepare('INSERT INTO todos (user_id, text) VALUES (?, ?)').run(req.session.userId, String(text).trim());
  const row = db.prepare('SELECT * FROM todos WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json({ ...row, completed: !!row.completed });
});

app.put('/todos/:id', requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT * FROM todos WHERE id = ? AND user_id = ?').get(id, req.session.userId);
  if (!row) return res.status(404).json({ message: '未找到任务' });

  const next = row.completed ? 0 : 1;
  db.prepare('UPDATE todos SET completed = ? WHERE id = ? AND user_id = ?').run(next, id, req.session.userId);

  const updated = db.prepare('SELECT * FROM todos WHERE id = ?').get(id);
  res.json({ ...updated, completed: !!updated.completed });
});

app.delete('/todos/:id', requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const result = db.prepare('DELETE FROM todos WHERE id = ? AND user_id = ?').run(id, req.session.userId);
  if (result.changes === 0) return res.status(404).json({ message: '未找到任务' });
  res.json({ message: '删除成功' });
});

// 首页
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});