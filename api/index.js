// api/index.js
const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

/**
 * ✅ 关键：兼容 /api 前缀
 * 你的前端请求 /api/todos，Vercel 会把请求交给这个 app
 * 这里把 /api/xxx 重写为 /xxx，这样路由写 /todos 也能命中
 */
app.use((req, res, next) => {
  if (req.url.startsWith("/api/")) {
    req.url = req.url.replace(/^\/api/, "");
  }
  next();
});

/**
 * ========== 简易 Cookie 工具 ==========
 */
function parseCookies(req) {
  const header = req.headers.cookie || "";
  const pairs = header.split(";").map(v => v.trim()).filter(Boolean);
  const out = {};
  for (const p of pairs) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function isSecureReq(req) {
  // Vercel/反代通常会带 x-forwarded-proto
  const proto = req.headers["x-forwarded-proto"];
  return proto === "https" || process.env.NODE_ENV === "production";
}

function setCookie(res, name, value, opts = {}) {
  const {
    httpOnly = true,
    sameSite = "Lax",
    maxAgeSeconds = 60 * 60 * 24 * 7, // 7天
    path = "/",
  } = opts;

  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    `Max-Age=${maxAgeSeconds}`,
    `SameSite=${sameSite}`,
  ];

  if (httpOnly) parts.push("HttpOnly");
  if (isSecureReq(opts.reqForSecureCheck || {})) parts.push("Secure");

  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly`);
}

/**
 * ========== “无数据库演示版”用户与Todo存储 ==========
 * ⚠️ Serverless 环境下可能会重启导致数据清空（演示OK）
 */
let nextUserId = 1;
const users = new Map(); // username -> {id, username, passHash, salt}
const todosByUserId = new Map(); // userId -> [{id,text,completed,created_at}]

/**
 * ========== 密码与会话签名 ==========
 */
const SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";

// 密码hash：scrypt（Node内置）
function hashPassword(password, salt) {
  const hash = crypto.scryptSync(password, salt, 32);
  return hash.toString("hex");
}

function makeSessionValue(payloadObj) {
  // payload: base64(json) + "." + signature
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function verifySessionValue(sessionValue) {
  if (!sessionValue || typeof sessionValue !== "string") return null;
  const [payload, sig] = sessionValue.split(".");
  if (!payload || !sig) return null;

  const expected = crypto.createHmac("sha256", SECRET).update(payload).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;

  const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  // 过期判断
  if (obj.exp && Date.now() > obj.exp) return null;
  return obj;
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const sess = cookies.session;
  const data = verifySessionValue(sess);
  if (!data || !data.user_id) return res.status(401).json({ message: "请先登录" });

  req.user = { id: data.user_id, username: data.username };
  next();
}

/**
 * ========== 首页：返回 index.html ==========
 */
app.get("/", (req, res) => {
  res.sendFile(path.join(process.cwd(), "index.html"));
});

/**
 * ========== Auth ==========
 */

// 当前用户
app.get("/auth/me", (req, res) => {
  const cookies = parseCookies(req);
  const data = verifySessionValue(cookies.session);
  if (!data || !data.user_id) return res.status(401).json({ message: "未登录" });
  res.json({ id: data.user_id, username: data.username });
});

// 注册
app.post("/auth/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ message: "username/password 不能为空" });

  const uname = String(username).trim();
  const pwd = String(password);

  if (uname.length < 2) return res.status(400).json({ message: "用户名太短" });
  if (pwd.length < 6) return res.status(400).json({ message: "密码至少6位" });

  if (users.has(uname)) return res.status(409).json({ message: "用户名已存在" });

  const salt = crypto.randomBytes(16).toString("hex");
  const passHash = hashPassword(pwd, salt);

  const user = { id: nextUserId++, username: uname, passHash, salt };
  users.set(uname, user);
  todosByUserId.set(user.id, []);

  // 注册后自动登录
  const session = makeSessionValue({
    user_id: user.id,
    username: user.username,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7,
  });

  // Secure 需要 req 信息，这里手动判断
  const secure = (req.headers["x-forwarded-proto"] === "https") || process.env.NODE_ENV === "production";
  res.setHeader(
    "Set-Cookie",
    `session=${encodeURIComponent(session)}; Path=/; Max-Age=${60 * 60 * 24 * 7}; SameSite=Lax; HttpOnly${secure ? "; Secure" : ""}`
  );

  res.status(201).json({ id: user.id, username: user.username });
});

// 登录
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  const uname = String(username || "").trim();
  const pwd = String(password || "");

  const user = users.get(uname);
  if (!user) return res.status(401).json({ message: "用户名或密码错误" });

  const passHash = hashPassword(pwd, user.salt);
  if (passHash !== user.passHash) return res.status(401).json({ message: "用户名或密码错误" });

  const session = makeSessionValue({
    user_id: user.id,
    username: user.username,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7,
  });

  const secure = (req.headers["x-forwarded-proto"] === "https") || process.env.NODE_ENV === "production";
  res.setHeader(
    "Set-Cookie",
    `session=${encodeURIComponent(session)}; Path=/; Max-Age=${60 * 60 * 24 * 7}; SameSite=Lax; HttpOnly${secure ? "; Secure" : ""}`
  );

  res.json({ id: user.id, username: user.username });
});

// 登出
app.post("/auth/logout", (req, res) => {
  clearCookie(res, "session");
  res.json({ message: "ok" });
});

/**
 * ========== Todos（需要登录） ==========
 */
app.get("/todos", requireAuth, (req, res) => {
  const list = todosByUserId.get(req.user.id) || [];
  res.json(list);
});

app.post("/todos", requireAuth, (req, res) => {
  const { text } = req.body || {};
  if (!text || !String(text).trim()) return res.status(400).json({ message: "text 不能为空" });

  const list = todosByUserId.get(req.user.id) || [];
  const todo = {
    id: Date.now(),
    text: String(text).trim(),
    completed: false,
    created_at: new Date().toISOString(),
  };
  list.unshift(todo);
  todosByUserId.set(req.user.id, list);
  res.status(201).json(todo);
});

app.put("/todos/:id", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const list = todosByUserId.get(req.user.id) || [];
  const t = list.find(x => x.id === id);
  if (!t) return res.status(404).json({ message: "未找到任务" });
  t.completed = !t.completed;
  res.json(t);
});

app.delete("/todos/:id", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const list = todosByUserId.get(req.user.id) || [];
  const before = list.length;
  const next = list.filter(x => x.id !== id);
  if (next.length === before) return res.status(404).json({ message: "未找到任务" });
  todosByUserId.set(req.user.id, next);
  res.json({ message: "删除成功" });
});

module.exports = app;