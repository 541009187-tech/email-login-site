const express = require('express');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const APP_NAME = '邮箱登录平台';
let db = { users: {}, codes: {}, resetCodes: {}, sessions: {}, adminSessions: {}, loginLogs: {} };

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.exmail.qq.com',
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: {
    user: process.env.SMTP_USER || 'service@shijiayu.cn',
    pass: process.env.SMTP_PASS,
  },
});

const CODE_TTL = 5 * 60 * 1000;
const RESEND_COOLDOWN = 60 * 1000;
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '小君久久这样子';
const ADMIN_SESSION_TTL = 8 * 60 * 60 * 1000;
const RISK_WINDOW = 24 * 60 * 60 * 1000;
const RISK_IP_THRESHOLD = 3;
const MAX_LOGS_PER_USER = 100;

// ===== AI 风控配置 =====
const DOUBAO_API_KEY = process.env.DOUBAO_API_KEY || '';
const DOUBAO_API_URL = 'https://ark.cn-beijing.volces.com/api/v3/responses';
const DOUBAO_MODEL = 'doubao-seed-evolving';

async function aiRiskCheck(user, loginInfo) {
  if (!DOUBAO_API_KEY) return { level: 'unknown', reason: 'AI未配置' };
  try {
    const recentLogs = (db.loginLogs[user.email] || []).slice(0, 10);
    const prompt = `你是一个网站风控专家。请根据以下登录信息，判断这个登录行为是否异常，是否存在账号被盗、账号售卖、批量注册等风险。

用户信息：
- 邮箱：${user.email}
- 注册时间：${user.createdAt}
- 是否设置密码：${user.passwordHash ? '是' : '否'}

本次登录：
- IP：${loginInfo.ip}
- 设备/浏览器：${loginInfo.userAgent}
- 时间：${loginInfo.time}

最近10次登录记录：
${recentLogs.map(l => `- ${l.time} | IP:${l.ip} | ${l.success ? '成功' : '失败'} | ${l.userAgent?.substring(0, 50)}`).join('\n')}

请只返回JSON格式，不要其他内容：
{"level": "high/medium/low", "reason": "判断原因一句话"}`;

    const res = await fetch(DOUBAO_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${DOUBAO_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: DOUBAO_MODEL,
        input: [{
          role: 'user',
          content: [{ type: 'input_text', text: prompt }]
        }]
      })
    });
    const data = await res.json();
    const text = data.output?.[0]?.content?.[0]?.text || '{}';
    const match = text.match(/\{[\s\S]*\}/);
    if (match) return JSON.parse(match[0]);
    return { level: 'unknown', reason: 'AI解析失败' };
  } catch (e) {
    return { level: 'unknown', reason: 'AI调用失败: ' + e.message };
  }
}

function hashPassword(password, salt) { return crypto.scryptSync(password, salt, 64).toString('hex'); }
function newSalt() { return crypto.randomBytes(16).toString('hex'); }
function newToken() { return crypto.randomBytes(32).toString('hex'); }
function norm(email) { return String(email || '').trim().toLowerCase(); }

function getSession(req) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const s = db.sessions[token];
  if (!s) return null;
  if (new Date(s.expiresAt) < new Date()) { delete db.sessions[token]; return null; }
  return { token, ...s };
}

function getAdminSession(req) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const s = db.adminSessions && db.adminSessions[token];
  if (!s) return null;
  if (new Date(s.expiresAt) < new Date()) { delete db.adminSessions[token]; return null; }
  return { token, ...s };
}

function sendMail(to, subject, html) {
  return transporter.sendMail({
    from: `${APP_NAME} <${process.env.SMTP_USER || 'service@shijiayu.cn'}>`,
    to, subject, html,
  });
}

function checkBan(user) {
  if (!user || !user.banned) return null;
  if (user.banned.permanent) return '账号已被永久封禁';
  if (user.banned.until && new Date(user.banned.until) > new Date()) {
    return `账号已被封禁，解封时间：${new Date(user.banned.until).toLocaleString('zh-CN')}`;
  }
  user.banned = null;
  return null;
}

function isBanned(user) { return !!checkBan(user); }

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.ip || 'unknown';
}

function recordLogin(email, req, success) {
  if (!db.loginLogs) db.loginLogs = {};
  if (!db.loginLogs[email]) db.loginLogs[email] = [];
  db.loginLogs[email].unshift({
    time: new Date().toISOString(),
    ip: getClientIp(req),
    userAgent: (req.headers['user-agent'] || '').substring(0, 200),
    success: !!success,
  });
  if (db.loginLogs[email].length > MAX_LOGS_PER_USER) db.loginLogs[email] = db.loginLogs[email].slice(0, MAX_LOGS_PER_USER);
}

function checkRisk(email) {
  if (!db.loginLogs || !db.loginLogs[email]) return { triggered: false };
  const now = Date.now();
  const recentLogs = db.loginLogs[email].filter(l => l.success && now - new Date(l.time).getTime() < RISK_WINDOW);
  const uniqueIps = [...new Set(recentLogs.map(l => l.ip))];
  if (uniqueIps.length >= RISK_IP_THRESHOLD) {
    const user = db.users[email];
    if (user && !isBanned(user)) {
      user.banned = { permanent: true, reason: `系统自动封禁：24小时内从 ${uniqueIps.length} 个不同IP登录，疑似账号售卖`, bannedAt: new Date().toISOString(), autoBanned: true };
      for (const t of Object.keys(db.sessions)) if (db.sessions[t].email === email) delete db.sessions[t];
      return { triggered: true, reason: user.banned.reason, ipCount: uniqueIps.length };
    }
  }
  return { triggered: false, ipCount: uniqueIps.length };
}

function getUserLoginInfo(email) {
  if (!db.loginLogs || !db.loginLogs[email] || !db.loginLogs[email].length) return { lastLogin: null, recentIpCount: 0, riskLevel: 'normal' };
  const logs = db.loginLogs[email];
  const successLogs = logs.filter(l => l.success);
  const lastLogin = successLogs.length ? successLogs[0].time : null;
  const now = Date.now();
  const recentIps = [...new Set(successLogs.filter(l => now - new Date(l.time).getTime() < RISK_WINDOW).map(l => l.ip))];
  let riskLevel = 'normal';
  if (recentIps.length >= RISK_IP_THRESHOLD) riskLevel = 'high';
  else if (recentIps.length >= 2) riskLevel = 'medium';
  return { lastLogin, recentIpCount: recentIps.length, riskLevel };
}

const app = express();
app.use(express.json());

app.post('/api/send-code', async (req, res) => {
  const email = norm(req.body.email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: '请输入有效的邮箱地址' });
  const existing = db.codes[email];
  if (existing && existing.sentAt && Date.now() - existing.sentAt < RESEND_COOLDOWN) {
    const wait = Math.ceil((RESEND_COOLDOWN - (Date.now() - existing.sentAt)) / 1000);
    return res.status(429).json({ error: `请等待 ${wait} 秒后再发送` });
  }
  const code = String(crypto.randomInt(100000, 1000000));
  db.codes[email] = { code, sentAt: Date.now(), expiresAt: Date.now() + CODE_TTL, usedAt: null };
  try {
    await sendMail(email, `${APP_NAME} - 登录验证码`, `<div style="font-family:Arial,'Microsoft YaHei',sans-serif;max-width:600px;margin:0 auto;padding:24px;"><h2 style="color:#2563eb;margin-top:0;">${APP_NAME}</h2><p style="color:#333;">您好，您正在登录${APP_NAME}，验证码为：</p><div style="font-size:32px;font-weight:bold;letter-spacing:8px;background:#f1f5f9;padding:16px;text-align:center;border-radius:8px;color:#1e293b;">${code}</div><p style="color:#dc2626;font-size:14px;margin-top:16px;">验证码 5 分钟内有效，请勿泄露给他人。</p></div>`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: '邮件发送失败：' + e.message }); }
});

app.post('/api/code-login', async (req, res) => {
  const email = norm(req.body.email);
  const code = String(req.body.code || '');
  const rec = db.codes[email];
  if (!rec || rec.usedAt || rec.code !== code) return res.status(400).json({ error: '验证码错误' });
  if (Date.now() > rec.expiresAt) return res.status(400).json({ error: '验证码已过期' });
  rec.usedAt = Date.now();
  let user = db.users[email];
  const isNew = !user;
  if (!user) { user = { email, passwordHash: '', salt: '', name: '', createdAt: new Date().toISOString() }; db.users[email] = user; }
  const banMsg = checkBan(user);
  if (banMsg) { recordLogin(email, req, false); return res.status(403).json({ error: banMsg }); }
  const token = newToken();
  db.sessions[token] = { email, expiresAt: new Date(Date.now() + SESSION_TTL).toISOString() };
  recordLogin(email, req, true);
  
  // AI风控分析
  const loginInfo = { ip: getClientIp(req), userAgent: req.headers['user-agent'] || '', time: new Date().toISOString() };
  const aiResult = await aiRiskCheck(user, loginInfo);
  if (aiResult.level === 'high') {
    user.banned = { permanent: true, reason: `AI风控判定高风险：${aiResult.reason}`, bannedAt: new Date().toISOString(), autoBanned: true };
    delete db.sessions[token];
    return res.status(403).json({ error: '账号已被AI风控系统自动封禁：' + aiResult.reason });
  }
  user.aiRisk = aiResult;
  
  const risk = checkRisk(email);
  if (risk.triggered) return res.status(403).json({ error: '账号已被系统自动永久封禁：' + risk.reason });
  res.json({ token, email: user.email, name: user.name, isNew, hasPassword: !!user.passwordHash, createdAt: user.createdAt });
});

app.post('/api/password-login', async (req, res) => {
  const email = norm(req.body.email);
  const password = String(req.body.password || '');
  const user = db.users[email];
  if (!user || !user.passwordHash) return res.status(401).json({ error: '密码错误或尚未设置密码' });
  const banMsg = checkBan(user);
  if (banMsg) { recordLogin(email, req, false); return res.status(403).json({ error: banMsg }); }
  if (hashPassword(password, user.salt) !== user.passwordHash) { recordLogin(email, req, false); return res.status(401).json({ error: '密码错误，请重试' }); }
  const token = newToken();
  db.sessions[token] = { email, expiresAt: new Date(Date.now() + SESSION_TTL).toISOString() };
  recordLogin(email, req, true);
  
  // AI风控分析
  const loginInfo = { ip: getClientIp(req), userAgent: req.headers['user-agent'] || '', time: new Date().toISOString() };
  const aiResult = await aiRiskCheck(user, loginInfo);
  if (aiResult.level === 'high') {
    user.banned = { permanent: true, reason: `AI风控判定高风险：${aiResult.reason}`, bannedAt: new Date().toISOString(), autoBanned: true };
    delete db.sessions[token];
    return res.status(403).json({ error: '账号已被AI风控系统自动封禁：' + aiResult.reason });
  }
  user.aiRisk = aiResult;
  
  const risk = checkRisk(email);
  if (risk.triggered) return res.status(403).json({ error: '账号已被系统自动永久封禁：' + risk.reason });
  res.json({ token, email: user.email, name: user.name, hasPassword: true, createdAt: user.createdAt });
});

app.post('/api/send-reset-code', async (req, res) => {
  const email = norm(req.body.email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: '请输入有效的邮箱地址' });
  if (!db.users[email]) return res.status(400).json({ error: '该邮箱未注册' });
  const existing = db.resetCodes[email];
  if (existing && existing.sentAt && Date.now() - existing.sentAt < RESEND_COOLDOWN) {
    const wait = Math.ceil((RESEND_COOLDOWN - (Date.now() - existing.sentAt)) / 1000);
    return res.status(429).json({ error: `请等待 ${wait} 秒后再发送` });
  }
  const code = String(crypto.randomInt(100000, 1000000));
  db.resetCodes[email] = { code, sentAt: Date.now(), expiresAt: Date.now() + CODE_TTL, usedAt: null };
  try {
    await sendMail(email, `${APP_NAME} - 重置密码验证码`, `<div style="font-family:Arial,'Microsoft YaHei',sans-serif;max-width:600px;margin:0 auto;padding:24px;"><h2 style="color:#2563eb;margin-top:0;">${APP_NAME}</h2><p style="color:#333;">您好，您正在重置密码，验证码为：</p><div style="font-size:32px;font-weight:bold;letter-spacing:8px;background:#f1f5f9;padding:16px;text-align:center;border-radius:8px;color:#1e293b;">${code}</div><p style="color:#dc2626;font-size:14px;margin-top:16px;">验证码 5 分钟内有效，请勿泄露给他人。</p></div>`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: '邮件发送失败：' + e.message }); }
});

app.post('/api/reset-password', (req, res) => {
  const email = norm(req.body.email);
  const code = String(req.body.code || '');
  const newPassword = String(req.body.newPassword || '');
  const rec = db.resetCodes[email];
  if (!rec || rec.usedAt || rec.code !== code) return res.status(400).json({ error: '验证码错误' });
  if (Date.now() > rec.expiresAt) return res.status(400).json({ error: '验证码已过期' });
  if (newPassword.length < 6) return res.status(400).json({ error: '新密码至少 6 位' });
  const user = db.users[email];
  if (!user) return res.status(400).json({ error: '该邮箱未注册' });
  rec.usedAt = Date.now();
  const salt = newSalt();
  user.salt = salt;
  user.passwordHash = hashPassword(newPassword, salt);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  const user = db.users[s.email];
  if (!user) return res.status(401).json({ error: '未登录' });
  res.json({ email: user.email, name: user.name, createdAt: user.createdAt, hasPassword: !!user.passwordHash, banned: user.banned || null });
});

app.post('/api/update-name', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  const name = String(req.body.name || '').trim();
  if (name.length < 2 || name.length > 20) return res.status(400).json({ error: '昵称长度需在 2~20 个字符之间' });
  db.users[s.email].name = name;
  res.json({ ok: true, name });
});

app.post('/api/set-password', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  const pwd = String(req.body.password || '');
  if (pwd.length < 6) return res.status(400).json({ error: '密码至少 6 位' });
  const salt = newSalt();
  db.users[s.email].salt = salt;
  db.users[s.email].passwordHash = hashPassword(pwd, salt);
  res.json({ ok: true });
});

app.post('/api/change-password', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  const oldPwd = String(req.body.oldPassword || '');
  const newPwd = String(req.body.newPassword || '');
  const user = db.users[s.email];
  if (!user || !user.passwordHash) return res.status(400).json({ error: '尚未设置密码' });
  if (hashPassword(oldPwd, user.salt) !== user.passwordHash) return res.status(400).json({ error: '原密码错误' });
  if (newPwd.length < 6) return res.status(400).json({ error: '新密码至少 6 位' });
  const salt = newSalt();
  user.salt = salt;
  user.passwordHash = hashPassword(newPwd, salt);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  delete db.sessions[token];
  res.json({ ok: true });
});

app.delete('/api/account', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: '未登录' });
  const confirmEmail = norm(req.body.email);
  if (confirmEmail !== s.email) return res.status(400).json({ error: '输入的邮箱与当前账号不一致' });
  delete db.users[s.email];
  delete db.codes[s.email];
  delete db.resetCodes[s.email];
  for (const t of Object.keys(db.sessions)) if (db.sessions[t].email === s.email) delete db.sessions[t];
  res.json({ ok: true });
});

app.post('/api/admin/login', (req, res) => {
  const pwd = String(req.body.password || '');
  if (pwd !== ADMIN_PASSWORD) return res.status(401).json({ error: '管理员密码错误' });
  const token = newToken();
  if (!db.adminSessions) db.adminSessions = {};
  db.adminSessions[token] = { expiresAt: new Date(Date.now() + ADMIN_SESSION_TTL).toISOString() };
  res.json({ token });
});

app.post('/api/admin/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (db.adminSessions) delete db.adminSessions[token];
  res.json({ ok: true });
});

app.get('/api/admin/stats', (req, res) => {
  if (!getAdminSession(req)) return res.status(401).json({ error: '未登录' });
  const users = Object.values(db.users);
  res.json({
    totalUsers: users.length,
    withPassword: users.filter(u => u.passwordHash).length,
    withoutPassword: users.filter(u => !u.passwordHash).length,
    activeSessions: Object.keys(db.sessions).length,
    todayNew: users.filter(u => new Date(u.createdAt).toDateString() === new Date().toDateString()).length,
    bannedUsers: users.filter(u => isBanned(u)).length,
  });
});

app.get('/api/admin/users', (req, res) => {
  if (!getAdminSession(req)) return res.status(401).json({ error: '未登录' });
  const users = Object.values(db.users).map(u => {
    const info = getUserLoginInfo(u.email);
    return { email: u.email, name: u.name, hasPassword: !!u.passwordHash, createdAt: u.createdAt, banned: u.banned || null, lastLogin: info.lastLogin, recentIpCount: info.recentIpCount, riskLevel: info.riskLevel, aiRisk: u.aiRisk || null };
  }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ users });
});

app.get('/api/admin/users/:email/logs', (req, res) => {
  if (!getAdminSession(req)) return res.status(401).json({ error: '未登录' });
  const email = norm(req.params.email);
  if (!db.users[email]) return res.status(404).json({ error: '用户不存在' });
  const logs = (db.loginLogs && db.loginLogs[email]) || [];
  res.json({ logs: logs.slice(0, 50) });
});

app.delete('/api/admin/users/:email', (req, res) => {
  if (!getAdminSession(req)) return res.status(401).json({ error: '未登录' });
  const email = norm(req.params.email);
  if (!db.users[email]) return res.status(404).json({ error: '用户不存在' });
  delete db.users[email];
  delete db.codes[email];
  delete db.resetCodes[email];
  if (db.loginLogs) delete db.loginLogs[email];
  for (const t of Object.keys(db.sessions)) if (db.sessions[t].email === email) delete db.sessions[t];
  res.json({ ok: true });
});

app.post('/api/admin/users/:email/ban', (req, res) => {
  if (!getAdminSession(req)) return res.status(401).json({ error: '未登录' });
  const email = norm(req.params.email);
  const user = db.users[email];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  const { permanent, days, months, years, reason } = req.body;
  if (permanent) {
    user.banned = { permanent: true, reason: reason || '', bannedAt: new Date().toISOString() };
  } else {
    const d = Number(days || 0), m = Number(months || 0), y = Number(years || 0);
    if (d <= 0 && m <= 0 && y <= 0) return res.status(400).json({ error: '请填写封禁时长' });
    const until = new Date();
    until.setDate(until.getDate() + d);
    until.setMonth(until.getMonth() + m);
    until.setFullYear(until.getFullYear() + y);
    user.banned = { permanent: false, until: until.toISOString(), reason: reason || '', bannedAt: new Date().toISOString() };
  }
  for (const t of Object.keys(db.sessions)) if (db.sessions[t].email === email) delete db.sessions[t];
  res.json({ ok: true, banned: user.banned });
});

app.post('/api/admin/users/:email/unban', (req, res) => {
  if (!getAdminSession(req)) return res.status(401).json({ error: '未登录' });
  const email = norm(req.params.email);
  const user = db.users[email];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  user.banned = null;
  res.json({ ok: true });
});

module.exports = app;
