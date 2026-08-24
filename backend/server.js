// ====================================================================
//  🏰 雅思副本 IELTS Dungeon 后端 API
//  Express + Supabase (Postgres) + JWT 认证
// ====================================================================
require('dotenv').config(); // 本地读取 .env；部署环境无 .env 时自动跳过

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dns = require('dns'); // Node 内置，用于校验邮箱域名 MX 记录
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '20mb' })); // 允许大 JSON（含成绩截图 base64）

// ===== Supabase 配置（通过环境变量注入）=====
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY; // anon key
const JWT_SECRET = process.env.JWT_SECRET || 'ielts-dungeon-dev-secret';

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ 缺少 SUPABASE_URL 或 SUPABASE_KEY 环境变量！');
  console.error('请在 Render 环境变量中配置，或本地创建 .env 文件');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
const PORT = process.env.PORT || 3000;

// ===== 辅助函数 =====
function makeToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    req.user = jwt.verify(token, JWT_SECRET).username;
    next();
  } catch {
    return res.status(401).json({ error: '登录已过期' });
  }
}

// ===== 邮箱验证辅助 =====
const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

function emailFormatOk(email) {
  return typeof email === 'string' && email.length <= 254 && EMAIL_RE.test(email);
}

// 校验邮箱域名是否有真实邮件服务器（MX 记录）
// 域名不存在 / 无 MX -> 判定无效；其余网络异常宽松放行，避免误伤真实邮箱
async function emailDomainOk(domain) {
  try {
    const mx = await dns.promises.resolveMx(domain);
    return Array.isArray(mx) && mx.length > 0;
  } catch (err) {
    if (err && (err.code === 'ENOTFOUND' || err.code === 'NXDOMAIN' || err.code === 'ENODATA' || err.code === 'ENOTEMPTY')) return false;
    return true;
  }
}

// 邮箱归一化（去空格 + 小写）后再做 格式 + 域名验证
async function verifyEmail(email) {
  const e = String(email || '').trim().toLowerCase();
  if (!emailFormatOk(e)) return { ok: false, reason: '邮箱格式无效' };
  const domainOk = await emailDomainOk(e.split('@')[1]);
  if (!domainOk) return { ok: false, reason: '邮箱域名无效或没有邮件服务器' };
  return { ok: true, email: e };
}

// 把 Supabase 查询/写入错误转成对用户友好的响应
function dbErr(res, label, error) {
  const m = (error && error.message) || String(error || '');
  console.error(`[${label}]`, error);
  if (/fetch failed|ENOTFOUND|getaddrinfo|ECONNREFUSED|network/i.test(m)) {
    return res.status(500).json({ error: '数据库连接失败：请检查 Supabase 地址与密钥配置（.env）' });
  }
  return res.status(500).json({ error: `数据库操作失败（${label}），请稍后再试` });
}

// ===== 用户认证 API =====

// 注册
app.post('/api/register', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = req.body.password;
    if (!username || username.length < 3) return res.status(400).json({ error: '用户名至少3个字符' });
    if (!password || password.length < 6) return res.status(400).json({ error: '密码至少6位' });

    // 邮箱：格式 + 域名 MX 验证（同时归一化）
    const ev = await verifyEmail(req.body.email);
    if (!ev.ok) return res.status(400).json({ error: ev.reason });
    const email = ev.email;

    // 检查用户名是否已存在
    const un = await supabase.from('users').select('username').eq('username', username).maybeSingle();
    if (un.error) return dbErr(res, '查询用户名', un.error);
    if (un.data) return res.status(400).json({ error: '用户名已存在' });

    // 检查邮箱是否已被注册（用 limit(1)，历史重复邮箱也不会触发多行报错）
    const em = await supabase.from('users').select('username').eq('email', email).limit(1);
    if (em.error) return dbErr(res, '查询邮箱', em.error);
    if (em.data && em.data.length) return res.status(400).json({ error: '该邮箱已被注册' });

    const hash = await bcrypt.hash(password, 10);
    // 初始数据
    const defaultData = {
      st: { lv: 1, ex: 0, co: 200, hp: 100, sk: 0, tk: 0, ts: 0, pf: 0, sb: { L: 0, R: 0, W: 0, S: 0 }, ah: [] },
      si: { p: 'c', ps: ['c'], ac: {}, acs: [], bg: 'b0', bgs: ['bg0'] },
      set: null, pl: null, ck: {}, sc: [], bio: ''
    };

    const ins = await supabase.from('users').insert([
      { username, password: hash, email, data: defaultData }
    ]);
    if (ins.error) return dbErr(res, '写入用户', ins.error);

    res.json({ ok: true, token: makeToken(username) });
  } catch (e) {
    console.error('register error:', e);
    res.status(500).json({ error: '注册失败' });
  }
});

// 登录
app.post('/api/login', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = req.body.password;
    if (!username || !password) return res.status(400).json({ error: '请填写完整' });

    // 管理员账号：按数据库里存的密码哈希校验（与普通用户一致）
    if (username === 'admin') {
      const q = await supabase.from('users').select('*').eq('username', 'admin').maybeSingle();
      if (q.error) return dbErr(res, '查询管理员', q.error);
      const adminRow = q.data;
      if (!adminRow) {
        // 首次登录：对照环境变量 ADMIN_PW，通过后写入管理员行
        const ADMIN_PW = process.env.ADMIN_PW || 'admin123';
        if (password !== ADMIN_PW) return res.status(401).json({ error: '管理员密码错误' });
        const ins = await supabase.from('users').insert([
          { username: 'admin', password: bcrypt.hashSync(ADMIN_PW, 10), email: 'admin@ielts.dungeon', data: {} }
        ]);
        if (ins.error) return dbErr(res, '写入管理员', ins.error);
        return res.json({ ok: true, token: makeToken('admin'), isAdmin: true, data: {} });
      }
      const adminOk = await bcrypt.compare(password, adminRow.password);
      if (!adminOk) return res.status(401).json({ error: '管理员密码错误' });
      return res.json({ ok: true, token: makeToken('admin'), isAdmin: true, data: adminRow.data || {} });
    }

    const q = await supabase.from('users').select('*').eq('username', username).maybeSingle();
    if (q.error) return dbErr(res, '查询用户', q.error);
    const user = q.data;
    if (!user) return res.status(401).json({ error: '用户不存在' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: '密码错误' });

    const ud = user.data || {};
    res.json({ ok: true, token: makeToken(username), email: user.email, nickname: ud.nick || null, data: ud });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: '登录失败' });
  }
});

// 读取当前用户数据
app.get('/api/data', auth, async (req, res) => {
  try {
    const q = await supabase.from('users').select('*').eq('username', req.user).maybeSingle();
    if (q.error) return dbErr(res, '读取用户', q.error);
    const user = q.data;
    if (!user) return res.status(404).json({ error: '用户不存在' });
    const ud = user.data || {};
    res.json({ data: ud, email: user.email, nickname: ud.nick || null });
  } catch (e) {
    console.error('get data error:', e);
    res.status(500).json({ error: '读取失败' });
  }
});

// 保存当前用户数据
app.post('/api/data', auth, async (req, res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: '数据为空' });
    const { error } = await supabase.from('users').update({ data }).eq('username', req.user);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    console.error('save data error:', e);
    res.status(500).json({ error: '保存失败' });
  }
});

// 删除当前用户账号
app.delete('/api/account', auth, async (req, res) => {
  try {
    if (req.user === 'admin') return res.status(400).json({ error: '管理员账号不可删除' });
    const { error } = await supabase.from('users').delete().eq('username', req.user);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    console.error('delete account error:', e);
    res.status(500).json({ error: '删除失败' });
  }
});

// 更新账户设置：邮箱/昵称/密码
app.put('/api/settings', auth, async (req, res) => {
  try {
    const { email, nickname, password } = req.body;
    const q0 = await supabase.from('users').select('data').eq('username', req.user).maybeSingle();
    if (q0.error) return dbErr(res, '查询用户', q0.error);
    const user = q0.data;
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const updates = {};
    if (email !== undefined) {
      const ev = await verifyEmail(email);
      if (!ev.ok) return res.status(400).json({ error: ev.reason });
      // 换绑邮箱不得占用其他账号的邮箱
      const dupe = await supabase.from('users').select('username').eq('email', ev.email).neq('username', req.user).limit(1);
      if (dupe.error) return dbErr(res, '查询邮箱', dupe.error);
      if (dupe.data && dupe.data.length) return res.status(400).json({ error: '该邮箱已被其他账号使用' });
      updates.email = ev.email;
    }
    if (nickname !== undefined) {
      if (!nickname || String(nickname).length > 20) return res.status(400).json({ error: '昵称需 1-20 字符' });
      const d = user.data || {};
      d.nick = nickname;
      updates.data = d;
    }
    if (password !== undefined) {
      if (String(password).length < 6) return res.status(400).json({ error: '密码至少6位' });
      updates.password = bcrypt.hashSync(password, 10);
    }

    const { error } = await supabase.from('users').update(updates).eq('username', req.user);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    console.error('update settings error:', e);
    res.status(500).json({ error: '保存失败' });
  }
});

// ===== 管理员 API =====
// 管理员 token 验证
function adminAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    const u = jwt.verify(token, JWT_SECRET);
    if (u.username !== 'admin') return res.status(403).json({ error: '仅管理员可操作' });
    req.user = 'admin';
    next();
  } catch {
    return res.status(401).json({ error: '登录已过期' });
  }
}

// 列出所有用户（不含 admin）
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const q = await supabase.from('users').select('username,email,data').neq('username', 'admin');
    if (q.error) return dbErr(res, '获取用户列表', q.error);
    const list = (q.data || []).map(u => {
      const d = u.data || {};
      return { username: u.username, email: u.email, st: d.st || { lv: 1, co: 0, tk: 0 } };
    });
    res.json({ users: list });
  } catch (e) {
    res.status(500).json({ error: '获取用户列表失败' });
  }
});

// 给指定用户加金币
app.post('/api/admin/users/:name/coins', adminAuth, async (req, res) => {
  try {
    const { amount } = req.body;
    const { data: user } = await supabase.from('users').select('data').eq('username', req.params.name).maybeSingle();
    if (!user) return res.status(404).json({ error: '用户不存在' });
    const d = user.data || {};
    d.st = d.st || {};
    d.st.co = (d.st.co || 0) + (amount || 0);
    await supabase.from('users').update({ data: d }).eq('username', req.params.name);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '操作失败' });
  }
});

// 重置用户
app.post('/api/admin/users/:name/reset', adminAuth, async (req, res) => {
  try {
    const defaultData = {
      st: { lv: 1, ex: 0, co: 200, hp: 100, sk: 0, tk: 0, ts: 0, pf: 0, sb: { L: 0, R: 0, W: 0, S: 0 }, ah: [] },
      si: { p: 'c', ps: ['c'], ac: {}, acs: [], bg: 'b0', bgs: ['bg0'] },
      set: null, pl: null, ck: {}, sc: [], bio: ''
    };
    await supabase.from('users').update({ data: defaultData }).eq('username', req.params.name);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '重置失败' });
  }
});

// 删除用户
app.delete('/api/admin/users/:name', adminAuth, async (req, res) => {
  try {
    await supabase.from('users').delete().eq('username', req.params.name);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '删除失败' });
  }
});

// ===== 静态文件服务（部署时前端）=====
const path = require('path');
// Render 部署时，前端 index.html 在项目根目录
const frontendDir = path.join(__dirname, '..');
app.use(express.static(frontendDir));

// 根路径 -> 打开前端主页
app.get('/', (req, res) => {
  res.sendFile(path.join(frontendDir, 'ielts_egg_party.html'));
});

// 健康检查（顺带探测 Supabase 连接状态，便于排障）
app.get('/api/health', async (req, res) => {
  try {
    const { error } = await supabase.from('users').select('username').limit(1);
    res.json({ ok: true, db: error ? 'error' : 'ok', dbError: error ? error.message : null });
  } catch (e) {
    res.json({ ok: true, db: 'error', dbError: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`⚔️ 雅思副本后端已启动: http://localhost:${PORT}`);
  console.log(`📡 Supabase 已连接`);
});
