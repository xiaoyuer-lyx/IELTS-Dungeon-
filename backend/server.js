// ====================================================================
//  🏰 雅思副本 IELTS Dungeon 后端 API
//  Express + Supabase (Postgres) + JWT 认证
// ====================================================================
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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

// ===== 用户认证 API =====

// 注册
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    if (!username || username.length < 3) return res.status(400).json({ error: '用户名至少3个字符' });
    if (!password || password.length < 6) return res.status(400).json({ error: '密码至少6位' });
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: '邮箱格式无效' });

    // 检查用户是否已存在
    const { data: existing } = await supabase.from('users').select('username').eq('username', username).maybeSingle();
    if (existing) return res.status(400).json({ error: '用户名已存在' });

    const hash = await bcrypt.hash(password, 10);
    // 初始数据
    const defaultData = {
      st: { lv: 1, ex: 0, co: 200, hp: 100, sk: 0, tk: 0, ts: 0, pf: 0, sb: { L: 0, R: 0, W: 0, S: 0 }, ah: [] },
      si: { p: 'c', ps: ['c'], ac: {}, acs: [], bg: 'b0', bgs: ['bg0'] },
      set: null, pl: null, ck: {}, sc: [], bio: ''
    };

    const { error } = await supabase.from('users').insert([
      { username, password: hash, email, data: defaultData }
    ]);
    if (error) throw error;

    res.json({ ok: true, token: makeToken(username) });
  } catch (e) {
    console.error('register error:', e);
    res.status(500).json({ error: '注册失败' });
  }
});

// 登录
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '请填写完整' });

    // 管理员内置账号
    if (username === 'admin') {
      const ADMIN_PW = process.env.ADMIN_PW || 'admin123';
      if (password !== ADMIN_PW) return res.status(401).json({ error: '管理员密码错误' });
      // 管理员数据存 admin 用户行
      const { data: adminRow } = await supabase.from('users').select('*').eq('username', 'admin').maybeSingle();
      if (!adminRow) {
        await supabase.from('users').insert([{ username: 'admin', password: bcrypt.hashSync(ADMIN_PW, 10), email: 'admin@ielts.dungeon', data: {} }]);
        return res.json({ ok: true, token: makeToken('admin'), isAdmin: true, data: {} });
      }
      return res.json({ ok: true, token: makeToken('admin'), isAdmin: true, data: adminRow.data || {} });
    }

    const { data: user } = await supabase.from('users').select('*').eq('username', username).maybeSingle();
    if (!user) return res.status(401).json({ error: '用户不存在' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: '密码错误' });

    res.json({ ok: true, token: makeToken(username), data: user.data || {} });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: '登录失败' });
  }
});

// 读取当前用户数据
app.get('/api/data', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('data').eq('username', req.user).maybeSingle();
    if (!data) return res.status(404).json({ error: '用户不存在' });
    res.json({ data: data.data || {} });
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
    const { data } = await supabase.from('users').select('username,email,data').neq('username', 'admin');
    const list = (data || []).map(u => {
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

// 健康检查
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`⚔️ 雅思副本后端已启动: http://localhost:${PORT}`);
  console.log(`📡 Supabase 已连接`);
});
