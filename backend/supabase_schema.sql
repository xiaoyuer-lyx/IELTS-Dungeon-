-- ====================================================================
--  🏰 雅思副本 IELTS Dungeon - Supabase 数据库表结构
--  在 Supabase 项目的 SQL Editor 中执行此脚本
-- ====================================================================

-- 用户表：所有用户数据统一存 data JSON 列
CREATE TABLE IF NOT EXISTS public.users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,          -- bcrypt hash
  email TEXT,
  nickname TEXT,
  data JSONB DEFAULT '{}',         -- 用户全部游戏数据
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 开启 RLS（行级安全）：生产环境建议配合 Supabase Auth
-- 但我们用 JWT 自定义认证，先禁用 RLS 让服务端可访问
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow_all" ON public.users FOR ALL USING (true) WITH CHECK (true);

-- 索引
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users (username);

-- 可选：预置管理员账号（密码：admin123 的 bcrypt hash）
-- 如果不执行，后端会在首次登录 admin 时自动创建
-- INSERT INTO public.users (username, password, email, data)
-- VALUES ('admin', '$2a$10$hG6qQtZrx0rMmU5JmS2H9uFdBzHq3n2H5s1XwV8yBkF0C5N6eM7aG', 'admin@ielts.dungeon', '{}');
