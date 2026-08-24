-- ====================================================================
--  🏰 雅思副本 IELTS Dungeon - Supabase 数据库表结构
--  在 Supabase 项目的 SQL Editor 中执行此脚本
-- ====================================================================

-- 用户表：所有用户数据统一存 data JSON 列
CREATE TABLE IF NOT EXISTS public.users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,          -- bcrypt hash
  email TEXT UNIQUE,               -- 一个邮箱只能注册一个账号
  nickname TEXT,
  data JSONB DEFAULT '{}',         -- 用户全部游戏数据
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 若表已存在（首次建表可跳过此步），在 Supabase SQL Editor 手动执行：
--   1) 先清理历史重复邮箱（保留其一，其余改名，避免 UNIQUE 约束建立失败）
--      UPDATE public.users a SET email = a.email || '_dup_' || a.id
--      FROM public.users b
--      WHERE a.id > b.id AND a.email = b.email;
--   2) 给 email 加唯一约束
--      ALTER TABLE public.users ADD CONSTRAINT users_email_key UNIQUE (email);

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
