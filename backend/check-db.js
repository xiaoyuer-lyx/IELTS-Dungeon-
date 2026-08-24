// ====================================================================
//  🔍 数据库连通性自检脚本
//  用法：cd backend && node check-db.js
//  读取 .env 里的 SUPABASE_URL / SUPABASE_KEY，实测能否连上并查询 users 表
//  返回 “✅ 数据库连接正常” = 配置有效；否则会打印具体错误
// ====================================================================
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_KEY;

if (!url || !key) {
  console.log('❌ 缺少 SUPABASE_URL 或 SUPABASE_KEY（请检查 backend/.env）');
  process.exit(1);
}
console.log('🔗 目标地址:', url);

const supabase = createClient(url, key);
(async () => {
  try {
    const { data, error } = await supabase.from('users').select('username').limit(1);
    if (error) {
      console.log('❌ 连接失败:', error.message);
      if (/fetch failed|ENOTFOUND|getaddrinfo/i.test(error.message || '')) {
        console.log('   → 大概率是这个地址在 DNS 里不存在，请在 Supabase 控制台核对 Project URL');
      }
      process.exit(1);
    }
    console.log(`✅ 数据库连接正常，users 表现有 ${data.length} 条示例记录`);
    console.log('   （首次建表后查询返回 0 条属正常）');
  } catch (e) {
    console.log('❌ 连接失败:', e.message);
    process.exit(1);
  }
})();
