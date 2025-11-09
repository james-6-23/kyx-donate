/// <reference lib="deno.unstable" />

import { Hono } from 'https://deno.land/x/hono@v3.11.7/mod.ts';
import { cors } from 'https://deno.land/x/hono@v3.11.7/middleware.ts';
import { setCookie, getCookie } from 'https://deno.land/x/hono@v3.11.7/helper.ts';

// ==================== 类型定义 ====================
interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

interface VPSServer {
  id: string;
  ip: string;
  port: number;
  username: string; // SSH登录用户名
  authType: 'password' | 'key';
  password?: string;
  privateKey?: string;
  donatedBy: string;
  donatedByUsername: string;
  donatedAt: number;
  status: 'active' | 'inactive' | 'failed'; // 新增 failed 状态
  note?: string;
  // 验证相关字段
  verifyStatus: 'pending' | 'verified' | 'failed';
  verifyCode?: string;
  verifyFilePath?: string;
  sshFingerprint?: string;
  lastVerifyAt?: number;
  verifyErrorMsg?: string;
}

interface User {
  linuxDoId: string;
  username: string;
  avatarUrl?: string;
  isAdmin: boolean;
  createdAt: number;
}

interface Session {
  id: string;
  userId: string;
  username: string;
  avatarUrl?: string;
  isAdmin: boolean;
  expiresAt: number;
}

// ==================== Deno KV 初始化 ====================
const kv = await Deno.openKv();

// ==================== 工具函数 ====================
function generateId(): string {
  return crypto.randomUUID();
}

function generateSessionId(): string {
  return crypto.randomUUID();
}

function generateVerifyCode(): string {
  // 生成8位随机验证码
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

function getVerifyFilePath(verifyCode: string): string {
  return `/tmp/vps-feeding-verify-${verifyCode}.txt`;
}

// IP 地址验证函数
function isValidIPv4(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;

  const parts = ip.split('.');
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

function isValidIPv6(ip: string): boolean {
  // 移除方括号（如果存在）
  const cleanIp = ip.replace(/^\[|\]$/g, '');

  // IPv6 正则表达式（支持完整格式和缩写格式）
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

  return ipv6Regex.test(cleanIp);
}

function isValidIP(ip: string): boolean {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

// 检查SSH指纹是否已存在（防止重复投喂）
async function checkSSHFingerprintExists(fingerprint: string): Promise<boolean> {
  const result = await kv.get(['ssh_fingerprints', fingerprint]);
  return result.value !== null;
}

// 保存SSH指纹
async function saveSSHFingerprint(fingerprint: string, vpsId: string): Promise<void> {
  await kv.set(['ssh_fingerprints', fingerprint], vpsId);
}

// 检查IP是否已存在
async function checkIPExists(ip: string, port: number): Promise<boolean> {
  const allVPS = await getAllVPS();
  return allVPS.some(vps => vps.ip === ip && vps.port === port);
}

// SSH验证函数
async function verifyVPSBySSH(vps: VPSServer): Promise<{ success: boolean; fingerprint?: string; error?: string }> {
  try {
    // 使用Deno的Command API执行SSH命令
    // 这需要系统有ssh客户端，或者使用SSH库

    const verifyCommand = vps.authType === 'password'
      ? `sshpass -p '${vps.password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@${vps.ip} -p ${vps.port} "cat ${vps.verifyFilePath}"`
      : `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i <(echo '${vps.privateKey}') root@${vps.ip} -p ${vps.port} "cat ${vps.verifyFilePath}"`;

    // 注意：以上方案需要系统环境支持
    // 在Deno Deploy上可能不可用，需要改用纯JavaScript SSH客户端

    // 临时方案：标记为需要手动验证
    return {
      success: false,
      error: 'SSH验证需要管理员手动触发'
    };
  } catch (error: any) {
    return {
      success: false,
      error: error.message
    };
  }
}

// 简单的端口可达性检测（支持 IPv4 和 IPv6）
async function checkPortReachable(ip: string, port: number): Promise<boolean> {
  try {
    // 清理 IPv6 地址（移除方括号，如果有的话）
    const cleanIp = ip.replace(/^\[|\]$/g, '');

    const conn = await Deno.connect({
      hostname: cleanIp,
      port,
      transport: 'tcp'
    });
    conn.close();
    return true;
  } catch {
    return false;
  }
}

// 批量验证VPS
async function batchVerifyVPS(): Promise<{ total: number; success: number; failed: number; details: any[] }> {
  const allVPS = await getAllVPS();
  const pendingVPS = allVPS.filter(v => v.verifyStatus === 'pending');

  let successCount = 0;
  let failedCount = 0;
  const details = [];

  for (const vps of pendingVPS) {
    try {
      // 检查端口是否可达
      const portReachable = await checkPortReachable(vps.ip, vps.port);

      if (portReachable) {
        // 端口可达，标记为验证通过
        vps.verifyStatus = 'verified';
        vps.status = 'active';
        vps.lastVerifyAt = Date.now();
        vps.verifyErrorMsg = undefined;
        await kv.set(['vps', vps.id], vps);

        successCount++;
        details.push({ id: vps.id, ip: vps.ip, status: 'success' });
      } else {
        // 端口不可达，标记为验证失败
        vps.verifyStatus = 'failed';
        vps.status = 'failed'; // 使用 failed 状态
        vps.lastVerifyAt = Date.now();
        vps.verifyErrorMsg = '端口不可达，无法建立连接';
        await kv.set(['vps', vps.id], vps);

        failedCount++;
        details.push({ id: vps.id, ip: vps.ip, status: 'failed', error: vps.verifyErrorMsg });
      }
    } catch (error: any) {
      // 验证过程出错
      vps.verifyStatus = 'failed';
      vps.status = 'failed'; // 使用 failed 状态
      vps.lastVerifyAt = Date.now();
      vps.verifyErrorMsg = error.message || '验证过程中发生错误';
      await kv.set(['vps', vps.id], vps);

      failedCount++;
      details.push({ id: vps.id, ip: vps.ip, status: 'failed', error: vps.verifyErrorMsg });
    }
  }

  return {
    total: pendingVPS.length,
    success: successCount,
    failed: failedCount,
    details
  };
}

// ==================== KV 数据操作 ====================
async function getOAuthConfig(): Promise<OAuthConfig | null> {
  const result = await kv.get<OAuthConfig>(['config', 'oauth']);
  return result.value;
}

async function setOAuthConfig(config: OAuthConfig): Promise<void> {
  await kv.set(['config', 'oauth'], config);
}

async function getAdminPassword(): Promise<string> {
  const result = await kv.get<string>(['config', 'admin_password']);
  return result.value || 'admin123';
}

async function setAdminPassword(password: string): Promise<void> {
  await kv.set(['config', 'admin_password'], password);
}

async function getSession(sessionId: string): Promise<Session | null> {
  const result = await kv.get<Session>(['sessions', sessionId]);
  if (!result.value) return null;

  // 检查是否过期
  if (result.value.expiresAt < Date.now()) {
    await kv.delete(['sessions', sessionId]);
    return null;
  }

  return result.value;
}

async function createSession(userId: string, username: string, avatarUrl: string | undefined, isAdmin: boolean): Promise<string> {
  const sessionId = generateSessionId();
  const session: Session = {
    id: sessionId,
    userId,
    username,
    avatarUrl,
    isAdmin,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7天
  };

  await kv.set(['sessions', sessionId], session);
  return sessionId;
}

async function getUser(linuxDoId: string): Promise<User | null> {
  const result = await kv.get<User>(['users', linuxDoId]);
  return result.value;
}

async function createOrUpdateUser(linuxDoId: string, username: string, avatarUrl?: string): Promise<User> {
  const existing = await getUser(linuxDoId);

  const user: User = {
    linuxDoId,
    username,
    avatarUrl,
    isAdmin: existing?.isAdmin || false,
    createdAt: existing?.createdAt || Date.now(),
  };

  await kv.set(['users', linuxDoId], user);
  return user;
}

async function addVPSServer(server: Omit<VPSServer, 'id'>): Promise<VPSServer> {
  const id = generateId();
  const vps: VPSServer = { id, ...server };

  await kv.set(['vps', id], vps);

  // 添加到用户的投喂列表
  const userDonations = await kv.get<string[]>(['user_donations', server.donatedBy]);
  const donations = userDonations.value || [];
  donations.push(id);
  await kv.set(['user_donations', server.donatedBy], donations);

  return vps;
}

async function getAllVPS(): Promise<VPSServer[]> {
  const entries = kv.list<VPSServer>({ prefix: ['vps'] });
  const servers: VPSServer[] = [];

  for await (const entry of entries) {
    servers.push(entry.value);
  }

  return servers.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function getUserDonations(linuxDoId: string): Promise<VPSServer[]> {
  const userDonations = await kv.get<string[]>(['user_donations', linuxDoId]);
  const donationIds = userDonations.value || [];

  const servers: VPSServer[] = [];
  for (const id of donationIds) {
    const result = await kv.get<VPSServer>(['vps', id]);
    if (result.value) {
      servers.push(result.value);
    }
  }

  return servers.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function deleteVPS(id: string): Promise<boolean> {
  const vps = await kv.get<VPSServer>(['vps', id]);
  if (!vps.value) return false;

  await kv.delete(['vps', id]);

  // 从用户投喂列表中移除
  const userDonations = await kv.get<string[]>(['user_donations', vps.value.donatedBy]);
  if (userDonations.value) {
    const filtered = userDonations.value.filter(vid => vid !== id);
    await kv.set(['user_donations', vps.value.donatedBy], filtered);
  }

  return true;
}

async function updateVPSStatus(id: string, status: 'active' | 'inactive' | 'failed'): Promise<boolean> {
  const result = await kv.get<VPSServer>(['vps', id]);
  if (!result.value) return false;

  result.value.status = status;
  await kv.set(['vps', id], result.value);
  return true;
}

// ==================== OAuth 函数 ====================
async function exchangeCodeForToken(code: string, config: OAuthConfig): Promise<any> {
  const response = await fetch('https://connect.linux.do/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code: code,
      redirect_uri: config.redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  return await response.json();
}

async function getLinuxDoUserInfo(accessToken: string): Promise<any> {
  const response = await fetch('https://connect.linux.do/api/user', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  return await response.json();
}

// ==================== 中间件 ====================
async function requireAuth(c: any, next: any) {
  const sessionId = getCookie(c, 'session_id');

  console.log(`[Auth] 检查认证，sessionId: ${sessionId ? '存在' : '不存在'}`);

  if (!sessionId) {
    console.log(`[Auth] 认证失败：无sessionId`);
    return c.json({ success: false, message: '未登录' }, 401);
  }

  const session = await getSession(sessionId);
  if (!session) {
    console.log(`[Auth] 认证失败：会话不存在或已过期`);
    return c.json({ success: false, message: '会话已过期' }, 401);
  }

  console.log(`[Auth] 认证成功：用户 ${session.username}`);
  c.set('session', session);
  await next();
}

async function requireAdmin(c: any, next: any) {
  const sessionId = getCookie(c, 'admin_session_id'); // 使用独立的cookie名称

  console.log(`[Admin Auth] 检查管理员权限，admin_session_id: ${sessionId ? '存在' : '不存在'}`);

  if (!sessionId) {
    console.log(`[Admin Auth] 认证失败：无admin_session_id`);
    return c.json({ success: false, message: '未登录' }, 401);
  }

  const session = await getSession(sessionId);
  if (!session || !session.isAdmin) {
    console.log(`[Admin Auth] 认证失败：${!session ? '会话不存在' : '非管理员'}`);
    return c.json({ success: false, message: '需要管理员权限' }, 403);
  }

  console.log(`[Admin Auth] 认证成功：管理员 ${session.username}`);
  c.set('session', session);
  await next();
}

// ==================== 创建应用 ====================
const app = new Hono();

app.use('*', cors());

// ==================== API 路由 ====================

// OAuth 回调
app.get('/oauth/callback', async (c) => {
  const code = c.req.query('code');
  const error = c.req.query('error');

  if (error) {
    return c.html(`
      <!DOCTYPE html>
      <html><body>
        <h1>登录失败</h1>
        <p>OAuth 认证失败: ${error}</p>
        <a href="/donate">返回首页</a>
      </body></html>
    `);
  }

  if (!code) {
    return c.text('Missing code', 400);
  }

  try {
    const config = await getOAuthConfig();
    if (!config) {
      return c.html(`
        <!DOCTYPE html>
        <html><body>
          <h1>配置错误</h1>
          <p>OAuth 配置未设置，请联系管理员</p>
          <a href="/donate">返回首页</a>
        </body></html>
      `);
    }

    const tokenData = await exchangeCodeForToken(code, config);
    const userInfo = await getLinuxDoUserInfo(tokenData.access_token);

    // LinuxDo 返回的是 avatar_template，需要替换尺寸参数
    let avatarUrl = userInfo.avatar_template;
    if (avatarUrl) {
      // 将 {size} 替换为实际尺寸，并确保是完整URL
      avatarUrl = avatarUrl.replace('{size}', '120');
      if (avatarUrl.startsWith('//')) {
        avatarUrl = 'https:' + avatarUrl;
      } else if (avatarUrl.startsWith('/')) {
        avatarUrl = 'https://connect.linux.do' + avatarUrl;
      }
    }

    const user = await createOrUpdateUser(
      userInfo.id.toString(),
      userInfo.username,
      avatarUrl
    );

    const sessionId = await createSession(
      user.linuxDoId,
      user.username,
      user.avatarUrl,
      user.isAdmin
    );

    console.log(`[OAuth] 用户 ${user.username} 登录成功，创建会话: ${sessionId}`);

    // 根据环境判断是否使用secure
    const isProduction = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;

    setCookie(c, 'session_id', sessionId, {
      maxAge: 7 * 24 * 60 * 60,
      httpOnly: true,
      secure: isProduction, // 只在生产环境使用secure
      sameSite: 'Lax',
      path: '/',
    });

    console.log(`[OAuth] Cookie已设置，跳转到 /donate`);

    return c.redirect('/donate');
  } catch (e: any) {
    console.error('OAuth callback failed:', e);
    return c.html(`
      <!DOCTYPE html>
      <html><body>
        <h1>登录失败</h1>
        <p>错误详情: ${e.message}</p>
        <a href="/donate">返回首页</a>
      </body></html>
    `);
  }
});

// 登出
app.get('/api/logout', async (c) => {
  const sessionId = getCookie(c, 'session_id');
  console.log(`[Logout] 用户登出，session_id: ${sessionId ? '存在' : '不存在'}`);

  if (sessionId) {
    await kv.delete(['sessions', sessionId]);
    console.log(`[Logout] 已删除会话: ${sessionId}`);
  }

  setCookie(c, 'session_id', '', { maxAge: 0, path: '/' });
  console.log(`[Logout] 已清除cookie`);

  return c.json({ success: true });
});

// 获取当前用户信息
app.get('/api/user/info', requireAuth, async (c) => {
  const session = c.get('session');
  const donations = await getUserDonations(session.userId);

  return c.json({
    success: true,
    data: {
      username: session.username,
      avatarUrl: session.avatarUrl,
      isAdmin: session.isAdmin,
      donationCount: donations.length,
    },
  });
});

// 获取用户的投喂记录
app.get('/api/user/donations', requireAuth, async (c) => {
  const session = c.get('session');
  const donations = await getUserDonations(session.userId);

  // 隐藏敏感信息，但保留验证相关信息
  const safeDonations = donations.map(d => ({
    id: d.id,
    ip: d.ip,
    port: d.port,
    username: d.username,
    authType: d.authType,
    donatedAt: d.donatedAt,
    status: d.status,
    note: d.note,
    verifyStatus: d.verifyStatus,
    verifyCode: d.verifyCode,
    verifyFilePath: d.verifyFilePath,
    lastVerifyAt: d.lastVerifyAt,
    verifyErrorMsg: d.verifyErrorMsg,
  }));

  return c.json({ success: true, data: safeDonations });
});

// 投喂 VPS
app.post('/api/donate', requireAuth, async (c) => {
  const session = c.get('session');
  const body = await c.req.json();

  const { ip, port, username, authType, password, privateKey, note } = body;

  console.log(`[Donate] 用户 ${session.username} 尝试投喂 VPS: ${username}@${ip}:${port}`);

  // 验证必填字段
  if (!ip || !port || !username || !authType) {
    console.log(`[Donate] 验证失败：缺少必填字段`);
    return c.json({ success: false, message: 'IP、端口、用户名和认证类型为必填项' }, 400);
  }

  if (authType === 'password' && !password) {
    console.log(`[Donate] 验证失败：缺少密码`);
    return c.json({ success: false, message: '密码认证需要提供密码' }, 400);
  }

  if (authType === 'key' && !privateKey) {
    console.log(`[Donate] 验证失败：缺少私钥`);
    return c.json({ success: false, message: '密钥认证需要提供私钥' }, 400);
  }

  // 验证 IP 格式（支持 IPv4 和 IPv6）
  if (!isValidIP(ip)) {
    console.log(`[Donate] 验证失败：IP格式不正确 - ${ip}`);
    return c.json({ success: false, message: 'IP 地址格式不正确（支持 IPv4 和 IPv6）' }, 400);
  }

  // 验证端口范围
  if (port < 1 || port > 65535) {
    console.log(`[Donate] 验证失败：端口范围错误 - ${port}`);
    return c.json({ success: false, message: '端口号必须在 1-65535 之间' }, 400);
  }

  // 检查IP+端口是否已存在
  console.log(`[Donate] 检查IP是否已存在...`);
  const ipExists = await checkIPExists(ip, parseInt(port));
  if (ipExists) {
    console.log(`[Donate] 验证失败：IP已存在 - ${ip}:${port}`);
    return c.json({ success: false, message: '该 IP 和端口已经被投喂过了' }, 400);
  }

  // 检查端口可达性
  console.log(`[Donate] 检查端口可达性...`);
  const portReachable = await checkPortReachable(ip, parseInt(port));
  if (!portReachable) {
    console.log(`[Donate] 验证失败：端口不可达 - ${ip}:${port}`);
    return c.json({ success: false, message: '无法连接到该服务器，请检查 IP 和端口是否正确' }, 400);
  }

  try {
    // 端口可达即视为验证通过
    console.log(`[Donate] 端口可达，自动验证通过`);

    const vps = await addVPSServer({
      ip,
      port: parseInt(port),
      username,
      authType,
      password: authType === 'password' ? password : undefined,
      privateKey: authType === 'key' ? privateKey : undefined,
      donatedBy: session.userId,
      donatedByUsername: session.username,
      donatedAt: Date.now(),
      status: 'active', // 端口可达自动激活
      note: note || '',
      verifyStatus: 'verified', // 自动验证通过
      verifyCode: undefined,
      verifyFilePath: undefined,
      lastVerifyAt: Date.now(),
    });

    console.log(`[Donate] ✅ 投喂成功 - 用户: ${session.username}, VPS: ${username}@${ip}:${port}`);

    return c.json({
      success: true,
      message: '✅ 投喂成功！VPS 已自动验证并激活',
      data: {
        id: vps.id,
        ip: vps.ip,
        port: vps.port,
      },
    });
  } catch (e: any) {
    console.error('[Donate] ❌ 投喂失败:', e);
    return c.json({ success: false, message: '投喂失败: ' + e.message }, 500);
  }
});

// ==================== 管理员 API ====================

// 检查管理员会话
app.get('/api/admin/check-session', async (c) => {
  const sessionId = getCookie(c, 'admin_session_id'); // 使用独立的cookie名称
  console.log(`[Admin] 检查管理员会话，admin_session_id: ${sessionId ? '存在' : '不存在'}`);

  if (!sessionId) {
    return c.json({ success: false, isAdmin: false });
  }

  const session = await getSession(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    console.log(`[Admin] 会话不存在或已过期`);
    return c.json({ success: false, isAdmin: false });
  }

  console.log(`[Admin] 会话有效：${session.username}, isAdmin: ${session.isAdmin}`);
  return c.json({
    success: true,
    isAdmin: session.isAdmin || false,
    username: session.username
  });
});

// 管理员登录
app.post('/api/admin/login', async (c) => {
  const { password } = await c.req.json();
  const adminPassword = await getAdminPassword();

  console.log(`[Admin] 管理员登录尝试`);

  if (password !== adminPassword) {
    console.log(`[Admin] 密码错误`);
    return c.json({ success: false, message: '密码错误' }, 401);
  }

  // 创建管理员专用会话（不需要 LinuxDo 登录）
  const sessionId = generateSessionId();
  const adminSession: Session = {
    id: sessionId,
    userId: 'admin',
    username: 'Administrator',
    avatarUrl: undefined,
    isAdmin: true,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7天
  };

  await kv.set(['sessions', sessionId], adminSession);

  console.log(`[Admin] 管理员登录成功，创建会话: ${sessionId}`);

  // 根据环境判断是否使用secure
  const isProduction = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;

  // 使用独立的cookie名称 admin_session_id
  setCookie(c, 'admin_session_id', sessionId, {
    maxAge: 7 * 24 * 60 * 60,
    httpOnly: true,
    secure: isProduction, // 只在生产环境使用secure
    sameSite: 'Lax',
    path: '/',
  });

  console.log(`[Admin] Cookie已设置（admin_session_id）`);

  return c.json({ success: true, message: '登录成功' });
});

// 管理员登出
app.get('/api/admin/logout', async (c) => {
  const sessionId = getCookie(c, 'admin_session_id');
  console.log(`[Admin] 管理员登出，admin_session_id: ${sessionId ? '存在' : '不存在'}`);

  if (sessionId) {
    await kv.delete(['sessions', sessionId]);
    console.log(`[Admin] 已删除会话: ${sessionId}`);
  }

  setCookie(c, 'admin_session_id', '', { maxAge: 0, path: '/' });
  console.log(`[Admin] 已清除cookie`);

  return c.json({ success: true });
});

// 获取所有 VPS（管理员）
app.get('/api/admin/vps', requireAdmin, async (c) => {
  const servers = await getAllVPS();
  return c.json({ success: true, data: servers });
});

// 删除 VPS（管理员）
app.delete('/api/admin/vps/:id', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const success = await deleteVPS(id);

  if (success) {
    return c.json({ success: true, message: 'VPS 已删除' });
  } else {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }
});

// 更新 VPS 状态（管理员）
app.put('/api/admin/vps/:id/status', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const { status } = await c.req.json();

  if (status !== 'active' && status !== 'inactive' && status !== 'failed') {
    return c.json({ success: false, message: '无效的状态' }, 400);
  }

  const success = await updateVPSStatus(id, status);

  if (success) {
    return c.json({ success: true, message: '状态已更新' });
  } else {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }
});

// 获取 OAuth 配置（管理员）
app.get('/api/admin/config/oauth', requireAdmin, async (c) => {
  const config = await getOAuthConfig();
  return c.json({ success: true, data: config || {} });
});

// 更新 OAuth 配置（管理员）
app.put('/api/admin/config/oauth', requireAdmin, async (c) => {
  const { clientId, clientSecret, redirectUri } = await c.req.json();

  if (!clientId || !clientSecret || !redirectUri) {
    return c.json({ success: false, message: '所有字段都是必填的' }, 400);
  }

  await setOAuthConfig({ clientId, clientSecret, redirectUri });
  return c.json({ success: true, message: 'OAuth 配置已更新' });
});

// 更新管理员密码
app.put('/api/admin/config/password', requireAdmin, async (c) => {
  const { password } = await c.req.json();

  if (!password || password.length < 6) {
    return c.json({ success: false, message: '密码至少需要 6 个字符' }, 400);
  }

  await setAdminPassword(password);
  return c.json({ success: true, message: '管理员密码已更新' });
});

// 获取统计信息（管理员）
app.get('/api/admin/stats', requireAdmin, async (c) => {
  const allVPS = await getAllVPS();
  const activeVPS = allVPS.filter(v => v.status === 'active');
  const failedVPS = allVPS.filter(v => v.status === 'failed');
  const pendingVPS = allVPS.filter(v => v.verifyStatus === 'pending');
  const verifiedVPS = allVPS.filter(v => v.verifyStatus === 'verified');

  // 统计用户投喂数量
  const userStats = new Map<string, number>();
  for (const vps of allVPS) {
    const count = userStats.get(vps.donatedByUsername) || 0;
    userStats.set(vps.donatedByUsername, count + 1);
  }

  const topDonors = Array.from(userStats.entries())
    .map(([username, count]) => ({ username, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return c.json({
    success: true,
    data: {
      totalVPS: allVPS.length,
      activeVPS: activeVPS.length,
      failedVPS: failedVPS.length,
      inactiveVPS: allVPS.length - activeVPS.length - failedVPS.length,
      pendingVPS: pendingVPS.length,
      verifiedVPS: verifiedVPS.length,
      topDonors,
    },
  });
});

// 标记VPS为已验证（管理员手动通过）
app.post('/api/admin/vps/:id/mark-verified', requireAdmin, async (c) => {
  const id = c.req.param('id');
  const result = await kv.get<VPSServer>(['vps', id]);

  if (!result.value) {
    return c.json({ success: false, message: 'VPS 不存在' }, 404);
  }

  const vps = result.value;
  vps.verifyStatus = 'verified';
  vps.status = 'active';
  vps.lastVerifyAt = Date.now();
  await kv.set(['vps', id], vps);

  return c.json({ success: true, message: 'VPS 已标记为验证通过' });
});

// 批量验证VPS（管理员）
app.post('/api/admin/vps/batch-verify', requireAdmin, async (c) => {
  console.log('[Admin] 开始批量验证 VPS...');

  try {
    const result = await batchVerifyVPS();

    console.log(`[Admin] 批量验证完成 - 总数: ${result.total}, 成功: ${result.success}, 失败: ${result.failed}`);

    return c.json({
      success: true,
      message: `验证完成！成功: ${result.success}，失败: ${result.failed}`,
      data: result
    });
  } catch (error: any) {
    console.error('[Admin] 批量验证失败:', error);
    return c.json({ success: false, message: '批量验证失败: ' + error.message }, 500);
  }
});

// ==================== 页面路由 ====================

// 首页 - 投喂界面
app.get('/donate', async (c) => {
  const config = await getOAuthConfig();
  const html = generateDonateHTML(config?.clientId || '');
  return c.html(html);
});

// 管理员界面
app.get('/admin', async (c) => {
  const html = generateAdminHTML();
  return c.html(html);
});

// 根路径重定向到投喂页面
app.get('/', (c) => c.redirect('/donate'));

// ==================== HTML 生成函数 ====================
function generateDonateHTML(clientId: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>风萧萧公益-闲置小鸡投喂站</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes slideInRight {
      from {
        opacity: 0;
        transform: translateX(100%);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }
    @keyframes slideOutRight {
      from {
        opacity: 1;
        transform: translateX(0);
      }
      to {
        opacity: 0;
        transform: translateX(100%);
      }
    }
    .animate-in { animation: fadeIn 0.5s ease-out; }
    .toast-container {
      position: fixed;
      top: 80px;
      right: 20px;
      z-index: 9999;
      pointer-events: none;
    }
    .toast {
      pointer-events: auto;
      min-width: 300px;
      max-width: 500px;
      margin-bottom: 12px;
      padding: 16px 20px;
      border-radius: 12px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15), 0 0 0 1px rgba(0, 0, 0, 0.05);
      animation: slideInRight 0.3s ease-out;
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 14px;
      font-weight: 500;
    }
    .toast.hiding {
      animation: slideOutRight 0.3s ease-out forwards;
    }
    .toast-icon {
      font-size: 20px;
      flex-shrink: 0;
    }
    .toast-success {
      background: linear-gradient(135deg, #10B981 0%, #059669 100%);
      color: white;
    }
    .toast-error {
      background: linear-gradient(135deg, #EF4444 0%, #DC2626 100%);
      color: white;
    }
    .toast-info {
      background: linear-gradient(135deg, #3B82F6 0%, #2563EB 100%);
      color: white;
    }
    .card-hover {
      transition: all 0.2s ease;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
    }
    .card-hover:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
    }
    .btn-primary {
      background-color: #1a1a1a;
      transition: all 0.2s;
    }
    .btn-primary:hover {
      background-color: #000000;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }
    .btn-secondary {
      background-color: white;
      border: 1px solid #e5e5e5;
      transition: all 0.2s;
    }
    .btn-secondary:hover {
      border-color: #1a1a1a;
    }
    .user-dropdown {
      position: absolute;
      top: 100%;
      right: 0;
      margin-top: 8px;
      background: white;
      border: 1px solid #F3F4F6;
      border-radius: 12px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      min-width: 200px;
      overflow: hidden;
      opacity: 0;
      transform: translateY(-10px);
      pointer-events: none;
      transition: all 0.2s ease;
      z-index: 100;
    }
    .user-dropdown.show {
      opacity: 1;
      transform: translateY(0);
      pointer-events: auto;
    }
    .dropdown-item {
      padding: 12px 16px;
      cursor: pointer;
      transition: background 0.2s;
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
    }
    .dropdown-item:hover {
      background: #F9FAFB;
    }
    .dropdown-divider {
      height: 1px;
      background: #F3F4F6;
      margin: 4px 0;
    }
    .dropdown-header {
      padding: 12px 16px;
      background: #F9FAFB;
      font-weight: 600;
      font-size: 14px;
    }
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s ease;
    }
    .modal-overlay.show {
      opacity: 1;
      pointer-events: auto;
    }
    .modal-content {
      background: white;
      border-radius: 16px;
      max-width: 800px;
      width: 90%;
      max-height: 80vh;
      overflow: hidden;
      transform: scale(0.9);
      transition: transform 0.3s ease;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    }
    .modal-overlay.show .modal-content {
      transform: scale(1);
    }
    .modal-header {
      padding: 20px 24px;
      border-bottom: 1px solid #F3F4F6;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .modal-body {
      padding: 24px;
      max-height: calc(80vh - 140px);
      overflow-y: auto;
    }
    .modal-footer {
      padding: 16px 24px;
      border-top: 1px solid #F3F4F6;
      display: flex;
      justify-content: flex-end;
    }
    @keyframes spin {
      from {
        transform: rotate(0deg);
      }
      to {
        transform: rotate(360deg);
      }
    }
    .animate-spin {
      animation: spin 1s linear infinite;
    }
  </style>
</head>
<body class="min-h-screen" style="background-color: #FAF9F8;">

  <!-- Toast 容器 -->
  <div id="toastContainer" class="toast-container"></div>

  <!-- 导航栏 -->
  <nav class="bg-white fixed top-0 left-0 right-0 z-50" style="border-bottom: 1px solid #F3F4F6; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);">
    <div class="max-w-4xl mx-auto px-6 py-4 flex justify-between items-center">
      <h1 class="text-2xl font-bold text-slate-900">
        风萧萧公益-闲置小鸡投喂站
      </h1>
      <div id="userInfo" class="hidden items-center gap-4 relative">
        <div class="flex items-center gap-2 cursor-pointer" onclick="toggleUserDropdown()">
          <div id="userAvatar" class="w-10 h-10 rounded-full bg-slate-200 flex items-center justify-center text-slate-700 font-bold">
            <span id="userInitial">U</span>
          </div>
          <div>
            <p id="userName" class="text-sm font-semibold text-slate-900"></p>
            <p id="donationCount" class="text-xs text-slate-500"></p>
          </div>
          <svg class="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
          </svg>
        </div>

        <!-- 用户下拉菜单 -->
        <div id="userDropdown" class="user-dropdown">
          <div class="dropdown-header">
            <div class="flex items-center gap-2">
              <span>👤</span>
              <span id="dropdownUserName"></span>
            </div>
            <div id="dropdownDonationCount" class="text-xs text-slate-500 mt-1"></div>
          </div>
          <div class="dropdown-divider"></div>
          <div class="dropdown-item" onclick="showDonationsModal()">
            <span>📋</span>
            <span>投喂记录</span>
          </div>
          <div class="dropdown-divider"></div>
          <div class="dropdown-item" onclick="logout()" style="color: #DC2626;">
            <span>🚪</span>
            <span>退出登录</span>
          </div>
        </div>
      </div>
      <button id="loginBtn" onclick="login()" class="btn-primary text-white px-6 py-2 rounded-lg font-semibold">
        LinuxDo 登录
      </button>
    </div>
  </nav>

  <!-- 主内容 -->
  <div class="max-w-4xl mx-auto p-6 pt-24">

    <!-- 欢迎卡片 -->
    <div class="bg-white rounded-xl p-5 mb-4 animate-in card-hover" style="border: 1px solid #F3F4F6;">
      <h2 class="text-2xl font-bold mb-1 text-slate-900">欢迎来到 风萧萧公益-闲置小鸡投喂站！</h2>
      <p class="text-base text-slate-600">分享您的闲置小鸡，让资源得到更好的利用 💝</p>
    </div>

    <!-- 投喂表单 -->
    <div id="donateForm" class="hidden bg-white rounded-xl p-6 animate-in card-hover mb-4" style="border: 1px solid #F3F4F6;">
      <h3 class="text-xl font-bold text-slate-900 mb-5">💝 投喂你的闲置小鸡</h3>

      <div class="space-y-3.5">
        <div class="grid grid-cols-3 gap-3">
          <div>
            <label class="block text-sm font-semibold text-slate-700 mb-1.5">服务器 IP *</label>
            <input id="ipInput" type="text" placeholder="192.168.1.100 或 2001:db8::1"
              class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm">
          </div>
          <div>
            <label class="block text-sm font-semibold text-slate-700 mb-1.5">SSH 端口 *</label>
            <input id="portInput" type="number" placeholder="22" value="22"
              class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm">
          </div>
          <div>
            <label class="block text-sm font-semibold text-slate-700 mb-1.5">登录用户名 *</label>
            <input id="usernameInput" type="text" placeholder="root" value="root"
              class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm">
          </div>
        </div>

        <div>
          <label class="block text-sm font-semibold text-slate-700 mb-1.5">认证方式 *</label>
          <select id="authTypeSelect" onchange="toggleAuthFields()"
            class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm">
            <option value="password">密码认证</option>
            <option value="key">密钥认证</option>
          </select>
        </div>

        <div id="passwordField">
          <label class="block text-sm font-semibold text-slate-700 mb-1.5">SSH 密码 *</label>
          <input id="passwordInput" type="password" placeholder="请输入 SSH 密码"
            class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm">
        </div>

        <div id="keyField" class="hidden">
          <label class="block text-sm font-semibold text-slate-700 mb-1.5">SSH 私钥 *</label>
          <textarea id="keyInput" placeholder="请粘贴完整的 SSH 私钥内容" rows="4"
            class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-mono text-xs"></textarea>
        </div>

        <div>
          <label class="block text-sm font-semibold text-slate-700 mb-1.5">备注（可选）</label>
          <input id="noteInput" type="text" placeholder="例如: 阿里云香港 2C4G"
            class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm">
        </div>

        <button onclick="submitDonation()"
          class="w-full btn-primary text-white py-3.5 rounded-lg font-bold text-base mt-2">
          🚀 提交投喂
        </button>
      </div>
    </div>

    <!-- 未登录提示 -->
    <div id="loginPrompt" class="bg-white rounded-xl p-12 text-center animate-in card-hover" style="border: 1px solid #F3F4F6;">
      <div class="text-6xl mb-4">🔐</div>
      <h3 class="text-2xl font-bold text-slate-900 mb-3">请先登录</h3>
      <p class="text-slate-600 mb-6">使用 LinuxDo 账号登录后即可投喂 VPS 服务器</p>
      <button onclick="login()"
        class="btn-primary text-white px-8 py-3 rounded-lg font-semibold">
        LinuxDo 登录
      </button>
    </div>
  </div>

  <!-- 投喂记录模态框 -->
  <div id="donationsModal" class="modal-overlay" onclick="closeDonationsModal(event)">
    <div class="modal-content" onclick="event.stopPropagation()">
      <div class="modal-header">
        <h3 class="text-xl font-bold text-slate-900">📋 我的投喂记录</h3>
        <button onclick="closeDonationsModal()" class="text-slate-400 hover:text-slate-600 transition-colors">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
          </svg>
        </button>
      </div>
      <div class="modal-body">
        <div id="donationsList" class="space-y-3"></div>
      </div>
      <div class="modal-footer">
        <button onclick="closeDonationsModal()" class="btn-primary text-white px-6 py-2 rounded-lg font-semibold">
          关闭
        </button>
      </div>
    </div>
  </div>

  <script>
    const CLIENT_ID = '${clientId}';
    const AUTH_URL = 'https://connect.linux.do/oauth2/authorize';
    const REDIRECT_URI = window.location.origin + '/oauth/callback';

    let currentUser = null;

    async function checkAuth() {
      console.log('[前端] 检查登录状态...');
      try {
        const res = await fetch('/api/user/info', {
          credentials: 'same-origin' // 确保发送cookie
        });
        console.log('[前端] 收到认证响应，状态码:', res.status);
        const data = await res.json();
        console.log('[前端] 认证数据:', data);

        if (data.success) {
          console.log('[前端] 用户已登录:', data.data.username);
          currentUser = data.data;
          showUserInfo(data.data);
        } else {
          console.log('[前端] 用户未登录，显示登录提示');
          showLoginPrompt();
        }
      } catch (e) {
        console.error('[前端] 检查登录状态失败:', e);
        showLoginPrompt();
      }
    }

    function showUserInfo(user) {
      document.getElementById('loginBtn').classList.add('hidden');
      document.getElementById('userInfo').classList.remove('hidden');
      document.getElementById('userInfo').classList.add('flex');
      document.getElementById('userName').textContent = '@' + user.username;
      document.getElementById('donationCount').textContent = \`已投喂 \${user.donationCount} 台\`;

      // 更新下拉菜单中的信息
      document.getElementById('dropdownUserName').textContent = '@' + user.username;
      document.getElementById('dropdownDonationCount').textContent = \`已投喂 \${user.donationCount} 台\`;

      // 设置头像
      const avatarDiv = document.getElementById('userAvatar');
      const initialSpan = document.getElementById('userInitial');

      if (user.avatarUrl) {
        // 有头像URL，显示图片
        avatarDiv.style.backgroundImage = \`url(\${user.avatarUrl})\`;
        avatarDiv.style.backgroundSize = 'cover';
        avatarDiv.style.backgroundPosition = 'center';
        initialSpan.style.display = 'none';
      } else {
        // 没有头像，显示首字母
        initialSpan.textContent = user.username[0].toUpperCase();
        initialSpan.style.display = 'block';
      }

      document.getElementById('loginPrompt').classList.add('hidden');
      document.getElementById('donateForm').classList.remove('hidden');
    }

    function showLoginPrompt() {
      document.getElementById('loginBtn').classList.remove('hidden');
      document.getElementById('userInfo').classList.add('hidden');
      document.getElementById('loginPrompt').classList.remove('hidden');
      document.getElementById('donateForm').classList.add('hidden');
    }

    function toggleUserDropdown() {
      const dropdown = document.getElementById('userDropdown');
      dropdown.classList.toggle('show');
    }

    // 点击页面其他地方关闭下拉菜单
    document.addEventListener('click', (e) => {
      const userInfo = document.getElementById('userInfo');
      const dropdown = document.getElementById('userDropdown');
      if (userInfo && !userInfo.contains(e.target)) {
        dropdown.classList.remove('show');
      }
    });

    function showDonationsModal() {
      // 关闭下拉菜单
      document.getElementById('userDropdown').classList.remove('show');

      // 显示模态框
      const modal = document.getElementById('donationsModal');
      modal.classList.add('show');

      // 加载投喂记录
      loadDonations();
    }

    function closeDonationsModal(event) {
      const modal = document.getElementById('donationsModal');
      modal.classList.remove('show');
    }

    function login() {
      if (!CLIENT_ID) {
        showToast('OAuth 配置未设置，请联系管理员', 'error');
        return;
      }
      const url = \`\${AUTH_URL}?client_id=\${CLIENT_ID}&redirect_uri=\${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=read\`;
      window.location.href = url;
    }

    async function logout() {
      console.log('[用户前端] 登出...');

      // 关闭下拉菜单
      const dropdown = document.getElementById('userDropdown');
      if (dropdown) {
        dropdown.classList.remove('show');
      }

      await fetch('/api/logout');
      window.location.reload();
    }

    function toggleAuthFields() {
      const authType = document.getElementById('authTypeSelect').value;
      const passwordField = document.getElementById('passwordField');
      const keyField = document.getElementById('keyField');

      if (authType === 'password') {
        passwordField.classList.remove('hidden');
        keyField.classList.add('hidden');
      } else {
        passwordField.classList.add('hidden');
        keyField.classList.remove('hidden');
      }
    }

    async function submitDonation() {
      const ip = document.getElementById('ipInput').value.trim();
      const port = document.getElementById('portInput').value.trim();
      const username = document.getElementById('usernameInput').value.trim();
      const authType = document.getElementById('authTypeSelect').value;
      const password = document.getElementById('passwordInput').value;
      const privateKey = document.getElementById('keyInput').value;
      const note = document.getElementById('noteInput').value.trim();

      console.log('提交投喂，IP:', ip, 'Port:', port, 'Username:', username);

      if (!ip || !port || !username) {
        showToast('请填写 IP 地址、端口和用户名', 'error');
        return;
      }

      if (authType === 'password' && !password) {
        showToast('请填写 SSH 密码', 'error');
        return;
      }

      if (authType === 'key' && !privateKey) {
        showToast('请填写 SSH 私钥', 'error');
        return;
      }

      // 禁用提交按钮，显示加载状态
      const submitBtn = document.querySelector('[onclick="submitDonation()"]');
      const originalText = submitBtn.textContent;
      submitBtn.disabled = true;
      submitBtn.textContent = '⏳ 提交中...';
      submitBtn.classList.add('opacity-50', 'cursor-not-allowed');

      try {
        console.log('发送投喂请求...');
        const res = await fetch('/api/donate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, port, username, authType, password, privateKey, note }),
          credentials: 'same-origin', // 确保发送cookie
        });

        console.log('收到响应，状态码:', res.status);
        const data = await res.json();
        console.log('响应数据:', data);

        if (data.success) {
          // 显示简洁的成功消息
          showToast('✅ 投喂成功！VPS 已自动验证并激活', 'success');

          // 清空表单
          document.getElementById('ipInput').value = '';
          document.getElementById('portInput').value = '22';
          document.getElementById('usernameInput').value = 'root';
          document.getElementById('passwordInput').value = '';
          document.getElementById('keyInput').value = '';
          document.getElementById('noteInput').value = '';

          // 更新投喂数量
          if (currentUser) {
            currentUser.donationCount += 1;
            document.getElementById('donationCount').textContent = \`已投喂 \${currentUser.donationCount} 台\`;
            document.getElementById('dropdownDonationCount').textContent = \`已投喂 \${currentUser.donationCount} 台\`;
          }
        } else {
          console.error('投喂失败:', data.message);
          showToast(data.message, 'error');
        }
      } catch (e) {
        console.error('提交投喂异常:', e);
        showToast('提交失败: ' + e.message + '。请检查网络连接并重试', 'error');
      } finally {
        // 恢复按钮状态
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
        submitBtn.classList.remove('opacity-50', 'cursor-not-allowed');
      }
    }

    async function loadDonations() {
      try {
        const res = await fetch('/api/user/donations');
        const data = await res.json();

        if (data.success && data.data.length > 0) {
          const html = data.data.map(d => {
            // 验证状态显示 - 简化版本，不显示验证码
            let verifyStatusHTML = '';
            if (d.verifyStatus === 'pending') {
              verifyStatusHTML = \`<span class="text-xs text-yellow-600">⏳ 待验证</span>\`;
            } else if (d.verifyStatus === 'verified') {
              verifyStatusHTML = \`<span class="text-xs text-green-600">✅ 已验证</span>\`;
            } else if (d.verifyStatus === 'failed') {
              verifyStatusHTML = \`<span class="text-xs text-red-600">❌ 验证失败</span>\`;
            }

            return \`
              <div class="p-3 rounded-lg bg-slate-50 hover:bg-slate-100 transition-colors" style="border: 1px solid #E5E7EB;">
                <div class="flex justify-between items-start mb-2">
                  <div class="flex-1">
                    <p class="font-semibold text-slate-900 text-sm">\${d.username}@\${d.ip}:\${d.port}</p>
                    <div class="flex items-center gap-2 mt-1">
                      <span class="text-xs text-slate-600">\${d.authType === 'password' ? '🔑 密码' : '🔐 密钥'}</span>
                      <span class="text-xs text-slate-400">|</span>
                      \${verifyStatusHTML}
                      <span class="text-xs text-slate-400">|</span>
                      <span class="px-2 py-0.5 rounded-full text-xs font-semibold \${
                        d.status === 'active' ? 'bg-green-100 text-green-700' :
                        d.status === 'failed' ? 'bg-red-100 text-red-700' :
                        'bg-slate-200 text-slate-600'
                      }">
                        \${d.status === 'active' ? '✓ 活跃' : d.status === 'failed' ? '✕ 失败' : '○ 停用'}
                      </span>
                    </div>
                  </div>
                </div>
                \${d.note ? \`<p class="text-xs text-slate-500 mb-1">📝 \${d.note}</p>\` : ''}
                <p class="text-xs text-slate-400">\${new Date(d.donatedAt).toLocaleString('zh-CN')}</p>
              </div>
            \`;
          }).join('');
          document.getElementById('donationsList').innerHTML = html;
        } else {
          document.getElementById('donationsList').innerHTML = '<div class="text-center py-12"><p class="text-slate-400 text-sm">暂无投喂记录</p><p class="text-slate-300 text-xs mt-2">投喂您的第一台闲置VPS吧！</p></div>';
        }
      } catch (e) {
        console.error('加载投喂记录失败', e);
        document.getElementById('donationsList').innerHTML = '<div class="text-center py-12"><p class="text-red-400 text-sm">加载失败，请稍后重试</p></div>';
      }
    }

    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');

      // 创建toast元素
      const toast = document.createElement('div');
      toast.className = \`toast toast-\${type}\`;

      // 图标
      const icon = document.createElement('div');
      icon.className = 'toast-icon';
      icon.textContent = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';

      // 消息文本
      const text = document.createElement('div');
      text.textContent = message;
      text.style.flex = '1';

      toast.appendChild(icon);
      toast.appendChild(text);
      container.appendChild(toast);

      // 自动移除
      setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => {
          if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
          }
        }, 300);
      }, 3000);
    }

    // 页面加载时检查登录状态
    checkAuth();
  </script>
</body>
</html>`;
}

function generateAdminHTML(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理员后台 - VPS 投喂站</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes slideInRight {
      from {
        opacity: 0;
        transform: translateX(100%);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }
    @keyframes slideOutRight {
      from {
        opacity: 1;
        transform: translateX(0);
      }
      to {
        opacity: 0;
        transform: translateX(100%);
      }
    }
    .animate-in { animation: fadeIn 0.5s ease-out; }
    .toast-container {
      position: fixed;
      top: 80px;
      right: 20px;
      z-index: 9999;
      pointer-events: none;
    }
    .toast {
      pointer-events: auto;
      min-width: 300px;
      max-width: 500px;
      margin-bottom: 12px;
      padding: 16px 20px;
      border-radius: 12px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15), 0 0 0 1px rgba(0, 0, 0, 0.05);
      animation: slideInRight 0.3s ease-out;
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 14px;
      font-weight: 500;
    }
    .toast.hiding {
      animation: slideOutRight 0.3s ease-out forwards;
    }
    .toast-icon {
      font-size: 20px;
      flex-shrink: 0;
    }
    .toast-success {
      background: linear-gradient(135deg, #10B981 0%, #059669 100%);
      color: white;
    }
    .toast-error {
      background: linear-gradient(135deg, #EF4444 0%, #DC2626 100%);
      color: white;
    }
    .toast-info {
      background: linear-gradient(135deg, #3B82F6 0%, #2563EB 100%);
      color: white;
    }
    .card-hover {
      transition: all 0.2s ease;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
    }
    .card-hover:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
    }
    .btn-primary {
      background-color: #1a1a1a;
      transition: all 0.2s;
    }
    .btn-primary:hover {
      background-color: #000000;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }
    .btn-secondary {
      background-color: white;
      border: 1px solid #e5e5e5;
      transition: all 0.2s;
    }
    .btn-secondary:hover {
      border-color: #1a1a1a;
    }
    .tab-button {
      transition: all 0.2s;
    }
    .tab-button.active {
      background-color: #1a1a1a;
      color: white;
    }
    @keyframes spin {
      from {
        transform: rotate(0deg);
      }
      to {
        transform: rotate(360deg);
      }
    }
    .animate-spin {
      animation: spin 1s linear infinite;
    }
  </style>
</head>
<body class="min-h-screen" style="background-color: #FAF9F8;">

  <!-- Toast 容器 -->
  <div id="toastContainer" class="toast-container"></div>

  <!-- 导航栏 -->
  <nav class="bg-white fixed top-0 left-0 right-0 z-50" style="border-bottom: 1px solid #F3F4F6; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);">
    <div class="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
      <h1 class="text-2xl font-bold text-slate-900">
        🔧 管理员后台
      </h1>
      <div class="flex gap-4">
        <a href="/donate" class="text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors">返回投喂站</a>
        <button onclick="logout()" class="text-sm font-medium hover:text-slate-900 transition-colors" style="color: #DC2626;">登出</button>
      </div>
    </div>
  </nav>

  <!-- 主内容 -->
  <div class="max-w-7xl mx-auto p-6 pt-24">

    <!-- 登录表单 -->
    <div id="loginForm" class="max-w-md mx-auto bg-white rounded-xl p-8 animate-in card-hover" style="border: 1px solid #F3F4F6;">
      <h2 class="text-2xl font-bold text-slate-900 mb-6 text-center">🔐 管理员登录</h2>
      <div class="space-y-4">
        <div>
          <label class="block text-sm font-semibold text-slate-700 mb-2">管理员密码</label>
          <input id="adminPassword" type="password" placeholder="请输入管理员密码"
            class="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400 focus:border-transparent"
            onkeypress="if(event.key==='Enter') adminLogin()">
        </div>
        <button onclick="adminLogin()"
          class="w-full btn-primary text-white py-3 rounded-lg font-semibold">
          登录
        </button>
        <p class="text-sm text-slate-500 text-center">默认密码: admin123（首次登录后请立即修改）</p>
      </div>
    </div>

    <!-- 管理面板 -->
    <div id="adminPanel" class="hidden">

      <!-- 统计卡片 -->
      <div class="grid grid-cols-1 md:grid-cols-5 gap-6 mb-6">
        <div class="bg-white rounded-xl p-6 animate-in card-hover" style="border: 1px solid #F3F4F6;">
          <p class="text-sm text-slate-500 mb-1">总投喂数</p>
          <p id="totalVPS" class="text-3xl font-bold text-slate-900">0</p>
        </div>
        <div class="bg-white rounded-xl p-6 animate-in card-hover" style="border: 1px solid #F3F4F6;">
          <p class="text-sm text-slate-500 mb-1">活跃服务器</p>
          <p id="activeVPS" class="text-3xl font-bold" style="color: #10B981;">0</p>
        </div>
        <div class="bg-white rounded-xl p-6 animate-in card-hover" style="border: 1px solid #F3F4F6;">
          <p class="text-sm text-slate-500 mb-1">验证失败</p>
          <p id="failedVPS" class="text-3xl font-bold" style="color: #EF4444;">0</p>
        </div>
        <div class="bg-white rounded-xl p-6 animate-in card-hover" style="border: 1px solid #F3F4F6;">
          <p class="text-sm text-slate-500 mb-1">待验证</p>
          <p id="pendingVPS" class="text-3xl font-bold" style="color: #F59E0B;">0</p>
        </div>
        <div class="bg-white rounded-xl p-6 animate-in card-hover" style="border: 1px solid #F3F4F6;">
          <p class="text-sm text-slate-500 mb-1">投喂用户</p>
          <p id="totalUsers" class="text-3xl font-bold text-slate-900">0</p>
        </div>
      </div>

      <!-- 标签页 -->
      <div class="bg-white rounded-xl p-6 animate-in" style="border: 1px solid #F3F4F6;">
        <div class="flex justify-between items-center mb-6" style="border-bottom: 1px solid #F3F4F6; padding-bottom: 12px;">
          <div class="flex gap-2">
            <button onclick="showTab('vps')" class="tab-button tab-btn px-4 py-2 font-semibold rounded-t-lg active">
              VPS 列表
            </button>
            <button onclick="showTab('config')" class="tab-button tab-btn px-4 py-2 font-semibold rounded-t-lg text-slate-600 hover:text-slate-900">
              系统配置
            </button>
          </div>
          <button id="batchVerifyBtn" onclick="batchVerifyVPS()" class="btn-primary text-white px-4 py-2 rounded-lg font-semibold text-sm flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            一键验证
          </button>
        </div>

        <!-- VPS 列表 -->
        <div id="vpsTab" class="tab-content">
          <div id="vpsList" class="space-y-3"></div>
        </div>

        <!-- 系统配置 -->
        <div id="configTab" class="tab-content hidden">
          <div class="space-y-6">

            <!-- OAuth 配置 -->
            <div class="border border-slate-200 rounded-lg p-6">
              <h3 class="text-lg font-bold text-slate-900 mb-4">LinuxDo OAuth 配置</h3>
              <div class="space-y-4">
                <div>
                  <label class="block text-sm font-semibold text-slate-700 mb-2">Client ID</label>
                  <input id="clientId" type="text" placeholder="你的 Client ID"
                    class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500">
                </div>
                <div>
                  <label class="block text-sm font-semibold text-slate-700 mb-2">Client Secret</label>
                  <input id="clientSecret" type="password" placeholder="你的 Client Secret"
                    class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500">
                </div>
                <div>
                  <label class="block text-sm font-semibold text-slate-700 mb-2">Redirect URI</label>
                  <input id="redirectUri" type="text" placeholder="你的回调地址"
                    class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500">
                  <p class="text-xs text-slate-500 mt-1">通常为: https://your-domain.deno.dev/oauth/callback</p>
                </div>
                <button onclick="saveOAuthConfig()"
                  class="btn-primary text-white px-6 py-2 rounded-lg font-semibold">
                  保存 OAuth 配置
                </button>
              </div>
            </div>

            <!-- 管理员密码 -->
            <div class="border border-slate-200 rounded-lg p-6">
              <h3 class="text-lg font-bold text-slate-900 mb-4">修改管理员密码</h3>
              <div class="space-y-4">
                <div>
                  <label class="block text-sm font-semibold text-slate-700 mb-2">新密码</label>
                  <input id="newPassword" type="password" placeholder="至少 6 个字符"
                    class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400">
                </div>
                <button onclick="changePassword()"
                  class="btn-primary text-white px-6 py-2 rounded-lg font-semibold">
                  修改密码
                </button>
              </div>
            </div>

          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    let isAdmin = false;

    // 页面加载时检查会话
    async function checkAdminSession() {
      try {
        const res = await fetch('/api/admin/check-session');
        const data = await res.json();

        if (data.success && data.isAdmin) {
          isAdmin = true;
          document.getElementById('loginForm').classList.add('hidden');
          document.getElementById('adminPanel').classList.remove('hidden');
          loadAdminData();
        }
      } catch (e) {
        console.log('未登录或会话已过期');
      }
    }

    // 页面加载时执行
    window.addEventListener('DOMContentLoaded', checkAdminSession);

    async function adminLogin() {
      const password = document.getElementById('adminPassword').value;

      if (!password) {
        showToast('请输入密码', 'error');
        return;
      }

      try {
        const res = await fetch('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password }),
        });

        const data = await res.json();

        if (data.success) {
          isAdmin = true;
          document.getElementById('loginForm').classList.add('hidden');
          document.getElementById('adminPanel').classList.remove('hidden');
          loadAdminData();
          showToast('登录成功', 'success');
        } else {
          showToast(data.message, 'error');
        }
      } catch (e) {
        showToast('登录失败: ' + e.message, 'error');
      }
    }

    async function loadAdminData() {
      await Promise.all([loadStats(), loadVPSList(), loadOAuthConfig()]);
    }

    async function loadStats() {
      try {
        const res = await fetch('/api/admin/stats');
        const data = await res.json();

        if (data.success) {
          document.getElementById('totalVPS').textContent = data.data.totalVPS;
          document.getElementById('activeVPS').textContent = data.data.activeVPS;
          document.getElementById('failedVPS').textContent = data.data.failedVPS;
          document.getElementById('pendingVPS').textContent = data.data.pendingVPS;
          document.getElementById('totalUsers').textContent = data.data.topDonors.length;
        }
      } catch (e) {
        console.error('加载统计失败', e);
      }
    }

    async function loadVPSList() {
      try {
        const res = await fetch('/api/admin/vps');
        const data = await res.json();

        if (data.success && data.data.length > 0) {
          const html = data.data.map(v => {
            // 验证状态徽章
            let verifyBadge = '';
            if (v.verifyStatus === 'pending') {
              verifyBadge = '<span class="px-2 py-1 rounded-full text-xs font-semibold bg-yellow-50 border border-yellow-200" style="color: #F59E0B;">⏳ 待验证</span>';
            } else if (v.verifyStatus === 'verified') {
              verifyBadge = '<span class="px-2 py-1 rounded-full text-xs font-semibold bg-green-50 border border-green-200" style="color: #10B981;">✅ 已验证</span>';
            } else if (v.verifyStatus === 'failed') {
              verifyBadge = '<span class="px-2 py-1 rounded-full text-xs font-semibold bg-red-50 border border-red-200" style="color: #EF4444;">❌ 验证失败</span>';
            }

            // 验证按钮
            let verifyButton = '';
            if (v.verifyStatus === 'pending' || v.verifyStatus === 'failed') {
              verifyButton = \`
                <button onclick="markVerified('\${v.id}')"
                  class="px-3 py-1 text-xs bg-white text-green-700 rounded-lg font-semibold hover:bg-green-50 transition-all border border-green-200">
                  ✓ 标记通过
                </button>
              \`;
            }

            return \`
              <div class="p-4 rounded-lg card-hover bg-white" style="border: 1px solid #F3F4F6;">
                <div class="flex justify-between items-start mb-3">
                  <div class="flex-1">
                    <div class="flex items-center gap-3 mb-2">
                      <p class="font-bold text-lg text-slate-900">\${v.username}@\${v.ip}:\${v.port}</p>
                      <span class="px-2 py-1 rounded-full text-xs font-semibold \${
                        v.status === 'active' ? 'bg-green-50 border border-green-200' :
                        v.status === 'failed' ? 'bg-red-50 border border-red-200' :
                        'bg-slate-50 border border-slate-200'
                      }" style="color: \${
                        v.status === 'active' ? '#10B981' :
                        v.status === 'failed' ? '#EF4444' :
                        '#64748B'
                      };">
                        \${v.status === 'active' ? '✓ 活跃' : v.status === 'failed' ? '✕ 失败' : '○ 停用'}
                      </span>
                      \${verifyBadge}
                    </div>
                    <p class="text-sm text-slate-600">投喂者: <span class="font-semibold">\${v.donatedByUsername}</span></p>
                    <p class="text-sm text-slate-600">认证方式: \${v.authType === 'password' ? '🔑 密码' : '🔐 密钥'}</p>
                    \${v.note ? \`<p class="text-sm text-slate-500 mt-1">备注: \${v.note}</p>\` : ''}
                    \${v.verifyStatus === 'pending' && v.verifyCode ? \`
                      <div class="mt-2 p-2 bg-yellow-50 border border-yellow-200 rounded text-xs">
                        <p class="text-yellow-800">验证文件: <code class="bg-yellow-100 px-1 rounded">\${v.verifyFilePath}</code></p>
                        <p class="text-yellow-800">验证码: <code class="bg-yellow-100 px-1 rounded">\${v.verifyCode}</code></p>
                      </div>
                    \` : ''}
                    \${v.verifyStatus === 'failed' && v.verifyErrorMsg ? \`
                      <p class="text-xs text-red-600 mt-2">验证失败原因: \${v.verifyErrorMsg}</p>
                    \` : ''}
                    <p class="text-xs text-slate-400 mt-2">\${new Date(v.donatedAt).toLocaleString('zh-CN')}</p>
                  </div>
                  <div class="flex flex-col gap-2">
                    \${verifyButton}
                    <button onclick="toggleVPSStatus('\${v.id}', '\${v.status}')"
                      class="px-3 py-1 text-xs rounded-lg font-semibold transition-all \${v.status === 'active' ? 'bg-slate-100 text-slate-700 hover:bg-slate-200 border border-slate-200' : 'bg-white text-green-700 hover:bg-green-50 border border-green-200'}">
                      \${v.status === 'active' ? '停用' : '启用'}
                    </button>
                    <button onclick="showVPSDetails('\${v.id}')"
                      class="px-3 py-1 text-xs bg-white text-slate-700 rounded-lg font-semibold hover:bg-slate-50 transition-all border border-slate-200">
                      查看详情
                    </button>
                    <button onclick="deleteVPS('\${v.id}')"
                      class="px-3 py-1 text-xs bg-white rounded-lg font-semibold hover:bg-red-50 transition-all border border-red-200" style="color: #DC2626;">
                      删除
                    </button>
                  </div>
                </div>
                <div id="details-\${v.id}" class="hidden mt-3 p-3 bg-slate-50 rounded-lg">
                  <p class="text-sm font-mono text-slate-700 mb-2"><strong>用户名:</strong> \${v.username}</p>
                  <p class="text-sm font-mono text-slate-700 mb-2"><strong>IP:</strong> \${v.ip}</p>
                  <p class="text-sm font-mono text-slate-700 mb-2"><strong>端口:</strong> \${v.port}</p>
                  \${v.authType === 'password' ?
                    \`<p class="text-sm font-mono text-slate-700 mb-2"><strong>密码:</strong> \${v.password || '***'}</p>\` :
                    \`<p class="text-sm font-mono text-slate-700 mb-2"><strong>私钥:</strong><br><textarea readonly class="w-full mt-1 p-2 bg-white border rounded text-xs" rows="4">\${v.privateKey || ''}</textarea></p>\`
                  }
                </div>
              </div>
            \`;
          }).join('');
          document.getElementById('vpsList').innerHTML = html;
        } else {
          document.getElementById('vpsList').innerHTML = '<p class="text-center text-slate-500 py-8">暂无 VPS 投喂记录</p>';
        }
      } catch (e) {
        console.error('加载 VPS 列表失败', e);
      }
    }

    function showVPSDetails(id) {
      const detailsDiv = document.getElementById('details-' + id);
      detailsDiv.classList.toggle('hidden');
    }

    async function toggleVPSStatus(id, currentStatus) {
      // 状态循环：active -> inactive -> active 或 failed -> active
      let newStatus;
      if (currentStatus === 'active') {
        newStatus = 'inactive';
      } else {
        newStatus = 'active';
      }

      try {
        const res = await fetch(\`/api/admin/vps/\${id}/status\`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        });

        const data = await res.json();

        if (data.success) {
          showToast('状态已更新', 'success');
          loadVPSList();
          loadStats();
        } else {
          showToast(data.message, 'error');
        }
      } catch (e) {
        showToast('更新失败: ' + e.message, 'error');
      }
    }

    async function deleteVPS(id) {
      if (!confirm('确定要删除这个 VPS 吗？此操作不可恢复！')) {
        return;
      }

      try {
        const res = await fetch(\`/api/admin/vps/\${id}\`, {
          method: 'DELETE',
        });

        const data = await res.json();

        if (data.success) {
          showToast('VPS 已删除', 'success');
          loadVPSList();
          loadStats();
        } else {
          showToast(data.message, 'error');
        }
      } catch (e) {
        showToast('删除失败: ' + e.message, 'error');
      }
    }

    async function markVerified(id) {
      if (!confirm('确定要手动标记这个 VPS 为验证通过吗？')) {
        return;
      }

      try {
        const res = await fetch(\`/api/admin/vps/\${id}/mark-verified\`, {
          method: 'POST',
        });

        const data = await res.json();

        if (data.success) {
          showToast('VPS 已标记为验证通过', 'success');
          loadVPSList();
          loadStats();
        } else {
          showToast(data.message, 'error');
        }
      } catch (e) {
        showToast('标记失败: ' + e.message, 'error');
      }
    }

    async function batchVerifyVPS() {
      const btn = document.getElementById('batchVerifyBtn');
      const originalHTML = btn.innerHTML;

      // 禁用按钮，显示加载状态
      btn.disabled = true;
      btn.innerHTML = \`
        <svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
        </svg>
        验证中...
      \`;

      try {
        const res = await fetch('/api/admin/vps/batch-verify', {
          method: 'POST',
        });

        const data = await res.json();

        if (data.success) {
          showToast(data.message, 'success');

          // 显示详细结果
          if (data.data.total > 0) {
            const details = \`总计: \${data.data.total} | 成功: \${data.data.success} | 失败: \${data.data.failed}\`;
            console.log('[批量验证] ' + details);
          } else {
            showToast('没有待验证的 VPS', 'info');
          }

          // 刷新列表和统计
          loadVPSList();
          loadStats();
        } else {
          showToast(data.message, 'error');
        }
      } catch (e) {
        showToast('批量验证失败: ' + e.message, 'error');
      } finally {
        // 恢复按钮状态
        btn.disabled = false;
        btn.innerHTML = originalHTML;
      }
    }

    async function loadOAuthConfig() {
      try {
        const res = await fetch('/api/admin/config/oauth');
        const data = await res.json();

        if (data.success && data.data) {
          document.getElementById('clientId').value = data.data.clientId || '';
          document.getElementById('clientSecret').value = data.data.clientSecret || '';
          document.getElementById('redirectUri').value = data.data.redirectUri || '';
        }
      } catch (e) {
        console.error('加载 OAuth 配置失败', e);
      }
    }

    async function saveOAuthConfig() {
      const clientId = document.getElementById('clientId').value.trim();
      const clientSecret = document.getElementById('clientSecret').value.trim();
      const redirectUri = document.getElementById('redirectUri').value.trim();

      if (!clientId || !clientSecret || !redirectUri) {
        showToast('所有字段都是必填的', 'error');
        return;
      }

      try {
        const res = await fetch('/api/admin/config/oauth', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ clientId, clientSecret, redirectUri }),
        });

        const data = await res.json();

        if (data.success) {
          showToast('OAuth 配置已保存', 'success');
        } else {
          showToast(data.message, 'error');
        }
      } catch (e) {
        showToast('保存失败: ' + e.message, 'error');
      }
    }

    async function changePassword() {
      const password = document.getElementById('newPassword').value;

      if (!password || password.length < 6) {
        showToast('密码至少需要 6 个字符', 'error');
        return;
      }

      try {
        const res = await fetch('/api/admin/config/password', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password }),
        });

        const data = await res.json();

        if (data.success) {
          showToast('密码已更新', 'success');
          document.getElementById('newPassword').value = '';
        } else {
          showToast(data.message, 'error');
        }
      } catch (e) {
        showToast('更新失败: ' + e.message, 'error');
      }
    }

    function showTab(tab) {
      // 更新标签按钮样式
      document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
        btn.className = 'tab-button tab-btn px-4 py-2 font-semibold rounded-t-lg text-slate-600 hover:text-slate-900';
      });
      event.target.classList.add('active');

      // 切换内容
      document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
      });

      if (tab === 'vps') {
        document.getElementById('vpsTab').classList.remove('hidden');
      } else if (tab === 'config') {
        document.getElementById('configTab').classList.remove('hidden');
      }
    }

    async function logout() {
      console.log('[管理员前端] 登出...');
      await fetch('/api/admin/logout');
      window.location.reload();
    }

    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');

      // 创建toast元素
      const toast = document.createElement('div');
      toast.className = \`toast toast-\${type}\`;

      // 图标
      const icon = document.createElement('div');
      icon.className = 'toast-icon';
      icon.textContent = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';

      // 消息文本
      const text = document.createElement('div');
      text.textContent = message;
      text.style.flex = '1';

      toast.appendChild(icon);
      toast.appendChild(text);
      container.appendChild(toast);

      // 自动移除
      setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => {
          if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
          }
        }, 300);
      }, 3000);
    }
  </script>
</body>
</html>`;
}

// 启动服务器
Deno.serve(app.fetch);
