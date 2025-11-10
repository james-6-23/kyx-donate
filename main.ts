/// <reference lib="deno.unstable" />

import { Hono } from 'https://deno.land/x/hono@v3.11.7/mod.ts';
import { cors } from 'https://deno.land/x/hono@v3.11.7/middleware.ts';
import { setCookie, getCookie } from 'https://deno.land/x/hono@v3.11.7/helper.ts';

/* ==================== 类型定义 ==================== */
interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}
interface VPSServer {
  id: string;
  ip: string;
  port: number;
  username: string;
  authType: 'password' | 'key';
  password?: string;
  privateKey?: string;
  donatedBy: string;
  donatedByUsername: string;
  donatedAt: number;
  status: 'active' | 'inactive' | 'failed';
  note?: string;
  adminNote?: string;
  country: string;
  traffic: string;
  expiryDate: string;
  specs: string;
  ipLocation?: string;
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

const kv = await Deno.openKv();

/* ==================== 工具函数 ==================== */
const genId = () => crypto.randomUUID();

async function getIPLocation(ip: string): Promise<string> {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city`, {
      signal: AbortSignal.timeout(5000)
    });
    if (res.ok) {
      const d = await res.json();
      const parts = [d.country, d.regionName, d.city].filter(Boolean);
      if (parts.length) return parts.join(', ');
    }
  } catch (_) {}
  return '未知地区';
}

const isIPv4 = (ip: string) =>
  /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every(p => +p >= 0 && +p <= 255);
const isIPv6 = (ip: string) =>
  /^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/i.test(
    ip.replace(/^\[|\]$/g, ''),
  );
const isValidIP = (ip: string) => isIPv4(ip) || isIPv6(ip);

async function getAllVPS(): Promise<VPSServer[]> {
  const iter = kv.list<VPSServer>({ prefix: ['vps'] });
  const arr: VPSServer[] = [];
  for await (const e of iter) arr.push(e.value);
  return arr.sort((a, b) => b.donatedAt - a.donatedAt);
}

async function ipDup(ip: string, port: number) {
  return (await getAllVPS()).some(v => v.ip === ip && v.port === port);
}

async function portOK(ip: string, port: number) {
  try {
    const conn = await Deno.connect({
      hostname: ip.replace(/^\[|\]$/g, ''),
      port,
      transport: 'tcp'
    });
    conn.close();
    return true;
  } catch {
    return false;
  }
}

async function addVPS(server: Omit<VPSServer, 'id'>) {
  const v: VPSServer = { id: genId(), ...server };
  await kv.set(['vps', v.id], v);
  const r = await kv.get<string[]>(['user_donations', v.donatedBy]);
  const list = r.value || [];
  list.push(v.id);
  await kv.set(['user_donations', v.donatedBy], list);
  return v;
}

async function delVPS(id: string) {
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return false;
  await kv.delete(['vps', id]);
  const u = await kv.get<string[]>(['user_donations', r.value.donatedBy]);
  if (u.value) {
    await kv.set(['user_donations', r.value.donatedBy], u.value.filter(x => x !== id));
  }
  return true;
}

async function updVPSStatus(id: string, s: VPSServer['status']) {
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return false;
  r.value.status = s;
  await kv.set(['vps', id], r.value);
  return true;
}

/* ==================== 配置 & 会话 ==================== */
const getOAuth = async () =>
  (await kv.get<OAuthConfig>(['config', 'oauth'])).value || null;
const setOAuth = async (c: OAuthConfig) => {
  await kv.set(['config', 'oauth'], c);
};
const getAdminPwd = async () =>
  (await kv.get<string>(['config', 'admin_password'])).value || 'admin123';
const setAdminPwd = async (p: string) => {
  await kv.set(['config', 'admin_password'], p);
};

async function getSession(id: string) {
  const r = await kv.get<Session>(['sessions', id]);
  if (!r.value) return null;
  if (r.value.expiresAt < Date.now()) {
    await kv.delete(['sessions', id]);
    return null;
  }
  return r.value;
}

async function createSession(
  userId: string,
  username: string,
  avatarUrl: string | undefined,
  isAdmin: boolean
) {
  const s: Session = {
    id: genId(),
    userId,
    username,
    avatarUrl,
    isAdmin,
    expiresAt: Date.now() + 7 * 24 * 3600 * 1000
  };
  await kv.set(['sessions', s.id], s);
  return s.id;
}

async function getUser(linuxDoId: string) {
  return (await kv.get<User>(['users', linuxDoId])).value || null;
}

async function upsertUser(linuxDoId: string, username: string, avatarUrl?: string) {
  const old = await getUser(linuxDoId);
  const u: User = {
    linuxDoId,
    username,
    avatarUrl,
    isAdmin: old?.isAdmin || false,
    createdAt: old?.createdAt || Date.now()
  };
  await kv.set(['users', linuxDoId], u);
  return u;
}

/* ==================== OAuth（Linux.do） ==================== */
async function tokenByCode(code: string, cfg: OAuthConfig) {
  const res = await fetch('https://connect.linux.do/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code,
      redirect_uri: cfg.redirectUri,
      grant_type: 'authorization_code'
    })
  });
  return res.json();
}

async function linuxDoUser(accessToken: string) {
  const r = await fetch('https://connect.linux.do/api/user', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  return r.json();
}

/* ==================== 中间件 ==================== */
const requireAuth = async (c: any, next: any) => {
  const sid = getCookie(c, 'session_id');
  if (!sid) return c.json({ success: false, message: '未登录' }, 401);
  const s = await getSession(sid);
  if (!s) return c.json({ success: false, message: '会话已过期' }, 401);
  c.set('session', s);
  await next();
};

const requireAdmin = async (c: any, next: any) => {
  const sid = getCookie(c, 'admin_session_id');
  if (!sid) return c.json({ success: false, message: '未登录' }, 401);
  const s = await getSession(sid);
  if (!s || !s.isAdmin) return c.json({ success: false, message: '需要管理员权限' }, 403);
  c.set('session', s);
  await next();
};

/* ==================== Hono 应用 ==================== */
const app = new Hono();
app.use('*', cors());

app.get('/', c => c.redirect('/donate'));

/* ---- OAuth 登录 ---- */
app.get('/oauth/login', async c => {
  const redirectPath = c.req.query('redirect') || '/donate/vps';
  const cfg = await getOAuth();
  if (!cfg) {
    return c.html(
      '<!doctype html><body><h1>配置错误</h1><p>OAuth 未设置</p><a href="/donate">返回</a></body>',
    );
  }
  const url = new URL('https://connect.linux.do/oauth2/authorize');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', cfg.redirectUri);
  url.searchParams.set('scope', 'openid profile');
  url.searchParams.set(
    'state',
    typeof redirectPath === 'string' ? redirectPath : '/donate/vps',
  );
  return c.redirect(url.toString());
});

app.get('/oauth/callback', async c => {
  const code = c.req.query('code');
  const error = c.req.query('error');
  const state = c.req.query('state') || '/donate';

  if (error) {
    return c.html(
      `<!doctype html><body><h1>登录失败</h1><p>${error}</p><a href="/donate">返回</a></body>`,
    );
  }
  if (!code) return c.text('Missing code', 400);

  try {
    const cfg = await getOAuth();
    if (!cfg) {
      return c.html('<!doctype html><body><h1>配置错误</h1><a href="/donate">返回</a></body>');
    }

    const token = await tokenByCode(code, cfg);
    const info = await linuxDoUser(token.access_token);

    let avatar = info.avatar_template as string | undefined;
    if (avatar) {
      avatar = avatar.replace('{size}', '120');
      if (avatar.startsWith('//')) avatar = 'https:' + avatar;
      else if (avatar.startsWith('/')) avatar = 'https://connect.linux.do' + avatar;
    }

    const user = await upsertUser(String(info.id), info.username, avatar);
    const sid = await createSession(
      user.linuxDoId,
      user.username,
      user.avatarUrl,
      user.isAdmin
    );
    const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;

    setCookie(c, 'session_id', sid, {
      maxAge: 7 * 24 * 3600,
      httpOnly: true,
      secure: isProd,
      sameSite: 'Lax',
      path: '/'
    });

    const redirectTo =
      typeof state === 'string' && state.startsWith('/') ? state : '/donate';
    return c.redirect(redirectTo);
  } catch (e: any) {
    return c.html(
      `<!doctype html><body><h1>登录失败</h1><p>${e.message || e}</p><a href="/donate">返回</a></body>`,
    );
  }
});

/* ---- 用户 API ---- */
app.get('/api/logout', async c => {
  const sid = getCookie(c, 'session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/user/info', requireAuth, async c => {
  const s = c.get('session');
  const r = await kv.get<string[]>(['user_donations', s.userId]);
  return c.json({
    success: true,
    data: {
      username: s.username,
      avatarUrl: s.avatarUrl,
      isAdmin: s.isAdmin,
      donationCount: (r.value || []).length
    }
  });
});

app.get('/api/user/donations', requireAuth, async c => {
  const s = c.get('session');
  const ids = (await kv.get<string[]>(['user_donations', s.userId])).value || [];
  const arr: VPSServer[] = [];

  for (const id of ids) {
    const r = await kv.get<VPSServer>(['vps', id]);
    if (r.value) arr.push(r.value);
  }

  const safe = arr
    .sort((a, b) => b.donatedAt - a.donatedAt)
    .map(d => ({
      id: d.id,
      ip: d.ip,
      port: d.port,
      username: d.username,
      authType: d.authType,
      donatedAt: d.donatedAt,
      status: d.status,
      note: d.note,
      country: d.country,
      traffic: d.traffic,
      expiryDate: d.expiryDate,
      specs: d.specs,
      ipLocation: d.ipLocation,
      verifyStatus: d.verifyStatus,
      lastVerifyAt: d.lastVerifyAt,
      verifyErrorMsg: d.verifyErrorMsg,
      donatedByUsername: d.donatedByUsername
    }));

  return c.json({ success: true, data: safe });
});

app.put('/api/user/donations/:id/note', requireAuth, async c => {
  const s = c.get('session');
  const id = c.req.param('id');
  const { note } = await c.req.json();

  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: 'VPS 不存在' }, 404);
  if (r.value.donatedBy !== s.userId)
    return c.json({ success: false, message: '无权修改' }, 403);

  r.value.note = (note || '').toString();
  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '备注已更新' });
});

/* ---- 公共榜单 API ---- */
app.get('/api/leaderboard', async c => {
  try {
    const all = await getAllVPS();
    const map = new Map<string, { username: string; count: number; servers: any[] }>();

    for (const v of all) {
      const rec =
        map.get(v.donatedBy) ||
        {
          username: v.donatedByUsername,
          count: 0,
          servers: []
        };
      rec.count++;
      rec.servers.push({
        ipLocation: v.ipLocation || '未知地区',
        country: v.country || '未填写',
        traffic: v.traffic || '未填写',
        expiryDate: v.expiryDate || '未填写',
        specs: v.specs || '未填写',
        status: v.status,
        donatedAt: v.donatedAt,
        note: v.note || ''
      });
      map.set(v.donatedBy, rec);
    }

    const leaderboard = Array.from(map.values()).sort((a, b) => b.count - a.count);
    return c.json({ success: true, data: leaderboard });
  } catch (err) {
    console.error('Leaderboard error:', err);
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

/* ---- 投喂 API ---- */
app.post('/api/donate', requireAuth, async c => {
  const s = c.get('session');
  const body = await c.req.json();
  const {
    ip,
    port,
    username,
    authType,
    password,
    privateKey,
    country,
    traffic,
    expiryDate,
    specs,
    note
  } = body;

  if (!ip || !port || !username || !authType) {
    return c.json({ success: false, message: 'IP / 端口 / 用户名 / 认证方式 必填' }, 400);
  }
  if (!country || !traffic || !expiryDate || !specs) {
    return c.json(
      { success: false, message: '国家、流量、到期、配置 必填' },
      400,
    );
  }
  if (authType === 'password' && !password) {
    return c.json({ success: false, message: '密码认证需要密码' }, 400);
  }
  if (authType === 'key' && !privateKey) {
    return c.json({ success: false, message: '密钥认证需要私钥' }, 400);
  }
  if (!isValidIP(ip)) {
    return c.json({ success: false, message: 'IP 格式不正确' }, 400);
  }

  const p = parseInt(String(port), 10);
  if (p < 1 || p > 65535) {
    return c.json({ success: false, message: '端口范围 1 ~ 65535' }, 400);
  }
  if (await ipDup(ip, p)) {
    return c.json({ success: false, message: '该 IP:端口 已被投喂' }, 400);
  }
  if (!(await portOK(ip, p))) {
    return c.json({ success: false, message: '无法连接到该服务器，请确认 IP / 端口 是否正确、且对外开放' }, 400);
  }

  const ipLoc = await getIPLocation(ip);
  const now = Date.now();

  const v = await addVPS({
    ip,
    port: p,
    username,
    authType,
    password: authType === 'password' ? password : undefined,
    privateKey: authType === 'key' ? privateKey : undefined,
    donatedBy: s.userId,
    donatedByUsername: s.username,
    donatedAt: now,
    status: 'active',
    note: note || '',
    adminNote: '',
    country,
    traffic,
    expiryDate,
    specs,
    ipLocation: ipLoc,
    verifyStatus: 'verified',
    lastVerifyAt: now,
    verifyErrorMsg: ''
  });

  return c.json({
    success: true,
    message: '✅ 投喂成功，已通过连通性验证，感谢支持！',
    data: { id: v.id, ipLocation: v.ipLocation }
  });
});

/* ---- 管理员 API ---- */
app.get('/api/admin/check-session', async c => {
  try {
    const sid = getCookie(c, 'admin_session_id');
    if (!sid) return c.json({ success: false, isAdmin: false });

    const s = await getSession(sid);
    if (!s) return c.json({ success: false, isAdmin: false });

    return c.json({
      success: true,
      isAdmin: !!s.isAdmin,
      username: s.username
    });
  } catch (err) {
    console.error('Admin check error:', err);
    return c.json({ success: false, isAdmin: false });
  }
});

app.post('/api/admin/login', async c => {
  const { password } = await c.req.json();
  const real = await getAdminPwd();

  if (password !== real)
    return c.json({ success: false, message: '密码错误' }, 401);

  const sid = genId();
  const sess: Session = {
    id: sid,
    userId: 'admin',
    username: 'Administrator',
    avatarUrl: undefined,
    isAdmin: true,
    expiresAt: Date.now() + 7 * 24 * 3600 * 1000
  };
  await kv.set(['sessions', sid], sess);

  const isProd = Deno.env.get('DENO_DEPLOYMENT_ID') !== undefined;
  setCookie(c, 'admin_session_id', sid, {
    maxAge: 7 * 24 * 3600,
    httpOnly: true,
    secure: isProd,
    sameSite: 'Lax',
    path: '/'
  });

  return c.json({ success: true, message: '登录成功' });
});

app.get('/api/admin/logout', async c => {
  const sid = getCookie(c, 'admin_session_id');
  if (sid) await kv.delete(['sessions', sid]);
  setCookie(c, 'admin_session_id', '', { maxAge: 0, path: '/' });
  return c.json({ success: true });
});

app.get('/api/admin/vps', requireAdmin, async c => {
  try {
    const data = await getAllVPS();
    return c.json({ success: true, data });
  } catch (err) {
    console.error('Admin VPS list error:', err);
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

app.delete('/api/admin/vps/:id', requireAdmin, async c => {
  const ok = await delVPS(c.req.param('id'));
  return c.json(
    ok ? { success: true, message: 'VPS 已删除' } : { success: false, message: '不存在' },
    ok ? 200 : 404,
  );
});

app.put('/api/admin/vps/:id/status', requireAdmin, async c => {
  const id = c.req.param('id');
  const { status } = await c.req.json();

  if (!['active', 'inactive', 'failed'].includes(status)) {
    return c.json({ success: false, message: '无效状态' }, 400);
  }

  const ok = await updVPSStatus(id, status as VPSServer['status']);
  return c.json(
    ok ? { success: true, message: '状态已更新' } : { success: false, message: '不存在' },
    ok ? 200 : 404,
  );
});

app.put('/api/admin/vps/:id/notes', requireAdmin, async c => {
  const id = c.req.param('id');
  const { note, adminNote, country, traffic, expiryDate, specs } = await c.req.json();

  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);

  if (note !== undefined) r.value.note = String(note);
  if (adminNote !== undefined) r.value.adminNote = String(adminNote);
  if (country !== undefined) r.value.country = String(country);
  if (traffic !== undefined) r.value.traffic = String(traffic);
  if (expiryDate !== undefined) r.value.expiryDate = String(expiryDate);
  if (specs !== undefined) r.value.specs = String(specs);

  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '信息已更新' });
});

app.get('/api/admin/config/oauth', requireAdmin, async c => {
  const oauth = await getOAuth();
  return c.json({ success: true, data: oauth || {} });
});

app.put('/api/admin/config/oauth', requireAdmin, async c => {
  const { clientId, clientSecret, redirectUri } = await c.req.json();

  if (!clientId || !clientSecret || !redirectUri) {
    return c.json({ success: false, message: '字段必填' }, 400);
  }

  await setOAuth({ clientId, clientSecret, redirectUri });
  return c.json({ success: true, message: 'OAuth 配置已更新' });
});

app.put('/api/admin/config/password', requireAdmin, async c => {
  const { password } = await c.req.json();

  if (!password || String(password).length < 6) {
    return c.json({ success: false, message: '密码至少 6 位' }, 400);
  }

  await setAdminPwd(String(password));
  return c.json({ success: true, message: '管理员密码已更新' });
});

/* 后端统计：今日新增按固定东八区日期判断 */
app.get('/api/admin/stats', requireAdmin, async c => {
  try {
    const all = await getAllVPS();

    // 用东八区（中国时间）来定义“今天”
    const tzOffsetMinutes = 8 * 60; // UTC+8
    const now = new Date();
    const nowUtcMs = now.getTime() + now.getTimezoneOffset() * 60000;
    const cnNow = new Date(nowUtcMs + tzOffsetMinutes * 60000);
    const cy = cnNow.getFullYear();
    const cm = cnNow.getMonth();
    const cd = cnNow.getDate();

    const isTodayCN = (ts: number | undefined) => {
      if (!ts) return false;
      const d = new Date(ts);
      const utcMs = d.getTime() + d.getTimezoneOffset() * 60000;
      const cn = new Date(utcMs + tzOffsetMinutes * 60000);
      return (
        cn.getFullYear() === cy &&
        cn.getMonth() === cm &&
        cn.getDate() === cd
      );
    };

    const userStats = new Map<string, number>();
    for (const v of all) {
      userStats.set(
        v.donatedByUsername,
        (userStats.get(v.donatedByUsername) || 0) + 1,
      );
    }

    const top = Array.from(userStats.entries())
      .map(([username, count]) => ({ username, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return c.json({
      success: true,
      data: {
        totalVPS: all.length,
        activeVPS: all.filter(v => v.status === 'active').length,
        failedVPS: all.filter(v => v.status === 'failed').length,
        inactiveVPS: all.filter(v => v.status === 'inactive').length,
        pendingVPS: all.filter(v => v.verifyStatus === 'pending').length,
        verifiedVPS: all.filter(v => v.verifyStatus === 'verified').length,
        todayNewVPS: all.filter(v => isTodayCN(v.donatedAt)).length,
        topDonors: top
      }
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    return c.json({ success: false, message: '加载失败' }, 500);
  }
});

app.post('/api/admin/vps/:id/mark-verified', requireAdmin, async c => {
  const id = c.req.param('id');
  const r = await kv.get<VPSServer>(['vps', id]);

  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);

  r.value.verifyStatus = 'verified';
  r.value.status = 'active';
  r.value.lastVerifyAt = Date.now();
  r.value.verifyErrorMsg = '';

  await kv.set(['vps', id], r.value);
  return c.json({ success: true, message: '已标记为验证通过' });
});

/* 单个一键验证接口 */
app.post('/api/admin/vps/:id/verify', requireAdmin, async c => {
  const id = c.req.param('id');
  const r = await kv.get<VPSServer>(['vps', id]);
  if (!r.value) return c.json({ success: false, message: '不存在' }, 404);

  const v = r.value;
  const ok = await portOK(v.ip, v.port);
  v.lastVerifyAt = Date.now();

  if (ok) {
    v.status = 'active';
    v.verifyStatus = 'verified';
    v.verifyErrorMsg = '';
    await kv.set(['vps', id], v);
    return c.json({
      success: true,
      message: '✅ 验证成功，VPS 连通正常',
      data: {
        status: v.status,
        verifyStatus: v.verifyStatus,
        verifyErrorMsg: v.verifyErrorMsg,
        lastVerifyAt: v.lastVerifyAt
      }
    });
  } else {
    v.status = 'failed';
    v.verifyStatus = 'failed';
    v.verifyErrorMsg = '无法连接 VPS，请检查服务器是否在线、防火墙/安全组端口放行';
    await kv.set(['vps', id], v);
    return c.json({
      success: false,
      message: '❌ 验证失败：无法连接 VPS',
      data: {
        status: v.status,
        verifyStatus: v.verifyStatus,
        verifyErrorMsg: v.verifyErrorMsg,
        lastVerifyAt: v.lastVerifyAt
      }
    });
  }
});

/* 一键验证全部 VPS */
app.post('/api/admin/verify-all', requireAdmin, async c => {
  const all = await getAllVPS();
  let total = 0;
  let success = 0;
  let failed = 0;

  for (const v of all) {
    total++;
    const ok = await portOK(v.ip, v.port);
    const r = await kv.get<VPSServer>(['vps', v.id]);
    if (!r.value) continue;
    const cur = r.value;
    cur.lastVerifyAt = Date.now();
    if (ok) {
      cur.status = 'active';
      cur.verifyStatus = 'verified';
      cur.verifyErrorMsg = '';
      success++;
    } else {
      cur.status = 'failed';
      cur.verifyStatus = 'failed';
      cur.verifyErrorMsg = '无法连接 VPS，请检查服务器是否在线、防火墙/安全组端口放行';
      failed++;
    }
    await kv.set(['vps', cur.id], cur);
  }

  return c.json({
    success: true,
    message: `批量验证完成：成功 ${success} 台，失败 ${failed} 台`,
    data: { total, success, failed }
  });
});

/* ==================== /donate 榜单页 ==================== */
app.get('/donate', c => {
  const head = commonHead('风萧萧公益机场 · VPS 投喂榜');
  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body class="min-h-screen" data-theme="dark">
<div class="max-w-6xl mx-auto px-4 py-6 md:py-10">

  <header class="mb-8 animate-in">
    <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6">
      <div class="flex-1 space-y-4">
        <h1 class="grad-title text-3xl md:text-5xl font-bold leading-tight">
          风萧萧公益机场 · VPS 投喂榜
        </h1>

        <div class="panel rounded-2xl border p-5 space-y-3 backdrop-blur-sm">
          <p class="text-sm leading-relaxed">
            <span class="muted">这是一个完全非盈利的公益项目，目前没有运营团队，由我独自维护。</span><br>
            同时也非常感谢以下几位佬的日常协助：
            <a href="https://linux.do/u/shklrt" target="_blank"
               class="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors">@shklrt</a>、
            <a href="https://linux.do/u/sar60677" target="_blank"
               class="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors">@sar60677</a>、
            <a href="https://linux.do/u/carrydelahaye" target="_blank"
               class="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors">@Carry&nbsp;Delahaye</a>。
          </p>

          <p class="text-sm leading-relaxed bg-amber-500/10 border border-amber-500/20 rounded-xl px-4 py-3">
            <span class="font-semibold text-amber-300">💝 榜单按投喂 VPS 数量排序，</span>
            但无论名次高低，您的每一次支持，对我和这个项目来说都弥足珍贵，衷心感谢！
          </p>

          <p class="text-xs text-amber-200/90 leading-relaxed flex items-start gap-2">
            <span class="text-base mt-0.5">🤝</span>
            <span>感谢大家的投喂，这个机场的发展离不开各位热佬的大力支持！这不是我一个人的功劳，而是大家的共同成果！共荣！🚀</span>
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-3">
          <button onclick="gotoDonatePage()"
            class="inline-flex items-center justify-center gap-2 rounded-xl
                   bg-gradient-to-r from-cyan-500 to-blue-500 px-6 py-3
                   text-sm font-bold shadow-xl hover:shadow-2xl
                   hover:scale-[1.02] transition-all duration-200
                   hover:from-cyan-400 hover:to-blue-400">
            <span class="text-lg">🧡</span> 我要投喂 VPS
          </button>
          <button id="theme-toggle" class="text-xs" onclick="toggleTheme()">浅色模式</button>
        </div>
      </div>
    </div>
  </header>

  <section class="mb-6">
    <div class="flex items-center gap-3 mb-4">
      <span class="text-2xl">🏆</span>
      <h2 class="text-2xl font-bold">捐赠榜单</h2>
      <span id="leaderboard-count" class="text-sm muted"></span>
    </div>
    
    <div id="leaderboard" class="space-y-4">
      <div class="flex items-center justify-center py-12">
        <div class="flex flex-col items-center gap-3">
          <div class="loading-spinner"></div>
          <div class="muted text-sm">正在加载榜单...</div>
        </div>
      </div>
    </div>
  </section>

  <footer class="mt-12 border-t border-slate-700/50 pt-6 text-xs muted text-center">
    <p class="flex items-center justify-center gap-2">
      <span class="text-base">ℹ️</span>
      <span>说明：本项目仅作公益用途，请勿滥用资源（长时间占满带宽、刷流量、倒卖账号等）。</span>
    </p>
  </footer>

</div>

<div id="toast-root"></div>
<script>
updateThemeBtn();

async function gotoDonatePage(){
  try{
    const r = await fetch('/api/user/info',{credentials:'same-origin',cache:'no-store'});
    if(r.ok){
      const j = await r.json();
      if(j.success) {
        location.href='/donate/vps';
      } else {
        location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
      }
    } else {
      location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
    }
  }catch(err){
    console.error('Check login error:', err);
    location.href='/oauth/login?redirect='+encodeURIComponent('/donate/vps');
  }
}

function statusText(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function statusCls(s){ return s==='active'?'badge-ok':(s==='failed'?'badge-fail':'badge-idle'); }

async function loadLeaderboard(){
  const box = document.getElementById('leaderboard'), countEl=document.getElementById('leaderboard-count');

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('加载超时')), 8000)
  );

  try{
    const fetchPromise = fetch('/api/leaderboard',{
      credentials:'same-origin',
      cache:'no-store'
    });

    const res = await Promise.race([fetchPromise, timeoutPromise]);

    if(!res.ok) {
      box.innerHTML='<div class="text-red-400 text-sm">加载失败: HTTP '+res.status+'<br><button onclick="loadLeaderboard()" class="mt-2 px-3 py-1 rounded-lg border">重试</button></div>';
      return;
    }

    const j = await res.json();
    if(!j.success){
      box.innerHTML='<div class="text-red-400 text-sm">加载失败: '+(j.message||'未知错误')+'<br><button onclick="loadLeaderboard()" class="mt-2 px-3 py-1 rounded-lg border">重试</button></div>';
      return;
    }

    const data=j.data||[];
    countEl.textContent = data.length?(' · 共 '+data.length+' 位投喂者'):'';

    if(!data.length){
      box.innerHTML='<div class="muted text-sm">暂时还没有投喂记录，成为第一个投喂者吧～</div>';
      return;
    }

    box.innerHTML='';
    data.forEach((it,idx)=>{
      const wrap=document.createElement('div');
      wrap.className='card rounded-2xl border p-5 shadow-lg hover:shadow-xl transition-all';

      const head=document.createElement('div');
      head.className='flex items-center justify-between mb-4 pb-3 border-b border-slate-700/30 gap-3';
      head.innerHTML='<div class="flex items-center gap-3 flex-1 min-w-0">'+
        '<span class="text-2xl flex-shrink-0">'+medalByRank(idx)+'</span>'+
        '<a class="font-bold text-lg text-sky-400 hover:text-cyan-300 truncate transition-colors" target="_blank" href="https://linux.do/u/'+encodeURIComponent(it.username)+'">@'+it.username+'</a>'+
        '</div>'+
        '<div class="flex items-center gap-2 bg-cyan-500/10 border border-cyan-500/20 rounded-full px-3 py-1.5 whitespace-nowrap">'+
          '<span class="text-cyan-400 font-bold text-sm">'+it.count+'</span>'+
          '<span class="text-xs muted">台 VPS</span>'+
        '</div>';
      wrap.appendChild(head);

      const list=document.createElement('div');
      list.className='space-y-3 text-xs';
      (it.servers||[]).forEach(srv=>{
        const d=document.createElement('div');
        d.className='rounded-xl border border-slate-700/50 bg-slate-800/30 px-4 py-3 hover:bg-slate-800/50 transition-all';
        d.innerHTML = '<div class="flex items-center justify-between gap-2 mb-2">'+
          '<div class="flex items-center gap-2 flex-1 min-w-0">'+
            '<span class="opacity-60">🌍</span>'+
            '<span class="text-sm font-medium truncate">'+(srv.country||'未填写')+(srv.ipLocation?' · '+srv.ipLocation:'')+'</span>'+
          '</div>'+
          '<span class="'+statusCls(srv.status)+' text-xs px-2 py-0.5 rounded-full">'+statusText(srv.status)+'</span>'+
        '</div>'+
        '<div class="grid grid-cols-2 gap-2 text-xs mt-2">'+
          '<div class="flex items-center gap-1.5"><span class="opacity-60">📊</span><span class="truncate">'+(srv.traffic||'未填写')+'</span></div>'+
          '<div class="flex items-center gap-1.5"><span class="opacity-60">📅</span><span class="truncate">'+(srv.expiryDate||'未填写')+'</span></div>'+
        '</div>'+
        (srv.specs?'<div class="text-xs muted mt-2 bg-slate-900/40 rounded-lg px-2 py-1.5 break-words flex items-start gap-1.5"><span class="opacity-60">⚙️</span><span>'+srv.specs+'</span></div>':'')+
        (srv.note?'<div class="text-xs text-amber-300/90 mt-2 bg-amber-500/5 border border-amber-500/20 rounded-lg px-2 py-1.5 break-words flex items-start gap-1.5"><span class="opacity-60">💬</span><span>'+srv.note+'</span></div>':'');
        list.appendChild(d);
      });
      wrap.appendChild(list);
      box.appendChild(wrap);
    });
  }catch(err){
    console.error('Leaderboard load error:', err);
    box.innerHTML='<div class="text-red-400 text-sm">'+err.message+'<br><button onclick="loadLeaderboard()" class="mt-2 px-3 py-1 rounded-lg border">重试</button></div>';
  }
}

loadLeaderboard();
</script>
</body></html>`;
  return c.html(html);
});


/* ==================== /donate/vps 投喂中心 ==================== */
app.get('/donate/vps', c => {
  const head = commonHead('风萧萧公益机场 · VPS 投喂中心');
  const today = new Date();
  const y = today.getFullYear(),
    m = String(today.getMonth() + 1).padStart(2, '0'),
    d = String(today.getDate()).padStart(2, '0');
  const minDate = `${y}-${m}-${d}`;
  const nextYear = new Date(today);
  nextYear.setFullYear(today.getFullYear() + 1);
  const ny = `${nextYear.getFullYear()}-${String(nextYear.getMonth() + 1).padStart(
    2,
    '0',
  )}-${String(nextYear.getDate()).padStart(2, '0')}`;

  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body class="min-h-screen" data-theme="dark">
<div class="max-w-7xl mx-auto px-4 py-6 md:py-10">
  <header class="mb-8 animate-fade-in">
    <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
      <div class="space-y-2">
        <h1 class="grad-title text-3xl md:text-4xl font-bold">风萧萧公益机场 · VPS 投喂中心</h1>
        <p class="text-xs muted flex items-center gap-2">
          <span class="text-base">📍</span>
          <span>提交新 VPS / 查看我的投喂记录</span>
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-3">
        <div id="user-info" class="text-sm bg-slate-800/50 rounded-full px-4 py-2 border border-slate-700"></div>
        <button onclick="logout()"
                class="text-xs rounded-full border border-slate-600 hover:border-red-400 px-4 py-2
                       transition-all hover:bg-red-500/10 hover:text-red-400">
          退出登录
        </button>
        <button id="theme-toggle" class="text-xs" onclick="toggleTheme()">浅色模式</button>
      </div>
    </div>
  </header>

  <main class="grid lg:grid-cols-2 gap-6 items-start">
    <section class="panel rounded-2xl border p-6 shadow-xl">
      <div class="flex items-center gap-3 mb-3">
        <span class="text-2xl">🧡</span>
        <h2 class="text-xl font-bold">提交新的 VPS 投喂</h2>
      </div>
      <p class="text-xs muted mb-5 leading-relaxed bg-amber-500/5 border border-amber-500/20 rounded-xl px-3 py-2">
        ⚠️ 请确保服务器是你有控制权的机器，并允许用于公益节点。禁止长时间占满带宽、刷流量、倒卖账号等行为。
      </p>

      <form id="donate-form" class="space-y-4 text-sm">
        <div class="grid md:grid-cols-2 gap-4">
          <div>
            <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
              <span>🌐</span> 服务器 IP <span class="text-red-400">*</span>
            </label>
            <input name="ip" required placeholder="示例：203.0.113.8 或 [2001:db8::1]"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
            <div class="help mt-1 flex items-center gap-1"><span class="opacity-60">💡</span>支持 IPv4 / IPv6</div>
          </div>
          <div>
            <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
              <span>🔌</span> 端口 <span class="text-red-400">*</span>
            </label>
            <input name="port" required type="number" min="1" max="65535" placeholder="示例：22 / 443 / 8080"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
          </div>
        </div>

        <div class="grid md:grid-cols-2 gap-4">
          <div>
            <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
              <span>👤</span> 系统用户名 <span class="text-red-400">*</span>
            </label>
            <input name="username" required placeholder="示例：root / ubuntu"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
          </div>
          <div>
            <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
              <span>🔐</span> 认证方式
            </label>
            <select name="authType" class="w-full rounded-lg border px-3 py-2 text-sm">
              <option value="password">🔑 密码</option>
              <option value="key">🗝️ SSH 私钥</option>
            </select>
          </div>
        </div>

        <div id="password-field">
          <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
            <span>🔑</span> 密码（密码登录必填）
          </label>
          <input name="password" type="password" placeholder="示例：MyStrongP@ssw0rd"
                 class="w-full rounded-lg border px-3 py-2 text-sm" />
        </div>

        <div id="key-field" class="hidden">
          <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
            <span>🗝️</span> SSH 私钥（密钥登录必填）
          </label>
          <textarea name="privateKey" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    class="w-full rounded-lg border px-3 py-2 text-sm font-mono"></textarea>
        </div>

        <div class="grid md:grid-cols-2 gap-4">
          <div>
            <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
              <span>🌍</span> 国家 / 区域 <span class="text-red-400">*</span>
            </label>
            <input name="country" required placeholder="示例：HK - Hong Kong, Kowloon, Hong Kong"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
          </div>
          <div>
            <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
              <span>📊</span> 流量 / 带宽 <span class="text-red-400">*</span>
            </label>
            <input name="traffic" required placeholder="示例：400G/月 · 上下行 1Gbps"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
          </div>
        </div>

        <div class="grid md:grid-cols-2 gap-4">
          <div>
            <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
              <span>📅</span> 到期日期 <span class="text-red-400">*</span>
            </label>
            <input name="expiryDate" required type="date" min="${minDate}" value="${ny}"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
            <div class="help mt-1 flex items-center gap-1"><span class="opacity-60">💡</span>默认已填为 +1 年（可改）</div>
          </div>
          <div>
            <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
              <span>⚙️</span> 配置描述 <span class="text-red-400">*</span>
            </label>
            <input name="specs" required placeholder="示例：1C1G · 10Gbps · 1T 流量"
                   class="w-full rounded-lg border px-3 py-2 text-sm" />
          </div>
        </div>

        <div>
          <label class="block mb-2 text-xs font-medium flex items-center gap-1.5">
            <span>💬</span> 投喂备注 <span class="text-xs muted">（可选，将前台展示）</span>
          </label>
          <textarea name="note" rows="3" placeholder="示例：电信到香港方向无法走大陆优选链路，共享带宽，不保证大陆连通性"
                    class="w-full rounded-lg border px-3 py-2 text-sm"></textarea>
        </div>

        <div id="donate-message" class="text-sm mt-2 min-h-[1.5rem] font-medium"></div>

        <button id="donate-submit-btn" type="submit"
                class="w-full mt-3 inline-flex items-center justify-center gap-2 rounded-xl
                       bg-gradient-to-r from-cyan-500 to-blue-500 px-6 py-3 text-sm font-bold
                       shadow-xl hover:shadow-2xl hover:scale-[1.02] transition-all duration-200
                       hover:from-cyan-400 hover:to-blue-400">
          <span class="text-lg">🚀</span> 提交投喂
        </button>
      </form>
    </section>

    <section class="panel rounded-2xl border p-6 shadow-xl">
      <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-3">
          <span class="text-2xl">📦</span>
          <h2 class="text-xl font-bold">我的投喂记录</h2>
        </div>
        <button onclick="loadDonations()"
                class="text-xs rounded-full border border-slate-600 hover:border-cyan-400 px-3 py-1.5
                       transition-all hover:bg-cyan-500/10">
          🔄 刷新
        </button>
      </div>
      <div id="donations-list" class="space-y-3 text-xs">
        <div class="flex items-center justify-center py-8">
          <div class="flex flex-col items-center gap-3">
            <div class="loading-spinner"></div>
            <div class="muted text-xs">正在加载...</div>
          </div>
        </div>
      </div>
    </section>
  </main>

  <footer class="mt-10 text-xs muted border-t border-slate-700/50 pt-6 text-center">
    <p class="flex items-center justify-center gap-2">
      <span class="text-base">ℹ️</span>
      <span>友情提示：投喂即视为同意将该 VPS 用于公益机场中转节点。请勿提交有敏感业务的生产机器。</span>
    </p>
  </footer>
</div>

<div id="toast-root"></div>
<script>
updateThemeBtn();

async function ensureLogin(){
  try{
    const res = await fetch('/api/user/info',{credentials:'same-origin',cache:'no-store'});
    if(!res.ok){ location.href='/donate'; return; }
    const j=await res.json();
    if(!j.success){ location.href='/donate'; return; }
    const u=j.data;
    const p='https://linux.do/u/'+encodeURIComponent(u.username);
    const infoEl = document.getElementById('user-info');
    if(infoEl) {
      infoEl.innerHTML='投喂者：<a href="'+p+'" target="_blank" class="underline text-sky-300">@'+u.username+'</a> · 已投喂 '+(u.donationCount||0)+' 台';
    }
  }catch(err){
    console.error('Login check error:', err);
    location.href='/donate';
  }
}

async function logout(){
  try{ await fetch('/api/logout',{credentials:'same-origin'});}catch{}
  location.href='/donate';
}

function bindAuthType(){
  const sel=document.querySelector('select[name="authType"]');
  const pwd=document.getElementById('password-field');
  const key=document.getElementById('key-field');
  if(sel && pwd && key) {
    sel.addEventListener('change',function(){
      if(sel.value==='password'){
        pwd.classList.remove('hidden');
        key.classList.add('hidden');
      }else{
        pwd.classList.add('hidden');
        key.classList.remove('hidden');
      }
    });
  }
}

function stxt(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function scls(s){ return s==='active'?'badge-ok':(s==='failed'?'badge-fail':'badge-idle'); }

async function submitDonate(e){
  e.preventDefault();
  const form=e.target, msg=document.getElementById('donate-message'), btn=document.getElementById('donate-submit-btn');
  msg.textContent=''; msg.className='text-xs mt-1 min-h-[1.5rem]';
  const fd=new FormData(form);
  const payload={
    ip:fd.get('ip')?.toString().trim(),
    port:Number(fd.get('port')||''),
    username:fd.get('username')?.toString().trim(),
    authType:fd.get('authType')?.toString(),
    password:fd.get('password')?.toString(),
    privateKey:fd.get('privateKey')?.toString(),
    country:fd.get('country')?.toString().trim(),
    traffic:fd.get('traffic')?.toString().trim(),
    expiryDate:fd.get('expiryDate')?.toString().trim(),
    specs:fd.get('specs')?.toString().trim(),
    note:fd.get('note')?.toString().trim()
  };
  btn.disabled=true; const t=btn.textContent; btn.textContent='提交中...';
  try{
    const r=await fetch('/api/donate',{
      method:'POST',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const j=await r.json();
    if(!r.ok||!j.success){
      msg.textContent=j.message||'提交失败';
      toast('投喂失败：'+(j.message||'请检查填写项'), 'error');
    } else{
      msg.textContent=j.message||'投喂成功';
      toast(j.message||'投喂成功','success');
      form.reset();
      loadDonations();
    }
  }catch(e){
    console.error('Donate error:', e);
    msg.textContent='提交异常';
    toast('提交异常','error');
  } finally{
    btn.disabled=false;
    btn.textContent=t;
  }
}

async function loadDonations(){
  const box=document.getElementById('donations-list');
  box.innerHTML='<div class="muted text-xs">正在加载...</div>';
  try{
    const r=await fetch('/api/user/donations',{credentials:'same-origin',cache:'no-store'});
    const j=await r.json();
    if(!r.ok||!j.success){
      box.innerHTML='<div class="text-red-400 text-xs">加载失败</div>';
      return;
    }
    const data=j.data||[];
    if(!data.length){
      box.innerHTML='<div class="muted text-xs">还没有投喂记录，先在左侧提交一台吧～</div>';
      return;
    }
    box.innerHTML='';
    data.forEach(v=>{
      const div=document.createElement('div');
      div.className='card rounded-xl border border-slate-700/50 bg-slate-800/30 px-4 py-3 hover:bg-slate-800/50 transition-all';
      const dt=v.donatedAt?new Date(v.donatedAt):null, t=dt?dt.toLocaleString():'';
      const uname=v.donatedByUsername||'';
      const p='https://linux.do/u/'+encodeURIComponent(uname);
      div.innerHTML='<div class="flex items-center justify-between gap-2 mb-2 pb-2 border-b border-slate-700/30">'+
        '<div class="text-xs font-medium flex items-center gap-2"><span>🖥️</span><span class="break-words">'+v.ip+':'+v.port+'</span></div>'+
        '<div class="'+scls(v.status)+' text-xs px-2 py-0.5 rounded-full">'+stxt(v.status)+'</div></div>'+
        '<div class="text-xs mb-2">投喂者：<a href="'+p+'" target="_blank" class="underline text-sky-400 hover:text-cyan-300 transition-colors">@'+uname+'</a></div>'+
        '<div class="grid grid-cols-2 gap-2 text-xs mt-2">'+
          '<div class="flex items-center gap-1.5"><span class="opacity-60">🌍</span><span class="truncate">'+(v.country||'未填写')+(v.ipLocation?' · '+v.ipLocation:'')+'</span></div>'+
          '<div class="flex items-center gap-1.5"><span class="opacity-60">📊</span><span class="truncate">'+(v.traffic||'未填写')+'</span></div>'+
          '<div class="flex items-center gap-1.5"><span class="opacity-60">📅</span><span class="truncate">'+(v.expiryDate||'未填写')+'</span></div>'+
        '</div>'+
        '<div class="text-xs muted mt-2 bg-slate-900/40 rounded-lg px-2 py-1.5 break-words">⚙️ '+(v.specs||'未填写')+'</div>'+
        (v.note?'<div class="text-xs text-amber-300/90 mt-2 bg-amber-500/5 border border-amber-500/20 rounded-lg px-2 py-1.5 break-words">💬 '+v.note+'</div>':'')+
        (t?'<div class="text-xs muted mt-2 flex items-center gap-1.5"><span class="opacity-60">🕐</span><span>'+t+'</span></div>':'');
      box.appendChild(div);
    });
  }catch(err){
    console.error('Load donations error:', err);
    box.innerHTML='<div class="text-red-400 text-xs">加载异常</div>';
  }
}

ensureLogin();
bindAuthType();
document.getElementById('donate-form').addEventListener('submit', submitDonate);
loadDonations();
</script>
</body></html>`;
  return c.html(html);
});

/* ==================== /admin 管理后台 ==================== */
app.get('/admin', c => {
  const head = commonHead('VPS 管理后台');
  const html = `<!doctype html><html lang="zh-CN"><head>${head}</head>
<body class="min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-8" id="app-root">
  <div class="flex items-center justify-center min-h-[60vh]">
    <div class="text-center space-y-3">
      <div class="loading-spinner mx-auto"></div>
      <div class="text-sm text-slate-600">正在检测管理员登录状态...</div>
    </div>
  </div>
</div>
<div id="toast-root"></div>
<script>
updateThemeBtn();

let allVpsList=[]; let statusFilter='all'; let searchFilter=''; let userFilter='';

function stxt(s){ return s==='active'?'运行中':(s==='failed'?'失败':'未启用'); }
function scls(s){ return s==='active'?'badge-ok':(s==='failed'?'badge-fail':'badge-idle'); }
function isTodayLocal(ts){
  if(!ts) return false;
  const d=new Date(ts);
  const now=new Date();
  return d.getFullYear()===now.getFullYear() &&
         d.getMonth()===now.getMonth() &&
         d.getDate()===now.getDate();
}

async function checkAdmin(){
  const root=document.getElementById('app-root');

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('请求超时')), 5000)
  );

  try{
    const fetchPromise = fetch('/api/admin/check-session',{
      credentials:'same-origin',
      cache:'no-store'
    });

    const r = await Promise.race([fetchPromise, timeoutPromise]);

    if(!r.ok) {
      console.error('Check session failed with status:', r.status);
      renderLogin(root);
      return;
    }

    const j = await r.json();
    if(!j.success || !j.isAdmin){
      renderLogin(root);
    } else {
      await renderAdmin(root, j.username);
    }
  }catch(err){
    console.error('Admin check error:', err);
    renderLogin(root);
  }
}

function renderLogin(root){
  root.innerHTML='';
  const wrap=document.createElement('div');
  wrap.className='panel max-w-md mx-auto rounded-2xl border p-8 shadow-xl animate-in';
  wrap.innerHTML='<div class="text-center mb-6">'+
    '<div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-cyan-500 to-blue-500 mb-4">'+
      '<span class="text-3xl">🔐</span>'+
    '</div>'+
    '<h1 class="text-2xl font-bold mb-2">管理员登录</h1>'+
    '<p class="text-sm muted">请输入管理员密码以继续</p>'+
  '</div>'+
    '<form id="admin-login-form" class="space-y-4">'+
      '<div>'+
        '<label class="block mb-2 text-sm font-medium flex items-center gap-2">'+
          '<span>🔑</span> 密码'+
        '</label>'+
        '<input type="password" name="password" placeholder="请输入管理员密码" '+
               'class="w-full rounded-lg border px-4 py-3 text-sm focus:ring-2 focus:ring-cyan-500"/>'+
      '</div>'+
      '<div id="admin-login-msg" class="text-sm min-h-[1.5rem] font-medium"></div>'+
      '<button type="submit" class="w-full inline-flex items-center justify-center gap-2 rounded-xl '+
                                    'bg-gradient-to-r from-cyan-500 to-blue-500 px-6 py-3 text-sm font-bold '+
                                    'shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all duration-200">'+
        '<span class="text-lg">🚀</span> 登录'+
      '</button>'+
    '</form>';
  root.appendChild(wrap);
  document.getElementById('admin-login-form').addEventListener('submit', async(e)=>{
    e.preventDefault();
    const fd=new FormData(e.target);
    const pwd=fd.get('password')?.toString()||'';
    try{
      const r=await fetch('/api/admin/login',{

        method:'POST',
        credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({password:pwd})
      });
      const j=await r.json();
      if(!r.ok||!j.success){
        toast(j.message||'登录失败','error');
      } else {
        toast('登录成功','success');
        location.reload();
      }
    }catch(err){
      console.error('Login error:', err);
      toast('登录异常','error');
    }
  });
}

async function renderAdmin(root, name){
  root.innerHTML='';
  const header=document.createElement('header');
  header.className='mb-8 animate-in';
  header.innerHTML='<div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">'+
    '<div class="space-y-3">'+
      '<div class="flex items-center gap-3">'+
        '<div class="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-500">'+
          '<span class="text-2xl">⚙️</span>'+
        '</div>'+
        '<h1 class="grad-title text-3xl md:text-4xl font-bold">VPS 管理后台</h1>'+
      '</div>'+
      '<p class="text-sm muted flex items-center gap-2 ml-15">'+
        '<span class="text-base">🔒</span>'+
        '<span>仅管理员可见，可查看全部投喂 VPS 与认证信息</span>'+
      '</p>'+
    '</div>'+
    '<div class="flex flex-wrap items-center gap-3">'+
      '<div class="flex items-center gap-2 bg-slate-100 dark:bg-slate-800/50 rounded-full px-4 py-2 border">'+
        '<span class="text-sm">👤</span>'+
        '<span class="text-sm font-medium">'+name+'</span>'+
      '</div>'+
      '<button id="theme-toggle" class="text-xs" onclick="toggleTheme()">浅色模式</button>'+
      '<button id="btn-admin-logout" class="text-xs rounded-full border border-slate-300 hover:border-red-400 px-4 py-2 '+
                                      'transition-all hover:bg-red-500/10 hover:text-red-500">'+
        '退出登录'+
      '</button>'+
    '</div>'+
  '</div>';
  root.appendChild(header);
  updateThemeBtn();
  document.getElementById('theme-toggle').addEventListener('click',toggleTheme);
  document.getElementById('btn-admin-logout').addEventListener('click', async()=>{
    try{await fetch('/api/admin/logout',{credentials:'same-origin'})}catch{}
    location.reload();
  });

  const stats=document.createElement('section');
  stats.id='admin-stats';
  root.appendChild(stats);

  const cfg=document.createElement('section');
  cfg.id='admin-config';
  cfg.className='mt-6 space-y-4';
  cfg.innerHTML=
  '<div class="panel rounded-2xl border p-6 shadow-lg">'+
    '<div class="flex items-center justify-between mb-4">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-xl">🔗</span>'+
        '<h2 class="text-lg font-bold">OAuth 配置</h2>'+
      '</div>'+
      '<button id="btn-toggle-oauth" class="text-xs rounded-full border px-3 py-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all">展开</button>'+
    '</div>'+
    '<div id="oauth-body" class="hidden">'+
      '<form id="oauth-form" class="grid md:grid-cols-3 gap-4">'+
        '<div>'+
          '<label class="block mb-2 text-sm font-medium flex items-center gap-1.5">'+
            '<span>🆔</span> Client ID'+
          '</label>'+
          '<input name="clientId" placeholder="输入 Client ID" class="w-full rounded-lg border px-3 py-2 text-sm"/>'+
        '</div>'+
        '<div>'+
          '<label class="block mb-2 text-sm font-medium flex items-center gap-1.5">'+
            '<span>🔐</span> Client Secret'+
          '</label>'+
          '<input name="clientSecret" placeholder="输入 Client Secret" class="w-full rounded-lg border px-3 py-2 text-sm"/>'+
        '</div>'+
        '<div>'+
          '<label class="block mb-2 text-sm font-medium flex items-center gap-1.5">'+
            '<span>🔗</span> Redirect URI'+
          '</label>'+
          '<input name="redirectUri" placeholder="输入 Redirect URI" class="w-full rounded-lg border px-3 py-2 text-sm"/>'+
        '</div>'+
      '</form>'+
      '<div class="mt-4 flex gap-2">'+
        '<button id="btn-save-oauth" class="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 '+
                                          'px-4 py-2 text-sm font-bold shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all">'+
          '<span>💾</span> 保存 OAuth 配置'+
        '</button>'+
      '</div>'+
    '</div>'+
  '</div>'+
  '<div class="panel rounded-2xl border p-6 shadow-lg">'+
    '<div class="flex items-center gap-3 mb-4">'+
      '<span class="text-xl">🔑</span>'+
      '<h2 class="text-lg font-bold">管理员密码</h2>'+
    '</div>'+
    '<p class="text-sm muted mb-4 bg-amber-500/5 border border-amber-500/20 rounded-xl px-3 py-2">'+
      '⚠️ 仅用于 <code class="px-1.5 py-0.5 bg-slate-200 dark:bg-slate-800 rounded">/admin</code> 后台登录，至少 6 位，建议与 Linux.do 账号密码不同'+
    '</p>'+
    '<div class="grid md:grid-cols-2 gap-4 mb-4">'+
      '<div>'+
        '<label class="block mb-2 text-sm font-medium">新密码</label>'+
        '<input id="admin-pass-input" type="password" placeholder="输入新的管理员密码" '+
               'class="w-full rounded-lg border px-3 py-2.5 text-sm"/>'+
      '</div>'+
      '<div>'+
        '<label class="block mb-2 text-sm font-medium">确认密码</label>'+
        '<input id="admin-pass-input2" type="password" placeholder="再次输入以确认" '+
               'class="w-full rounded-lg border px-3 py-2.5 text-sm"/>'+
      '</div>'+
    '</div>'+
    '<button id="btn-save-admin-pass" class="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-green-500 '+
                                              'px-4 py-2 text-sm font-bold shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all">'+
      '<span>🔒</span> 保存密码'+
    '</button>'+
    '<p class="text-xs muted mt-3">💡 修改成功后立即生效，下次登录需要使用新密码</p>'+
  '</div>';
  root.appendChild(cfg);

  document.getElementById('btn-toggle-oauth').addEventListener('click',()=>{
    const b=document.getElementById('oauth-body');
    const btn=document.getElementById('btn-toggle-oauth');
    if(b.classList.contains('hidden')){
      b.classList.remove('hidden');
      btn.textContent='收起';
    } else {
      b.classList.add('hidden');
      btn.textContent='展开';
    }
  });
  document.getElementById('btn-save-oauth').addEventListener('click', saveOAuth);
  document.getElementById('btn-save-admin-pass').addEventListener('click', saveAdminPassword);

  const listWrap=document.createElement('section');
  listWrap.className='mt-8';
  listWrap.innerHTML='<div class="panel rounded-2xl border p-6 shadow-lg mb-6">'+
    '<div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-2xl">📋</span>'+
        '<h2 class="text-2xl font-bold">VPS 列表</h2>'+
      '</div>'+
      '<button id="btn-verify-all" class="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-purple-500 to-pink-500 '+
                                          'px-4 py-2 text-sm font-bold shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all">'+
        '<span>🔄</span> 一键验证全部'+
      '</button>'+
    '</div>'+
    '<div class="flex flex-col md:flex-row gap-3">'+
      '<div class="flex flex-wrap items-center gap-2">'+
        '<span class="text-sm font-medium">筛选：</span>'+
        '<button data-status="all" class="px-3 py-1.5 rounded-full border text-xs hover:bg-slate-100 dark:hover:bg-slate-800 transition-all">全部</button>'+
        '<button data-status="active" class="px-3 py-1.5 rounded-full border text-xs hover:bg-slate-100 dark:hover:bg-slate-800 transition-all">✅ 运行中</button>'+
        '<button data-status="failed" class="px-3 py-1.5 rounded-full border text-xs hover:bg-slate-100 dark:hover:bg-slate-800 transition-all">❌ 失败</button>'+
      '</div>'+
      '<div class="flex-1 flex gap-2">'+
        '<input id="filter-input" placeholder="🔍 搜索 IP / 用户名 / 备注..." '+
               'class="flex-1 rounded-lg border px-3 py-2 text-sm"/>'+
        '<button id="filter-btn" class="px-4 py-2 rounded-lg border text-sm font-medium hover:bg-slate-100 dark:hover:bg-slate-800 transition-all">搜索</button>'+
        '<button id="filter-clear-btn" class="px-4 py-2 rounded-lg border text-sm font-medium hover:bg-slate-100 dark:hover:bg-slate-800 transition-all">清除</button>'+
      '</div>'+
    '</div>'+
  '</div>'+
  '<div id="vps-list" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"></div>';
  root.appendChild(listWrap);

  listWrap.querySelectorAll('button[data-status]').forEach(btn=> btn.addEventListener('click',()=>{
    statusFilter=btn.getAttribute('data-status')||'all';
    userFilter='';
    renderVpsList();
  }));
  document.getElementById('filter-btn').addEventListener('click',()=>{
    searchFilter=document.getElementById('filter-input').value.trim();
    userFilter='';
    renderVpsList();
  });
  document.getElementById('filter-clear-btn').addEventListener('click',()=>{
    searchFilter='';
    document.getElementById('filter-input').value='';
    userFilter='';
    renderVpsList();
  });
  document.getElementById('btn-verify-all').addEventListener('click', verifyAll);

  await loadStats();
  await loadConfig();
  await loadVps();
}

async function loadStats(){
  const wrap=document.getElementById('admin-stats');
  wrap.innerHTML='<div class="flex items-center justify-center py-8">'+
    '<div class="flex flex-col items-center gap-3">'+
      '<div class="loading-spinner"></div>'+
      '<div class="text-sm muted">正在加载统计信息...</div>'+
    '</div>'+
  '</div>';
  try{
    const r=await fetch('/api/admin/stats',{credentials:'same-origin',cache:'no-store'});

    if(!r.ok) {
      wrap.innerHTML='<div class="text-red-400 text-xs">统计信息加载失败: HTTP '+r.status+'</div>';
      return;
    }

    const j=await r.json();
    if(!j.success){
      wrap.innerHTML='<div class="text-red-400 text-xs">统计信息加载失败</div>';
      return;
    }

    const d=j.data||{};
    function card(label,value,key){
      return '<button data-gok="'+key+'" class="stat-card stat-'+key+' rounded-2xl border px-3 py-2 text-left">'+
        '<div class="stat-label text-[11px] muted">'+label+'</div><div class="stat-value mt-1">'+value+'</div></button>';
    }
    wrap.innerHTML='<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 mb-3">'+
      card('总投喂数',d.totalVPS||0,'all')+
      card('运行中',d.activeVPS||0,'active')+
      card('失败',d.failedVPS||0,'failed')+
      card('今日新增',d.todayNewVPS||0,'today')+'</div>';
    wrap.querySelectorAll('button[data-gok]').forEach(b=> b.addEventListener('click',()=>{
      statusFilter=b.getAttribute('data-gok');
      userFilter='';
      renderVpsList();
    }));
  }catch(err){
    console.error('Stats load error:', err);
    wrap.innerHTML='<div class="text-red-400 text-xs">统计信息加载异常</div>';
  }
}

async function loadConfig(){
  try {
    const res=await fetch('/api/admin/config/oauth',{credentials:'same-origin',cache:'no-store'});
    const j=await res.json();
    const cfg=j.data||{};
    const f=document.getElementById('oauth-form');
    f.querySelector('input[name="clientId"]').value=cfg.clientId||'';
    f.querySelector('input[name="clientSecret"]').value=cfg.clientSecret||'';
    f.querySelector('input[name="redirectUri"]').value=cfg.redirectUri||'';
  } catch(err) {
    console.error('Config load error:', err);
  }
}

async function saveOAuth(){
  const f=document.getElementById('oauth-form');
  const payload={
    clientId:f.querySelector('input[name="clientId"]').value.trim(),
    clientSecret:f.querySelector('input[name="clientSecret"]').value.trim(),
    redirectUri:f.querySelector('input[name="redirectUri"]').value.trim()
  };
  try{
    const r=await fetch('/api/admin/config/oauth',{
      method:'PUT',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const j=await r.json();
    if(!r.ok||!j.success){
      toast(j.message||'保存失败','error');
    } else {
      toast('OAuth 已保存','success');
    }
  }catch(err){
    console.error('Save OAuth error:', err);
    toast('保存异常','error');
  }
}

async function saveAdminPassword(){
  const input=document.getElementById('admin-pass-input');
  const input2=document.getElementById('admin-pass-input2');
  const pwd=input.value.trim();
  const pwd2=input2.value.trim();
  if(!pwd || !pwd2){
    toast('请填写两次新密码','warn');
    return;
  }
  if(pwd!==pwd2){
    toast('两次输入的密码不一致','error');
    return;
  }
  try{
    const r=await fetch('/api/admin/config/password',{
      method:'PUT',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pwd})
    });
    const j=await r.json();
    if(!r.ok||!j.success){
      toast(j.message||'保存失败','error');
    } else {
      toast('管理员密码已更新','success');
      input.value='';
      input2.value='';
    }
  }catch(err){
    console.error('Save admin password error:', err);
    toast('保存异常','error');
  }
}

async function loadVps(){
  const list=document.getElementById('vps-list');
  list.innerHTML='<div class="col-span-full flex items-center justify-center py-12">'+
    '<div class="flex flex-col items-center gap-3">'+
      '<div class="loading-spinner"></div>'+
      '<div class="text-sm muted">正在加载 VPS 列表...</div>'+
    '</div>'+
  '</div>';
  try{
    const r=await fetch('/api/admin/vps',{credentials:'same-origin',cache:'no-store'});

    if(!r.ok) {
      list.innerHTML='<div class="text-red-400 text-xs col-span-full">加载失败: HTTP '+r.status+'</div>';
      return;
    }

    const j=await r.json();
    if(!j.success){
      list.innerHTML='<div class="text-red-400 text-xs col-span-full">加载失败</div>';
      return;
    }
    allVpsList=j.data||[];
    renderVpsList();
  }catch(err){
    console.error('VPS load error:', err);
    list.innerHTML='<div class="text-red-400 text-xs col-span-full">加载异常: '+err.message+'</div>';
  }
}

async function verifyAll(){
  if(!allVpsList.length){
    toast('当前没有 VPS 可以验证','warn');
    return;
  }
  if(!confirm('确定要对全部 VPS 执行连通性检测吗？这可能会持续数十秒。')) return;
  try{
    const r=await fetch('/api/admin/verify-all',{method:'POST',credentials:'same-origin'});
    const j=await r.json();
    if(!r.ok||!j.success){
      toast(j.message||'批量验证失败','error');
    }else{
      const d=j.data||{};
      const msg=j.message||('批量验证完成：成功 '+(d.success||0)+' 台，失败 '+(d.failed||0)+' 台');
      toast(msg,'success',4000);
    }
  }catch(err){
    console.error('Verify all error:',err);
    toast('批量验证异常','error');
  }
  await loadVps();
  await loadStats();
}

function renderVpsList(){
  const list=document.getElementById('vps-list');
  if(!allVpsList.length){
    list.innerHTML='<div class="muted text-xs col-span-full">暂无 VPS 记录</div>';
    return;
  }

  const kw=(searchFilter||'').toLowerCase();

  const arr=allVpsList.filter(v=>{
    let ok=true;
    if(statusFilter==='active') ok=v.status==='active';
    else if(statusFilter==='failed') ok=v.status==='failed';
    else if(statusFilter==='today') ok=v.donatedAt && isTodayLocal(v.donatedAt);
    if(userFilter) ok=ok && v.donatedByUsername===userFilter;
    if(kw){
      const hay=[v.ip,String(v.port),v.donatedByUsername,v.country,v.traffic,v.specs,v.note,v.adminNote].join(' ').toLowerCase();
      ok=ok && hay.includes(kw);
    }
    return ok;
  });

  if(!arr.length){
    list.innerHTML='<div class="muted text-xs col-span-full">当前筛选下没有 VPS</div>';
    return;
  }

  list.innerHTML='';
  arr.forEach(v=>{
    const card=document.createElement('div');
    card.className='card rounded-2xl border p-4 flex flex-col gap-3 text-sm shadow-lg hover:shadow-xl transition-all';
    const dt=v.donatedAt?new Date(v.donatedAt):null;
    const t=dt?dt.toLocaleString():'';
    const uname=v.donatedByUsername||'';
    const p='https://linux.do/u/'+encodeURIComponent(uname);

    card.innerHTML='<div class="flex items-center justify-between gap-2 pb-3 border-b">'+
        '<div class="flex items-center gap-2 text-sm font-medium">'+
          '<span>🖥️</span>'+
          '<span class="break-words">'+v.ip+':'+v.port+'</span>'+
        '</div>'+
        '<span class="'+scls(v.status)+' text-xs px-2 py-1 rounded-full">'+stxt(v.status)+'</span>'+
      '</div>'+
      '<div class="space-y-2 text-xs">'+
        '<div class="flex items-center gap-2">'+
          '<span class="opacity-60">👤</span>'+
          '<span>投喂者：<a href="'+p+'" target="_blank" class="text-sky-500 hover:text-cyan-400 underline transition-colors">@'+uname+'</a></span>'+
        '</div>'+
        '<div class="flex items-center gap-2">'+
          '<span class="opacity-60">🌍</span>'+
          '<span>'+(v.country||'未填写')+(v.ipLocation?' · '+v.ipLocation:'')+'</span>'+
        '</div>'+
        '<div class="grid grid-cols-2 gap-2">'+
          '<div class="flex items-center gap-1.5"><span class="opacity-60">📊</span><span class="truncate">'+(v.traffic||'未填写')+'</span></div>'+
          '<div class="flex items-center gap-1.5"><span class="opacity-60">📅</span><span class="truncate">'+(v.expiryDate||'未填写')+'</span></div>'+
        '</div>'+
        '<div class="bg-slate-100 dark:bg-slate-800/50 rounded-lg px-2 py-1.5 flex items-start gap-1.5">'+
          '<span class="opacity-60">⚙️</span>'+
          '<span class="break-words">'+(v.specs||'未填写')+'</span>'+
        '</div>'+
        (v.note?'<div class="bg-amber-500/5 border border-amber-500/20 rounded-lg px-2 py-1.5 text-amber-600 dark:text-amber-300 flex items-start gap-1.5">'+
          '<span class="opacity-60">💬</span>'+
          '<span class="break-words">'+v.note+'</span>'+
        '</div>':'')+
        (v.adminNote?'<div class="bg-cyan-500/5 border border-cyan-500/20 rounded-lg px-2 py-1.5 text-cyan-600 dark:text-cyan-300 flex items-start gap-1.5">'+
          '<span class="opacity-60">📝</span>'+
          '<span class="break-words">'+v.adminNote+'</span>'+
        '</div>':'')+
        (t?'<div class="flex items-center gap-1.5 text-xs muted"><span class="opacity-60">🕐</span><span>'+t+'</span></div>':'')+
      '</div>'+
      '<div class="flex flex-wrap gap-2 pt-3 border-t">'+
        '<button class="px-3 py-1.5 rounded-lg border text-xs hover:bg-slate-100 dark:hover:bg-slate-800 transition-all" data-act="login" data-id="'+v.id+'">🔍 查看</button>'+
        '<button class="px-3 py-1.5 rounded-lg border text-xs hover:bg-slate-100 dark:hover:bg-slate-800 transition-all" data-act="verify" data-id="'+v.id+'">✅ 验证</button>'+
        '<button class="px-3 py-1.5 rounded-lg border text-xs hover:bg-slate-100 dark:hover:bg-slate-800 transition-all" data-act="edit" data-id="'+v.id+'">✏️ 编辑</button>'+
        '<button class="px-3 py-1.5 rounded-lg border border-red-300 text-red-500 text-xs hover:bg-red-50 dark:hover:bg-red-900/20 transition-all" data-act="del" data-id="'+v.id+'">🗑️ 删除</button>'+
      '</div>';

    card.querySelectorAll('button[data-act]').forEach(btn=>{
      const id=btn.getAttribute('data-id');
      const act=btn.getAttribute('data-act');
      btn.addEventListener('click', async()=>{
        if(!id) return;

        if(act==='login'){
          modalLoginInfo(v);
          return;
        }

        if(act==='verify'){
          try{
            const r=await fetch('/api/admin/vps/'+id+'/verify',{method:'POST',credentials:'same-origin'});
            const j=await r.json();
            toast(j.message || (j.success ? '验证成功' : '验证失败'), j.success ? 'success' : 'error');

            // 本地就地更新，不再整页重新加载，避免列表抖动
            const target = allVpsList.find(x => x.id === id);
            if (target) {
              const data = j.data || {};
              const now = Date.now();
              target.lastVerifyAt = data.lastVerifyAt || now;
              if (j.success) {
                target.status = data.status || 'active';
                target.verifyStatus = data.verifyStatus || 'verified';
                target.verifyErrorMsg = data.verifyErrorMsg || '';
              } else {
                target.status = data.status || 'failed';
                target.verifyStatus = data.verifyStatus || 'failed';
                target.verifyErrorMsg =
                  data.verifyErrorMsg || '无法连接 VPS，请检查服务器是否在线、防火墙/安全组端口放行';
              }
              renderVpsList();
            }
          }catch{
            toast('验证异常','error');
          }
          // 只刷新顶部统计，不再重新拉取全部 VPS 列表
          await loadStats();
          return;
        }

        if(act==='failed'){
          try{
            const r=await fetch('/api/admin/vps/'+id+'/status',{
              method:'PUT',
              credentials:'same-origin',
              headers:{'Content-Type':'application/json'},
              body:JSON.stringify({status:'failed'})
            });
            const j=await r.json();
            toast(j.message||'已更新','success');
          }catch{
            toast('更新失败','error');
          }
        }
        else if(act==='del'){
          try{
            const r=await fetch('/api/admin/vps/'+id,{method:'DELETE',credentials:'same-origin'});
            const j=await r.json();
            toast(j.message||'已删除', r.ok?'success':'error');
          }catch{
            toast('删除失败','error');
          }
        }
        else if(act==='edit'){
          modalEdit('编辑 VPS 信息（用户备注前台可见）',[
            {key:'country',label:'国家/区域',value:v.country||'',placeholder:'如：HK - Hong Kong, Kowloon, Hong Kong'},
            {key:'traffic',label:'流量/带宽',value:v.traffic||'',placeholder:'如：400G/月 · 1Gbps'},
            {key:'expiryDate',label:'到期时间',value:v.expiryDate||'',placeholder:'YYYY-MM-DD'},
            {key:'specs',label:'配置描述',value:v.specs||'',placeholder:'如：1C1G · 10Gbps · 1T/月'},
            {key:'note',label:'公用备注（前台可见）',value:v.note||'',type:'textarea',placeholder:'如：电信方向无法大陆优选链路…'},
            {key:'adminNote',label:'管理员备注（仅后台）',value:v.adminNote||'',type:'textarea',placeholder:'仅管理员可见的附注'}
          ], async(data,close)=>{
            try{
              const r=await fetch('/api/admin/vps/'+id+'/notes',{
                method:'PUT',
                credentials:'same-origin',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify(data)
              });
              const j=await r.json();
              if(!r.ok||!j.success){
                toast(j.message||'保存失败','error');
              }else{
                toast('已保存','success');
                close();
                await loadVps();
                await loadStats();
              }
            }catch{
              toast('保存异常','error');
            }
          });
          return;
        }

        await loadVps();
        await loadStats();
      });
    });

    const link=card.querySelector('a[href^="https://linux.do/u/"]');
    if(link){
      link.addEventListener('click',e=>{
        e.preventDefault();
        userFilter=v.donatedByUsername;
        renderVpsList();
      });
    }
    list.appendChild(card);
  });
}

checkAdmin();
</script>
</body></html>`;
  return c.html(html);
});

/* ==================== 公共 head（主题 + 全局样式 + 工具） ==================== */
function commonHead(title: string): string {
  return `
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${title}</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = {
  theme: {
    extend: {
      colors: {
        border: "hsl(214.3 31.8% 91.4%)",
        primary: {
          DEFAULT: "hsl(222.2 47.4% 11.2%)",
          foreground: "hsl(210 40% 98%)",
        },
      }
    }
  }
}
</script>
<style>
:root{
  --radius: 0.5rem;
  color-scheme: light;
}
html,body{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-size: 15px;
  -webkit-font-smoothing: antialiased;
  overflow-x: hidden;
}
body{
  background: #f8fafc;
  color: #1e293b;
  min-height: 100vh;
}
body[data-theme="dark"]{
  color-scheme: dark;
  background: linear-gradient(135deg, #020617 0%, #0f172a 100%);
  color: #e5f0ff;
}

@keyframes slideUpAndFade {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
.animate-in {
  animation: slideUpAndFade 0.4s ease-out;
}

.loading-spinner {
  width: 16px;
  height: 16px;
  border: 2px solid #f3f4f6;
  border-top-color: #3b82f6;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}

.panel,.card{
  background: white;
  border: 1px solid #e2e8f0;
  box-shadow: 0 1px 3px 0 rgba(0,0,0,0.1), 0 1px 2px -1px rgba(0,0,0,0.1);
  transition: all 0.2s ease;
}
.card:hover {
  box-shadow: 0 4px 12px rgba(0,0,0,0.08);
  transform: translateY(-2px);
}
body[data-theme="dark"] .panel,
body[data-theme="dark"] .card{
  background: rgba(15,23,42,.95);
  border-color: rgba(56,189,248,.3);
  box-shadow: 0 20px 50px rgba(0,0,0,.5), 0 0 0 1px rgba(56,189,248,.1);
  backdrop-filter: blur(10px);
}
body[data-theme="dark"] .card:hover{
  box-shadow: 0 25px 60px rgba(0,0,0,.6), 0 0 0 1px rgba(56,189,248,.3);
}

.card{
  word-break: break-word;
  transition: all 0.3s ease;
}

/* 新增：弹窗内大段文本（SSH 密钥等）样式 */
.modal-text-block{
  word-break: break-all;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
  max-height: 260px;
  overflow-y: auto;
  padding: 6px 8px;
  border-radius: 0.5rem;
  background: rgba(15,23,42,.85);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}
body[data-theme="light"] .modal-text-block{
  background:#f3f4f6;
}

.muted{
  color: #94a3b8;
}
body[data-theme="light"] .muted{
  color: #6b7280;
}

.grad-title{
  background-image: linear-gradient(115deg, #22d3ee 0%, #38bdf8 25%, #a855f7 50%, #ec4899 75%, #f97316 100%);
  background-size: 320% 100%;
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  display: inline-block;
  animation: grad-loop 12s ease-in-out infinite alternate;
  text-shadow: 0 0 30px rgba(56,189,248,0.3);
}
@keyframes grad-loop{
  0%{ background-position: 0% 50%; }
  100%{ background-position: 100% 50%; }
}

#toast-root{
  position:fixed;
  inset:0;
  z-index:9999;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  gap:10px;
  pointer-events:none;
}
.toast{
  padding:10px 12px;
  border-radius:12px;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(15,23,42,.97);
  color:#e5f0ff;
  box-shadow:0 10px 30px rgba(0,0,0,.5);
  transform:translateY(10px);
  opacity:0;
  transition:all .25s ease;
  pointer-events:auto;
}
.toast.show{ transform:translateY(0); opacity:1; }
.toast.success{ border-color:#10b981; }
.toast.error{ border-color:#ef4444; }
.toast.warn{ border-color:#f59e0b; }

.help{ font-size:11px; opacity:.8; }

.badge-ok{
  color: #34d399;
  font-weight: 600;
  text-shadow: 0 0 10px rgba(52,211,153,0.3);
}
.badge-fail{
  color: #f97373;
  font-weight: 600;
  text-shadow: 0 0 10px rgba(249,115,115,0.3);
}
.badge-idle{
  color: #cbd5e1;
}

#theme-toggle{
  border-radius: 9999px;
  padding: 0.5rem 1rem;
  border: 1px solid rgba(148,163,184,.4);
  background: rgba(15,23,42,.9);
  color: #e5e7eb;
  box-shadow: 0 8px 20px rgba(15,23,42,.9);
  transition: all 0.3s ease;
  cursor: pointer;
}
#theme-toggle:hover{
  background: rgba(30,41,59,.95);
  border-color: rgba(56,189,248,.6);
  box-shadow: 0 10px 25px rgba(15,23,42,.95), 0 0 20px rgba(56,189,248,.2);
  transform: translateY(-2px);
}
body[data-theme="light"] #theme-toggle{
  background: #ffffff;
  color: #374151;
  border-color: #d1d5db;
  box-shadow: 0 6px 18px rgba(148,163,184,.3);
}
body[data-theme="light"] #theme-toggle:hover{
  border-color: #38bdf8;
  box-shadow: 0 8px 22px rgba(148,163,184,.4), 0 0 15px rgba(56,189,248,.15);
  transform: translateY(-2px);
}

.stat-card{
  background: linear-gradient(135deg, rgba(15,23,42,1), rgba(30,64,175,.8));
  border-color: rgba(56,189,248,.4);
  transition: all 0.3s ease;
  cursor: pointer;
}
.stat-card:hover{
  transform: translateY(-4px);
  box-shadow: 0 25px 60px rgba(0,0,0,.6), 0 0 0 1px rgba(56,189,248,.3);
  border-color: rgba(56,189,248,.6);
}
.stat-card .stat-value{
  font-size: 1.8rem;
  font-weight: 700;
  color: #7dd3fc;
  text-shadow: 0 0 20px rgba(125,211,252,0.3);
}
.stat-card.stat-active .stat-value{
  color: #22c55e;
  text-shadow: 0 0 20px rgba(34,197,94,0.3);
}
.stat-card.stat-failed .stat-value{
  color: #f97373;
  text-shadow: 0 0 20px rgba(249,115,115,0.3);
}
.stat-card.stat-inactive .stat-value{ color: #eab308; }
.stat-card.stat-pending .stat-value{ color: #facc15; }
.stat-card.stat-today .stat-value{
  color: #38bdf8;
  text-shadow: 0 0 20px rgba(56,189,248,0.3);
}
body[data-theme="light"] .stat-card{
  background: linear-gradient(135deg, #eff6ff, #e0f2fe);
  border-color: #bfdbfe;
}
body[data-theme="light"] .stat-card:hover{
  box-shadow: 0 25px 60px rgba(148,163,184,.25), 0 0 0 1px rgba(56,189,248,.3);
}
body[data-theme="light"] .stat-card .stat-value{
  color: #0f766e;
  text-shadow: none;
}
body[data-theme="light"] .stat-card.stat-active .stat-value{ color: #16a34a; }
body[data-theme="light"] .stat-card.stat-failed .stat-value{ color: #ef4444; }
body[data-theme="light"] .stat-card.stat-today .stat-value{ color: #0284c7; }

.text-xs{ font-size:0.8rem; line-height:1.4; }
.text-sm{ font-size:0.9rem; line-height:1.45; }

input, textarea, select{
  background: rgba(2,6,23,.8);
  color: #e5f0ff;
  border: 1px solid rgba(51,65,85,.6);
  transition: all 0.2s ease;
}
input:focus, textarea:focus, select:focus{
  background: rgba(2,6,23,.95);
  border-color: #38bdf8;
  box-shadow: 0 0 0 3px rgba(56,189,248,.1);
  outline: none;
}
input::placeholder,
textarea::placeholder{
  color: #64748b;
}
body[data-theme="light"] input,
body[data-theme="light"] textarea,
body[data-theme="light"] select{
  background: #ffffff;
  color: #111827;
  border-color: #d1d5db;
}
body[data-theme="light"] input:focus,
body[data-theme="light"] textarea:focus,
body[data-theme="light"] select:focus{
  border-color: #38bdf8;
  box-shadow: 0 0 0 3px rgba(56,189,248,.1);
}
body[data-theme="light"] input::placeholder,
body[data-theme="light"] textarea::placeholder{
  color: #9ca3af;
}

button{
  transition: all 0.2s ease;
  cursor: pointer;
}
button:hover{
  filter: brightness(1.1);
}
button:active{
  transform: scale(0.98);
}
button:disabled{
  opacity: 0.5;
  cursor: not-allowed;
}

@media (max-width: 640px){
  html,body{
    font-size:14px;
  }
  .grad-title{
    font-size:1.6rem;
    line-height:1.3;
  }
  .panel,.card{
    border-radius:16px;
  }
}
</style>
<script>
(function(){
  const saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  document.addEventListener('DOMContentLoaded', () => {
    document.body.setAttribute('data-theme', saved);
  });
})();

function toggleTheme(){
  const cur = document.body.getAttribute('data-theme') || 'dark';
  const nxt = cur === 'dark' ? 'light' : 'dark';
  document.body.setAttribute('data-theme', nxt);
  document.documentElement.setAttribute('data-theme', nxt);
  localStorage.setItem('theme', nxt);
  updateThemeBtn && updateThemeBtn();
}

function updateThemeBtn(){
  const b=document.getElementById('theme-toggle');
  if(b){
    const cur=document.body.getAttribute('data-theme')||'dark';
    b.textContent = cur==='dark' ? '浅色模式' : '深色模式';
  }
}

function toast(msg,type='info',ms=2600){
  let root=document.getElementById('toast-root');
  if(!root){
    root=document.createElement('div');
    root.id='toast-root';
    document.body.appendChild(root);
  }
  const el=document.createElement('div');
  el.className='toast '+(type==='success'?'success':type==='error'?'error':type==='warn'?'warn':'');
  el.textContent=msg;
  root.appendChild(el);
  requestAnimationFrame(()=>el.classList.add('show'));
  setTimeout(()=>{
    el.classList.remove('show');
    setTimeout(()=>el.remove(),250);
  },ms);
}

function copyToClipboard(text){
  if(!text){
    toast('没有可复制的内容','warn');
    return;
  }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(()=>toast('已复制到剪贴板','success')).catch(()=>toast('复制失败','error'));
  }else{
    const ta=document.createElement('textarea');
    ta.value=text;
    ta.style.position='fixed';
    ta.style.left='-9999px';
    ta.style.top='-9999px';
    document.body.appendChild(ta);
    ta.select();
    try{
      document.execCommand('copy');
      toast('已复制到剪贴板','success');
    }catch(e){
      toast('复制失败','error');
    }
    document.body.removeChild(ta);
  }
}

function modalEdit(title, fields, onOk){
  const wrap=document.createElement('div');
  wrap.style.cssText='position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;';
  const card=document.createElement('div');
  card.className='panel rounded-2xl border p-4';
  card.style.width='min(680px,92vw)';
  const h=document.createElement('div');
  h.className='text-lg font-semibold mb-3';
  h.textContent=title;
  card.appendChild(h);
  const form=document.createElement('div');
  form.className='grid grid-cols-2 gap-3 text-sm';
  fields.forEach(f=>{
    const box=document.createElement('div');
    const lab=document.createElement('div');
    lab.className='muted text-xs mb-1';
    lab.textContent=f.label;
    const inp=f.type==='textarea'?document.createElement('textarea'):document.createElement('input');
    if(f.type!=='textarea') inp.type='text';
    inp.value=f.value||'';
    inp.placeholder=f.placeholder||'';
    if(f.type==='textarea') inp.rows=3;
    inp.className='w-full rounded-lg border px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500';
    box.appendChild(lab);
    box.appendChild(inp);
    box._get=()=>inp.value;
    box._key=f.key;
    form.appendChild(box);
  });
  card.appendChild(form);
  const actions=document.createElement('div');
  actions.className='mt-4 flex items-center justify-end gap-2';
  const btn1=document.createElement('button');
  btn1.textContent='取消';
  btn1.className='px-3 py-1 rounded-full border';
  btn1.onclick=()=>wrap.remove();
  const btn2=document.createElement('button');
  btn2.textContent='保存';
  btn2.className='px-3 py-1 rounded-full bg-cyan-500 text-black font-semibold';
  btn2.onclick=()=>{ const data={}; form.childNodes.forEach((n)=>{ data[n._key]=n._get(); }); try{ onOk(data,()=>wrap.remove()); }catch(e){ console.error(e); } };
  actions.append(btn1,btn2);
  card.appendChild(actions);
  wrap.appendChild(card);
  document.body.appendChild(wrap);
}

function guessCountryFlag(v) {
  const txt = ((v.country || "") + " " + (v.ipLocation || "")).toLowerCase();

  const rules = [
    // ========= 东亚 / 东北亚 =========
    { k: ["china","prc","cn","中国","beijing","shanghai","guangzhou"], f: "🇨🇳" },
    { k: ["hong kong","hk","香港"], f: "🇭🇰" },
    { k: ["macau","macao","澳门"], f: "🇲🇴" },
    { k: ["taiwan","台灣","台湾"], f: "🇹🇼" },
    { k: ["japan","tokyo","osaka","日本"], f: "🇯🇵" },
    { k: ["korea","south korea","republic of korea","首尔","韓國","韩国","seoul"], f: "🇰🇷" },
    { k: ["north korea","dprk","朝鲜","pyongyang"], f: "🇰🇵" },
    { k: ["mongolia","蒙古"], f: "🇲🇳" },

    // ========= 东南亚 =========
    { k: ["vietnam","越南","hanoi","ho chi minh"], f: "🇻🇳" },
    { k: ["thailand","泰国","bangkok"], f: "🇹🇭" },
    { k: ["malaysia","马来西亚","kuala lumpur"], f: "🇲🇾" },
    { k: ["singapore","新加坡"], f: "🇸🇬" },
    { k: ["philippines","菲律宾","manila"], f: "🇵🇭" },
    { k: ["indonesia","印尼","jakarta"], f: "🇮🇩" },
    { k: ["myanmar","burma","缅甸"], f: "🇲🇲" },
    { k: ["cambodia","柬埔寨","phnom penh"], f: "🇰🇭" },
    { k: ["laos","老挝","vientiane"], f: "🇱🇦" },
    { k: ["brunei","文莱"], f: "🇧🇳" },
    { k: ["timor-leste","east timor","timor","东帝汶"], f: "🇹🇱" },

    // ========= 南亚 =========
    { k: ["india","印度","new delhi","mumbai"], f: "🇮🇳" },
    { k: ["pakistan","巴基斯坦","islamabad"], f: "🇵🇰" },
    { k: ["bangladesh","孟加拉","dhaka"], f: "🇧🇩" },
    { k: ["nepal","尼泊尔","kathmandu"], f: "🇳🇵" },
    { k: ["sri lanka","斯里兰卡","colombo"], f: "🇱🇰" },
    { k: ["maldives","马尔代夫"], f: "🇲🇻" },
    { k: ["bhutan","不丹"], f: "🇧🇹" },
    { k: ["afghanistan","阿富汗"], f: "🇦🇫" },

    // ========= 中东 / 西亚 =========
    { k: ["saudi arabia","saudi","沙特","riyadh"], f: "🇸🇦" },
    { k: ["united arab emirates","uae","dubai","abu dhabi","阿联酋"], f: "🇦🇪" },
    { k: ["israel","以色列","tel aviv","jerusalem"], f: "🇮🇱" },
    { k: ["iran","伊朗","tehran"], f: "🇮🇷" },
    { k: ["iraq","伊拉克","baghdad"], f: "🇮🇶" },
    { k: ["turkey","turkiye","土耳其","ankara","istanbul"], f: "🇹🇷" },
    { k: ["qatar","卡塔尔","doha"], f: "🇶🇦" },
    { k: ["kuwait","科威特"], f: "🇰🇼" },
    { k: ["bahrain","巴林"], f: "🇧🇭" },
    { k: ["oman","阿曼","muscat"], f: "🇴🇲" },
    { k: ["jordan","约旦","amman"], f: "🇯🇴" },
    { k: ["lebanon","黎巴嫩","beirut"], f: "🇱🇧" },
    { k: ["yemen","也门"], f: "🇾🇪" },
    { k: ["syria","syrian arab republic","叙利亚"], f: "🇸🇾" },
    { k: ["palestine","palestinian","巴勒斯坦"], f: "🇵🇸" },

    // ========= 欧洲（西欧 / 北欧 / 南欧 / 东欧） =========
    { k: ["united kingdom","uk","great britain","england","london","英国"], f: "🇬🇧" },
    { k: ["france","paris","法国"], f: "🇫🇷" },
    { k: ["germany","berlin","德国"], f: "🇩🇪" },
    { k: ["netherlands","amsterdam","荷兰"], f: "🇳🇱" },
    { k: ["belgium","比利时","brussels"], f: "🇧🇪" },
    { k: ["luxembourg","卢森堡"], f: "🇱🇺" },
    { k: ["switzerland","瑞士","zurich","geneva"], f: "🇨🇭" },
    { k: ["austria","奥地利","vienna"], f: "🇦🇹" },
    { k: ["ireland","爱尔兰","dublin"], f: "🇮🇪" },
    { k: ["iceland","冰岛","reykjavik"], f: "🇮🇸" },
    { k: ["denmark","丹麦","copenhagen"], f: "🇩🇰" },
    { k: ["sweden","瑞典","stockholm"], f: "🇸🇪" },
    { k: ["norway","挪威","oslo"], f: "🇳🇴" },
    { k: ["finland","芬兰","helsinki"], f: "🇫🇮" },

    { k: ["spain","madrid","barcelona","西班牙"], f: "🇪🇸" },
    { k: ["portugal","里斯本","葡萄牙"], f: "🇵🇹" },
    { k: ["italy","rome","milan","意大利"], f: "🇮🇹" },
    { k: ["greece","雅典","希腊"], f: "🇬🇷" },
    { k: ["malta","马耳他"], f: "🇲🇹" },
    { k: ["cyprus","塞浦路斯"], f: "🇨🇾" },

    { k: ["poland","波兰"], f: "🇵🇱" },
    { k: ["czech","czech republic","捷克"], f: "🇨🇿" },
    { k: ["slovakia","斯洛伐克"], f: "🇸🇰" },
    { k: ["hungary","匈牙利"], f: "🇭🇺" },
    { k: ["romania","罗马尼亚"], f: "🇷🇴" },
    { k: ["bulgaria","保加利亚"], f: "🇧🇬" },
    { k: ["slovenia","斯洛文尼亚"], f: "🇸🇮" },
    { k: ["croatia","克罗地亚"], f: "🇭🇷" },
    { k: ["serbia","塞尔维亚"], f: "🇷🇸" },
    { k: ["bosnia","bosnia and herzegovina","波黑","波斯尼亚"], f: "🇧🇦" },
    { k: ["montenegro","黑山"], f: "🇲🇪" },
    { k: ["north macedonia","macedonia","北马其顿"], f: "🇲🇰" },
    { k: ["albania","阿尔巴尼亚"], f: "🇦🇱" },
    { k: ["kosovo","科索沃"], f: "🇽🇰" },
    { k: ["moldova","moldovan","moldavia","chisinau","摩尔多瓦"], f: "🇲🇩" },
    { k: ["ukraine","乌克兰","kyiv","kiev"], f: "🇺🇦" },
    { k: ["belarus","白俄罗斯"], f: "🇧🇾" },
    { k: ["russia","russian federation","moscow","俄罗斯"], f: "🇷🇺" },
    { k: ["estonia","爱沙尼亚"], f: "🇪🇪" },
    { k: ["latvia","拉脱维亚"], f: "🇱🇻" },
    { k: ["lithuania","立陶宛"], f: "🇱🇹" },

    // ========= 北美 =========
    { k: ["united states","usa","u.s.","america","los angeles","new york","美国"], f: "🇺🇸" },
    { k: ["canada","toronto","vancouver","canadian","加拿大"], f: "🇨🇦" },
    { k: ["mexico","mexican","墨西哥","mexico city"], f: "🇲🇽" },
    { k: ["greenland","格陵兰"], f: "🇬🇱" },

    // ========= 中美洲 & 加勒比 =========
    { k: ["cuba","古巴","havana"], f: "🇨🇺" },
    { k: ["dominican republic","dominican","多米尼加"], f: "🇩🇴" },
    { k: ["haiti","海地"], f: "🇭🇹" },
    { k: ["jamaica","牙买加"], f: "🇯🇲" },
    { k: ["puerto rico","波多黎各"], f: "🇵🇷" },
    { k: ["panama","巴拿马"], f: "🇵🇦" },
    { k: ["costa rica","哥斯达黎加"], f: "🇨🇷" },
    { k: ["guatemala","危地马拉"], f: "🇬🇹" },
    { k: ["honduras","洪都拉斯"], f: "🇭🇳" },
    { k: ["nicaragua","尼加拉瓜"], f: "🇳🇮" },
    { k: ["el salvador","萨尔瓦多"], f: "🇸🇻" },
    { k: ["belize","伯利兹"], f: "🇧🇿" },
    { k: ["trinidad and tobago","trinidad","特立尼达和多巴哥"], f: "🇹🇹" },
    { k: ["barbados","巴巴多斯"], f: "🇧🇧" },
    { k: ["bahamas","巴哈马"], f: "🇧🇸" },
    { k: ["grenada","格林纳达"], f: "🇬🇩" },
    { k: ["saint lucia","圣卢西亚"], f: "🇱🇨" },
    { k: ["saint kitts","kitts and nevis","圣基茨"], f: "🇰🇳" },
    { k: ["saint vincent","st vincent","圣文森特"], f: "🇻🇨" },

    // ========= 南美 =========
    { k: ["brazil","brasil","巴西"], f: "🇧🇷" },
    { k: ["argentina","阿根廷"], f: "🇦🇷" },
    { k: ["chile","智利"], f: "🇨🇱" },
    { k: ["colombia","哥伦比亚"], f: "🇨🇴" },
    { k: ["peru","秘鲁"], f: "🇵🇪" },
    { k: ["uruguay","乌拉圭"], f: "🇺🇾" },
    { k: ["paraguay","巴拉圭"], f: "🇵🇾" },
    { k: ["bolivia","玻利维亚"], f: "🇧🇴" },
    { k: ["ecuador","厄瓜多尔"], f: "🇪🇨" },
    { k: ["venezuela","委内瑞拉"], f: "🇻🇪" },
    { k: ["guyana","圭亚那"], f: "🇬🇾" },
    { k: ["suriname","苏里南"], f: "🇸🇷" },

    // ========= 大洋洲 =========
    { k: ["australia","悉尼","melbourne","澳大利亚"], f: "🇦🇺" },
    { k: ["new zealand","新西兰","auckland"], f: "🇳🇿" },
    { k: ["fiji","斐济"], f: "🇫🇯" },
    { k: ["papua new guinea","巴布亚新几内亚"], f: "🇵🇬" },
    { k: ["samoa","萨摩亚"], f: "🇼🇸" },
    { k: ["tonga","汤加"], f: "🇹🇴" },
    { k: ["vanuatu","瓦努阿图"], f: "🇻🇺" },
    { k: ["solomon islands","所罗门群岛"], f: "🇸🇧" },
    { k: ["palau","帕劳"], f: "🇵🇼" },
    { k: ["micronesia","密克罗尼西亚"], f: "🇫🇲" },
    { k: ["marshall islands","马绍尔群岛"], f: "🇲🇭" },
    { k: ["kiribati","基里巴斯"], f: "🇰🇮" },
    { k: ["nauru","瑙鲁"], f: "🇳🇷" },
    { k: ["tuvalu","图瓦卢"], f: "🇹🇻" },

    // ========= 非洲 =========
    { k: ["south africa","南非","johannesburg"], f: "🇿🇦" },
    { k: ["egypt","埃及","cairo"], f: "🇪🇬" },
    { k: ["nigeria","尼日利亚"], f: "🇳🇬" },
    { k: ["kenya","肯尼亚","nairobi"], f: "🇰🇪" },
    { k: ["ethiopia","埃塞俄比亚"], f: "🇪🇹" },
    { k: ["ghana","加纳"], f: "🇬🇭" },
    { k: ["morocco","摩洛哥"], f: "🇲🇦" },
    { k: ["algeria","阿尔及利亚"], f: "🇩🇿" },
    { k: ["tunisia","突尼斯"], f: "🇹🇳" },
    { k: ["libya","利比亚"], f: "🇱🇾" },
    { k: ["sudan","苏丹"], f: "🇸🇩" },
    { k: ["south sudan","南苏丹"], f: "🇸🇸" },
    { k: ["tanzania","坦桑尼亚"], f: "🇹🇿" },
    { k: ["uganda","乌干达"], f: "🇺🇬" },
    { k: ["angola","安哥拉"], f: "🇦🇴" },
    { k: ["mozambique","莫桑比克"], f: "🇲🇿" },
    { k: ["zambia","赞比亚"], f: "🇿🇲" },
    { k: ["zimbabwe","津巴布韦"], f: "🇿🇼" },
    { k: ["rwanda","卢旺达"], f: "🇷🇼" },
    { k: ["burundi","布隆迪"], f: "🇧🇮" },
    { k: ["botswana","博茨瓦纳"], f: "🇧🇼" },
    { k: ["namibia","纳米比亚"], f: "🇳🇦" },
    { k: ["madagascar","马达加斯加"], f: "🇲🇬" },
    { k: ["seychelles","塞舌尔"], f: "🇸🇨" },
    { k: ["mauritius","毛里求斯"], f: "🇲🇺" },
    { k: ["senegal","塞内加尔"], f: "🇸🇳" },
    { k: ["mali","马里"], f: "🇲🇱" },
    { k: ["niger","尼日尔"], f: "🇳🇪" },
    { k: ["cameroon","喀麦隆"], f: "🇨🇲" },
    { k: ["ivory coast","cote d ivoire","科特迪瓦"], f: "🇨🇮" },
    { k: ["gabon","加蓬"], f: "🇬🇦" },
    { k: ["congo","republic of the congo","刚果共和国"], f: "🇨🇬" },
    { k: ["dr congo","democratic republic of the congo","刚果金"], f: "🇨🇩" },
    { k: ["guinea","几内亚"], f: "🇬🇳" },
    { k: ["guinea-bissau","几内亚比绍"], f: "🇬🇼" },
    { k: ["sierra leone","塞拉利昂"], f: "🇸🇱" },
    { k: ["liberia","利比里亚"], f: "🇱🇷" },
    { k: ["eritrea","厄立特里亚"], f: "🇪🇷" },
    { k: ["djibouti","吉布提"], f: "🇩🇯" },
    { k: ["somalia","索马里"], f: "🇸🇴" }
  ];

  for (const r of rules) {
    if (r.k.some(k => txt.includes(k.toLowerCase()))) {
      return r.f;
    }
  }
  return "";
}




/* 重要：重写的 VPS 登录信息弹窗，支持长密钥换行+滚动+复制 */
function modalLoginInfo(v){
  const wrap=document.createElement('div');
  wrap.style.cssText='position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;';
  const card=document.createElement('div');
  card.className='panel rounded-2xl border p-4';
  card.style.width='min(640px,96vw)';

  const title=document.createElement('div');
  title.className='text-base font-semibold mb-3';
  title.textContent='VPS 登录信息（仅管理员可见）';
  card.appendChild(title);

  const rows=document.createElement('div');
  rows.className='space-y-3 text-xs';

  function addRow(label,value,canCopy=true,isCode=false){
    const row=document.createElement('div');
    row.className='space-y-1';

    const head=document.createElement('div');
    head.className='muted text-xs';
    head.textContent=label;
    row.appendChild(head);

    const body=document.createElement('div');
    body.className='flex items-start gap-2';

    const val=isCode?document.createElement('pre'):document.createElement('div');
    val.className='flex-1 modal-text-block';
    val.textContent=value || '-';
    body.appendChild(val);

    if(canCopy && value){
      const btn=document.createElement('button');
      btn.className='px-2 py-1 rounded-full border text-[11px] whitespace-nowrap self-start';
      btn.textContent='复制';
      btn.onclick=()=>copyToClipboard(value);
      body.appendChild(btn);
    }

    row.appendChild(body);
    rows.appendChild(row);
  }

  const sponsor=v.donatedByUsername||'';
  if(sponsor){
    addRow('赞助人','@'+sponsor,true,false);
  }

  const flag=guessCountryFlag(v);
  const ipLoc=(v.country||'未填写')+(v.ipLocation?' · '+v.ipLocation:'');
  addRow('IP 归属',(flag?flag+' ':'')+ipLoc,true,false);

  addRow('IP 地址', v.ip || '', true,false);
  addRow('端口', String(v.port||''), true,false);

  addRow('系统用户名', v.username || '', true,false);
  addRow('认证方式', v.authType==='key'?'密钥':'密码', false,false);

  if(v.authType==='password'){
    addRow('登录密码', v.password || '', true, true);
  }else{
    addRow('SSH 私钥', v.privateKey || '', true, true);
  }

  const statusText = v.verifyStatus || 'unknown';
  const extra = v.verifyErrorMsg ? ('（'+v.verifyErrorMsg+'）') : '';
  addRow('验证状态', statusText+extra, false,false);

  card.appendChild(rows);

  const footer=document.createElement('div');
  footer.className='mt-4 flex justify-end';
  const closeBtn=document.createElement('button');
  closeBtn.textContent='关闭';
  closeBtn.className='px-3 py-1 rounded-full border';
  closeBtn.onclick=()=>wrap.remove();
  footer.appendChild(closeBtn);
  card.appendChild(footer);

  wrap.appendChild(card);
  document.body.appendChild(wrap);
}

function medalByRank(i){
  const arr=["👑","🏆","🥇","🥈","🥉","💎","🔥","🌟","✨","⚡","🎖️","🛡️","🎗️","🎯","🚀","🧿","🪙","🧭","🗡️","🦄","🐉","🦅","🦁","🐯","🐺","🐻","🐼","🐧","🐬","🐳","🛰️","🪐","🌙","🌈","🌊","🌋","🏔️","🏰","🧱","⚙️","🔧","🔭","🧪","🧠","🪄","🔮","🎩","🎼","🎷","🎻","🥁","🎹"];
  return arr[i%arr.length];
}
</script>
`;
}

/* ==================== 导出 ==================== */
export default app;