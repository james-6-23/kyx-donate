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
  } catch (_) { }
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

/* ---- Favicon 路由（防止 404 错误）---- */
app.get('/favicon.ico', c => {
  // 返回一个简单的橙色心形 SVG favicon
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🧡</text></svg>`;
  return c.body(svg, 200, {
    'Content-Type': 'image/svg+xml',
    'Cache-Control': 'public, max-age=86400' // 缓存1天
  });
});

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
<div class="max-w-6xl mx-auto px-6 py-8 md:py-12">

  <header class="mb-10 animate-in">
    <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6">
      <div class="flex-1 space-y-5">
        <h1 class="grad-title text-4xl md:text-5xl font-bold leading-tight">
          风萧萧公益机场 · VPS 投喂榜
        </h1>

        <div class="panel border p-6 space-y-4">
          <p class="text-sm leading-relaxed">
            <span class="muted">这是一个完全非盈利的公益项目，目前没有运营团队，由我独自维护。</span><br>
            同时也非常感谢以下几位佬的日常协助：
            <a href="https://linux.do/u/shklrt" target="_blank"
               class="font-semibold transition-colors hover:opacity-80">@shklrt</a>、
            <a href="https://linux.do/u/sar60677" target="_blank"
               class="font-semibold transition-colors hover:opacity-80">@sar60677</a>、
            <a href="https://linux.do/u/carrydelahaye" target="_blank"
               class="font-semibold transition-colors hover:opacity-80">@Carry&nbsp;Delahaye</a>
            <a href="https://linux.do/u/kkkyyx" target="_blank"
               class="font-semibold transition-colors hover:opacity-80">@kkkyyx</a>。
          </p>

          <div class="alert-warning text-sm leading-relaxed rounded-xl px-4 py-3">
            <span class="font-semibold">💝 榜单按投喂 VPS 数量排序，</span>
            但无论名次高低，您的每一次支持，对我和这个项目来说都弥足珍贵，衷心感谢！
          </div>

          <p class="text-sm leading-relaxed flex items-start gap-2">
            <span class="text-lg mt-0.5">🤝</span>
            <span>感谢大家的投喂，这个机场的发展离不开各位热佬的大力支持！这不是我一个人的功劳，而是大家的共同成果！共荣！🚀</span>
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-3">
          <button onclick="gotoDonatePage()" class="btn-primary">
            <span class="text-lg">🧡</span> 我要投喂 VPS
          </button>
          <button id="theme-toggle" onclick="toggleTheme()">浅色模式</button>
        </div>
      </div>
    </div>
  </header>

  <section class="mb-8">
    <div class="flex items-center gap-3 mb-6">
      <span class="text-3xl">🏆</span>
      <div>
        <h2 class="text-3xl font-bold leading-tight">捐赠榜单</h2>
        <p id="leaderboard-count" class="text-sm muted mt-1"></p>
      </div>
    </div>
    
    <div id="leaderboard" class="space-y-5">
      <div class="flex items-center justify-center py-12">
        <div class="flex flex-col items-center gap-3">
          <div class="loading-spinner"></div>
          <div class="muted text-sm">正在加载榜单...</div>
        </div>
      </div>
    </div>
  </section>

  <footer class="mt-16 pt-8 pb-8 text-center">
    <div class="panel border px-4 md:px-6 py-4 inline-block max-w-full">
      <p class="flex items-center justify-center gap-2 text-sm muted flex-wrap">
        <span class="text-lg flex-shrink-0">ℹ️</span>
        <span class="break-words">说明：本项目仅作公益用途，请勿滥用资源（长时间占满带宽、刷流量、倒卖账号等）。</span>
      </p>
    </div>
  </footer>

</div>

<div id="toast-root"></div>
<script>
updateThemeBtn();

let allLeaderboardData = [];

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

function renderLeaderboard(){
  const box = document.getElementById('leaderboard');
  const countEl = document.getElementById('leaderboard-count');
  
  countEl.textContent = allLeaderboardData.length ? ('共 '+allLeaderboardData.length+' 位投喂者') : '';
  
  if(!allLeaderboardData.length){
    box.innerHTML='<div class="muted text-sm py-8 text-center">暂时还没有投喂记录</div>';
    return;
  }
  
  box.innerHTML='';
  allLeaderboardData.forEach((it,idx)=>{
    const wrap=document.createElement('div');
    wrap.className='card border transition-all animate-slide-in';
    wrap.style.animationDelay = (idx * 0.05) + 's';
    const cardId = 'card-'+idx;
    const isExpanded = localStorage.getItem(cardId) !== 'collapsed';

    const head=document.createElement('div');
    head.className='flex items-center justify-between p-5 pb-4 border-b gap-4 bg-gradient-to-r cursor-pointer';
    
    let gradientClass = '';
    if(idx === 0) gradientClass = 'from-amber-500/5 to-transparent';
    else if(idx === 1) gradientClass = 'from-slate-400/5 to-transparent';
    else if(idx === 2) gradientClass = 'from-orange-600/5 to-transparent';
    head.className += ' ' + gradientClass;
    
    const badge=getBadge(it.count);
    head.innerHTML='<div class="flex items-center gap-4 flex-1 min-w-0">'+
      '<div class="flex-shrink-0 w-12 h-12 flex items-center justify-center text-3xl">'+medalByRank(idx)+'</div>'+
      '<div class="flex flex-col gap-1.5 min-w-0">'+
        '<a class="font-bold text-xl hover:opacity-80 truncate transition-colors" target="_blank" href="https://linux.do/u/'+encodeURIComponent(it.username)+'" onclick="event.stopPropagation()">@'+it.username+'</a>'+
        '<div class="flex items-center gap-2 flex-wrap">'+
          renderBadge(badge)+
          '<span class="text-xs muted">共投喂 '+it.count+' 台服务器</span>'+
        '</div>'+
      '</div>'+
      '</div>'+
      '<div class="flex items-center gap-3">'+
        '<div class="flex-shrink-0 flex items-center justify-center w-16 h-16 panel border rounded-2xl">'+
          '<div class="text-center">'+
            '<div class="font-bold text-2xl leading-none mb-1">'+it.count+'</div>'+
            '<div class="text-xs muted leading-none">VPS</div>'+
          '</div>'+
        '</div>'+
        '<button class="toggle-expand flex-shrink-0 w-10 h-10 flex items-center justify-center rounded-lg panel border hover:bg-sky-500/10 transition-all" data-card="'+cardId+'" onclick="event.stopPropagation()" title="'+(isExpanded ? '收起列表' : '展开列表')+'">'+
          '<span class="text-lg transition-transform duration-300 '+(isExpanded ? 'rotate-0' : '-rotate-90')+'">'+'▼'+'</span>'+
        '</button>'+
      '</div>';
    
    head.onclick = () => {
      const listEl = wrap.querySelector('.server-list');
      const toggleBtn = wrap.querySelector('.toggle-expand');
      const toggleIcon = toggleBtn.querySelector('span');
      const isCurrentlyExpanded = !listEl.classList.contains('expandable');

      if(isCurrentlyExpanded){
        // 收起
        listEl.classList.add('expandable');
        toggleIcon.classList.remove('rotate-0');
        toggleIcon.classList.add('-rotate-90');
        toggleBtn.setAttribute('title', '展开列表');
        localStorage.setItem(cardId, 'collapsed');
      } else {
        // 展开
        listEl.classList.remove('expandable');
        toggleIcon.classList.remove('-rotate-90');
        toggleIcon.classList.add('rotate-0');
        toggleBtn.setAttribute('title', '收起列表');
        localStorage.removeItem(cardId);
      }
    };
    
    wrap.appendChild(head);

    const list=document.createElement('div');
    list.className='server-list px-5 pb-5 pt-4 space-y-3';
    if(!isExpanded){
      list.classList.add('expandable');
    }
    (it.servers||[]).forEach(srv=>{
      const d=document.createElement('div');
      d.className='panel border rounded-xl p-4 transition-all hover:shadow-sm';
      d.innerHTML = '<div class="flex items-start justify-between gap-3 mb-3">'+
        '<div class="flex items-center gap-2.5 flex-1 min-w-0">'+
          '<span class="text-xl flex-shrink-0">🌍</span>'+
          '<div class="flex flex-col gap-1 min-w-0">'+
            '<span class="font-semibold text-sm truncate">'+(srv.country||'未填写')+'</span>'+
            (srv.ipLocation?'<span class="text-xs muted truncate">'+srv.ipLocation+'</span>':'')+
          '</div>'+
        '</div>'+
        '<span class="'+statusCls(srv.status)+' text-xs px-2.5 py-1 rounded-full font-semibold flex-shrink-0">'+statusText(srv.status)+'</span>'+
      '</div>'+
      '<div class="grid grid-cols-2 gap-3 text-sm">'+
        '<div class="flex items-center gap-2 panel border rounded-lg px-3 py-2">'+
          '<span class="opacity-60">📊</span>'+
          '<span class="truncate font-medium">'+(srv.traffic||'未填写')+'</span>'+
        '</div>'+
        '<div class="flex items-center gap-2 panel border rounded-lg px-3 py-2">'+
          '<span class="opacity-60">📅</span>'+
          '<span class="truncate font-medium">'+(srv.expiryDate||'未填写')+'</span>'+
        '</div>'+
      '</div>'+
      (srv.specs?'<div class="text-sm mt-3 panel border rounded-lg px-3 py-2.5 flex items-start gap-2"><span class="opacity-60 text-base">⚙️</span><span class="flex-1">'+srv.specs+'</span></div>':'')+
      (srv.note?'<div class="text-sm mt-3 bg-amber-500/5 border border-amber-500/20 rounded-lg px-3 py-2.5 flex items-start gap-2"><span class="opacity-60 text-base">💬</span><span class="flex-1">'+srv.note+'</span></div>':'');
      list.appendChild(d);
    });
    wrap.appendChild(list);
    box.appendChild(wrap);
  });
}

async function loadLeaderboard(){
  const box = document.getElementById('leaderboard'), countEl=document.getElementById('leaderboard-count');
  
  // 显示骨架屏
  box.innerHTML='<div class="space-y-5">'+
    '<div class="skeleton-card"><div class="skeleton-header">'+
    '<div class="skeleton skeleton-avatar"></div>'+
    '<div class="flex-1"><div class="skeleton skeleton-title"></div><div class="skeleton skeleton-text short mt-2"></div></div>'+
    '</div>'+
    '<div class="skeleton skeleton-text"></div>'+
    '<div class="skeleton skeleton-text medium"></div>'+
    '</div>'.repeat(3)+
    '</div>';

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
      box.innerHTML='<div class="text-red-400 text-sm">加载失败: '+(j.message||'未知错误')+'<br><button onclick="loadLeaderboard()" class="btn-secondary mt-4">重试</button></div>';
      return;
    }

    allLeaderboardData = j.data||[];
    
    if(!allLeaderboardData.length){
      box.innerHTML='<div class="muted text-sm py-8 text-center">暂时还没有投喂记录，成为第一个投喂者吧～</div>';
      countEl.textContent = '';
      return;
    }
    
    renderLeaderboard();
  }catch(err){
    console.error('Leaderboard load error:', err);
    box.innerHTML='<div class="text-red-400 text-sm text-center py-8">'+err.message+'<br><button onclick="loadLeaderboard()" class="btn-secondary mt-4">重试</button></div>';
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
<div class="max-w-7xl mx-auto px-6 py-8 md:py-12">
  <header class="mb-10 animate-fade-in">
    <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
      <div class="space-y-3">
        <h1 class="grad-title text-4xl md:text-5xl font-bold leading-tight">风萧萧公益机场 · VPS 投喂中心</h1>
        <p class="text-sm muted flex items-center gap-2">
          <span class="text-lg">📍</span>
          <span>提交新 VPS / 查看我的投喂记录</span>
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-3">
        <div id="user-info" class="text-sm panel px-5 py-2.5 border"></div>
        <button onclick="logout()" class="btn-secondary">
          退出登录
        </button>
        <button id="theme-toggle" onclick="toggleTheme()">浅色模式</button>
      </div>
    </div>
  </header>

  <main class="grid lg:grid-cols-2 gap-8 items-start">
    <section class="panel border p-8">
      <div class="flex items-center gap-3 mb-5">
        <span class="text-3xl">🧡</span>
        <h2 class="text-2xl font-bold">提交新的 VPS 投喂</h2>
      </div>
      <div class="alert-warning text-sm mb-6 leading-relaxed rounded-xl px-4 py-3">
        ⚠️ 请确保服务器是你有控制权的机器，并允许用于公益节点。禁止长时间占满带宽、刷流量、倒卖账号等行为。
      </div>

      <form id="donate-form" class="space-y-5">
        <div class="grid md:grid-cols-2 gap-5">
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <span>🌐</span> 服务器 IP <span class="text-red-400">*</span>
            </label>
            <input name="ip" required placeholder="示例：203.0.113.8 或 [2001:db8::1]"
                   class="w-full" />
            <div class="help mt-1.5 flex items-center gap-1"><span class="opacity-60">💡</span>支持 IPv4 / IPv6</div>
          </div>
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <span>🔌</span> 端口 <span class="text-red-400">*</span>
            </label>
            <input name="port" required type="number" min="1" max="65535" placeholder="示例：22 / 443 / 8080"
                   class="w-full" />
          </div>
        </div>

        <div class="grid md:grid-cols-2 gap-5">
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <span>👤</span> 系统用户名 <span class="text-red-400">*</span>
            </label>
            <input name="username" required placeholder="示例：root / ubuntu"
                   class="w-full" />
          </div>
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <span>🔐</span> 认证方式
            </label>
            <select name="authType" class="w-full">
              <option value="password">🔑 密码</option>
              <option value="key">🗝️ SSH 私钥</option>
            </select>
          </div>
        </div>

        <div id="password-field">
          <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
            <span>🔑</span> 密码（密码登录必填）
          </label>
          <input name="password" type="password" placeholder="示例：MyStrongP@ssw0rd"
                 class="w-full" />
        </div>

        <div id="key-field" class="hidden">
          <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
            <span>🗝️</span> SSH 私钥（密钥登录必填）
          </label>
          <textarea name="privateKey" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    class="w-full font-mono"></textarea>
        </div>

        <div class="grid md:grid-cols-2 gap-5">
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <span>🌍</span> 国家 / 区域 <span class="text-red-400">*</span>
            </label>
            <select name="country" required class="w-full">
              <option value="">请选择国家/区域</option>
              <optgroup label="🌏 亚洲">
                <option value="🇨🇳 中国大陆">🇨🇳 中国大陆</option>
                <option value="🇭🇰 中国香港">🇭🇰 中国香港</option>
                <option value="🇲🇴 中国澳门">🇲🇴 中国澳门</option>
                <option value="🇹🇼 中国台湾">🇹🇼 中国台湾</option>
                <option value="🇯🇵 日本">🇯🇵 日本</option>
                <option value="🇰🇷 韩国">🇰🇷 韩国</option>
                <option value="🇸🇬 新加坡">🇸🇬 新加坡</option>
                <option value="🇲🇾 马来西亚">🇲🇾 马来西亚</option>
                <option value="🇹🇭 泰国">🇹🇭 泰国</option>
                <option value="🇻🇳 越南">🇻🇳 越南</option>
                <option value="🇵🇭 菲律宾">🇵🇭 菲律宾</option>
                <option value="🇮🇩 印度尼西亚">🇮🇩 印度尼西亚</option>
                <option value="🇮🇳 印度">🇮🇳 印度</option>
              </optgroup>
              <optgroup label="🌍 欧洲">
                <option value="🇬🇧 英国">🇬🇧 英国</option>
                <option value="🇩🇪 德国">🇩🇪 德国</option>
                <option value="🇫🇷 法国">🇫🇷 法国</option>
                <option value="🇳🇱 荷兰">🇳🇱 荷兰</option>
                <option value="🇮🇹 意大利">🇮🇹 意大利</option>
                <option value="🇪🇸 西班牙">🇪🇸 西班牙</option>
                <option value="🇷🇺 俄罗斯">🇷🇺 俄罗斯</option>
                <option value="🇵🇱 波兰">🇵🇱 波兰</option>
                <option value="🇨🇭 瑞士">🇨🇭 瑞士</option>
                <option value="🇸🇪 瑞典">🇸🇪 瑞典</option>
              </optgroup>
              <optgroup label="🌎 北美">
                <option value="🇺🇸 美国">🇺🇸 美国</option>
                <option value="🇨🇦 加拿大">🇨🇦 加拿大</option>
                <option value="🇲🇽 墨西哥">🇲🇽 墨西哥</option>
              </optgroup>
              <optgroup label="🌏 大洋洲">
                <option value="🇦🇺 澳大利亚">🇦🇺 澳大利亚</option>
                <option value="🇳🇿 新西兰">🇳🇿 新西兰</option>
              </optgroup>
              <optgroup label="🌍 非洲">
                <option value="🇿🇦 南非">🇿🇦 南非</option>
                <option value="🇪🇬 埃及">🇪🇬 埃及</option>
              </optgroup>
              <optgroup label="🌎 南美">
                <option value="🇧🇷 巴西">🇧🇷 巴西</option>
                <option value="🇦🇷 阿根廷">🇦🇷 阿根廷</option>
                <option value="🇨🇱 智利">🇨🇱 智利</option>
              </optgroup>
              <optgroup label="🌏 中东">
                <option value="🇦🇪 阿联酋">🇦🇪 阿联酋</option>
                <option value="🇸🇦 沙特阿拉伯">🇸🇦 沙特阿拉伯</option>
                <option value="🇹🇷 土耳其">🇹🇷 土耳其</option>
              </optgroup>
            </select>
          </div>
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <span>📊</span> 流量 / 带宽 <span class="text-red-400">*</span>
            </label>
            <input name="traffic" required placeholder="示例：400G/月 · 上下行 1Gbps"
                   class="w-full" />
          </div>
        </div>

        <div class="grid md:grid-cols-2 gap-5">
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <span>📅</span> 到期日期 <span class="text-red-400">*</span>
            </label>
            <input name="expiryDate" required type="date" min="${minDate}" value="${ny}"
                   class="w-full" />
            <div class="help mt-1.5 flex items-center gap-1"><span class="opacity-60">💡</span>默认已填为 +1 年（可改）</div>
          </div>
          <div>
            <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
              <span>⚙️</span> 配置描述 <span class="text-red-400">*</span>
            </label>
            <input name="specs" required placeholder="示例：1C1G · 10Gbps · 1T 流量"
                   class="w-full" />
          </div>
        </div>

        <div>
          <label class="block mb-2.5 text-sm font-medium flex items-center gap-1.5">
            <span>💬</span> 投喂备注 <span class="help ml-1">（可选，将前台展示）</span>
          </label>
          <textarea name="note" rows="3" placeholder="示例：电信到香港方向无法走大陆优选链路，共享带宽，不保证大陆连通性"
                    class="w-full"></textarea>
        </div>

        <div id="donate-message" class="text-sm min-h-[1.5rem] font-medium"></div>

        <button id="donate-submit-btn" type="submit" class="w-full btn-primary mt-4">
          <span class="text-lg">🚀</span> 提交投喂
        </button>
      </form>
    </section>

    <section class="panel border p-8">
      <div class="flex items-center justify-between mb-5">
        <div class="flex items-center gap-3">
          <span class="text-3xl">📦</span>
          <h2 class="text-2xl font-bold">我的投喂记录</h2>
        </div>
        <div class="flex gap-2">
          <button onclick="exportDonations()" class="btn-secondary" title="导出为JSON">
            📥 导出
          </button>
          <button onclick="loadDonations()" class="btn-secondary">
            🔄 刷新
          </button>
        </div>
      </div>
      <div id="donations-list" class="space-y-4 text-sm">
        <div class="flex items-center justify-center py-12">
          <div class="flex flex-col items-center gap-3">
            <div class="loading-spinner"></div>
            <div class="muted text-sm">正在加载...</div>
          </div>
        </div>
      </div>
    </section>
  </main>

  <footer class="mt-16 pt-8 pb-8 text-center">
    <div class="panel border px-4 md:px-6 py-4 inline-block max-w-full">
      <p class="flex items-center justify-center gap-2 text-sm muted flex-wrap">
        <span class="text-lg flex-shrink-0">ℹ️</span>
        <span class="break-words">友情提示：投喂即视为同意将该 VPS 用于公益机场中转节点。请勿提交有敏感业务的生产机器。</span>
      </p>
    </div>
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

async function exportDonations(){
  try{
    const r=await fetch('/api/user/donations',{credentials:'same-origin',cache:'no-store'});
    const j=await r.json();
    if(!r.ok||!j.success){
      toast('导出失败','error');
      return;
    }
    const data=j.data||[];
    if(!data.length){
      toast('暂无投喂记录可导出','warn');
      return;
    }
    
    const exportData = {
      exportTime: new Date().toISOString(),
      totalCount: data.length,
      donations: data.map(v => ({
        ip: v.ip,
        port: v.port,
        username: v.username,
        country: v.country,
        ipLocation: v.ipLocation,
        traffic: v.traffic,
        expiryDate: v.expiryDate,
        specs: v.specs,
        status: v.status,
        donatedAt: new Date(v.donatedAt).toISOString(),
        note: v.note || ''
      }))
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'my-vps-donations-'+Date.now()+'.json';
    a.click();
    URL.revokeObjectURL(url);
    toast('导出成功','success');
  }catch(err){
    console.error('Export error:', err);
    toast('导出异常','error');
  }
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
  
  btn.disabled=true;
  btn.classList.add('loading');
  const originalHTML=btn.innerHTML;
  btn.innerHTML='<span>提交中...</span>';
  
  try{
    const r=await fetch('/api/donate',{
      method:'POST',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const j=await r.json();
    
    btn.classList.remove('loading');
    
    if(!r.ok||!j.success){
      btn.classList.add('error');
      msg.textContent=j.message||'提交失败';
      msg.className='text-sm mt-1 min-h-[1.5rem] text-red-400';
      toast('投喂失败：'+(j.message||'请检查填写项'), 'error');
      setTimeout(()=>btn.classList.remove('error'), 400);
    } else{
      btn.classList.add('success');
      btn.innerHTML='<span>✓ 提交成功</span>';
      msg.textContent=j.message||'投喂成功';
      msg.className='text-sm mt-1 min-h-[1.5rem] text-green-500';
      toast(j.message||'投喂成功','success');
      
      setTimeout(()=>{
        btn.classList.remove('success');
        btn.innerHTML=originalHTML;
        form.reset();
        loadDonations();
      }, 2000);
    }
  }catch(e){
    console.error('Donate error:', e);
    btn.classList.remove('loading');
    btn.classList.add('error');
    msg.textContent='提交异常';
    msg.className='text-sm mt-1 min-h-[1.5rem] text-red-400';
    toast('提交异常','error');
    setTimeout(()=>btn.classList.remove('error'), 400);
  } finally{
    setTimeout(()=>{
      btn.disabled=false;
      if(!btn.classList.contains('success')){
        btn.innerHTML=originalHTML;
      }
    }, 500);
  }
}

async function loadDonations(){
  const box=document.getElementById('donations-list');
  
  // 显示骨架屏
  box.innerHTML='<div class="space-y-4">'+
    '<div class="skeleton-card"><div class="skeleton-header">'+
    '<div class="skeleton skeleton-avatar"></div>'+
    '<div class="flex-1"><div class="skeleton skeleton-title"></div></div>'+
    '</div>'+
    '<div class="skeleton skeleton-text"></div>'+
    '<div class="skeleton skeleton-text medium"></div>'+
    '<div class="skeleton skeleton-text short"></div>'+
    '</div>'+
    '<div class="skeleton-card"><div class="skeleton-header">'+
    '<div class="skeleton skeleton-avatar"></div>'+
    '<div class="flex-1"><div class="skeleton skeleton-title"></div></div>'+
    '</div>'+
    '<div class="skeleton skeleton-text"></div>'+
    '<div class="skeleton skeleton-text medium"></div>'+
    '</div>'+
    '</div>';
  
  try{
    const r=await fetch('/api/user/donations',{credentials:'same-origin',cache:'no-store'});
    const j=await r.json();
    if(!r.ok||!j.success){
      box.innerHTML='<div class="text-red-400 text-sm">加载失败</div>';
      return;
    }
    const data=j.data||[];
    if(!data.length){
      box.innerHTML='<div class="muted text-sm py-8 text-center">还没有投喂记录，先在左侧提交一台吧～</div>';
      return;
    }
    box.innerHTML='';
    data.forEach(v=>{
      const div=document.createElement('div');
      div.className='card border px-5 py-4 transition-all';
      const dt=v.donatedAt?new Date(v.donatedAt):null, t=dt?dt.toLocaleString():'';
      const uname=v.donatedByUsername||'';
      const p='https://linux.do/u/'+encodeURIComponent(uname);
      div.innerHTML='<div class="flex items-center justify-between gap-2 mb-3 pb-3 border-b">'+
        '<div class="text-sm font-medium flex items-center gap-2"><span>🖥️</span><span class="break-words">'+v.ip+':'+v.port+'</span></div>'+
        '<div class="'+scls(v.status)+' text-xs px-2.5 py-1 rounded-full font-semibold">'+stxt(v.status)+'</div></div>'+
        '<div class="text-sm mb-3">投喂者：<a href="'+p+'" target="_blank" class="underline hover:text-cyan-300 transition-colors">@'+uname+'</a></div>'+
        '<div class="grid grid-cols-2 gap-3 text-sm mt-3">'+
          '<div class="flex items-center gap-2"><span class="opacity-60">🌍</span><span class="truncate">'+(v.country||'未填写')+(v.ipLocation?' · '+v.ipLocation:'')+'</span></div>'+
          '<div class="flex items-center gap-2"><span class="opacity-60">📊</span><span class="truncate">'+(v.traffic||'未填写')+'</span></div>'+
          '<div class="flex items-center gap-2"><span class="opacity-60">📅</span><span class="truncate">'+(v.expiryDate||'未填写')+'</span></div>'+
        '</div>'+
        '<div class="text-sm muted mt-3 panel border rounded-lg px-3 py-2 break-words flex items-start gap-2"><span class="opacity-60">⚙️</span><span>'+(v.specs||'未填写')+'</span></div>'+
        (v.note?'<div class="text-sm mt-3 bg-amber-500/5 border border-amber-500/20 rounded-lg px-3 py-2 break-words flex items-start gap-2"><span class="opacity-60">💬</span><span>'+v.note+'</span></div>':'')+
        (t?'<div class="text-xs muted mt-3 flex items-center gap-2"><span class="opacity-60">🕐</span><span>'+t+'</span></div>':'');
      box.appendChild(div);
    });
  }catch(err){
    console.error('Load donations error:', err);
    box.innerHTML='<div class="text-red-400 text-sm">加载异常</div>';
  }
}

ensureLogin();
bindAuthType();
document.getElementById('donate-form').addEventListener('submit', submitDonate);
loadDonations();

// 实时IP格式验证
document.querySelector('input[name="ip"]').addEventListener('blur', function(){
  const ip = this.value.trim();
  if(!ip) return;
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every(p => +p >= 0 && +p <= 255);
  const ipv6 = /^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|::)/i.test(ip.replace(/^\[|\]$/g, ''));
  
  if(ipv4 || ipv6){
    this.classList.remove('error');
    this.classList.add('success');
    setTimeout(()=>this.classList.remove('success'), 2000);
  } else {
    this.classList.add('error');
    toast('IP 格式不正确','error');
  }
});

// 端口范围验证
document.querySelector('input[name="port"]').addEventListener('blur', function(){
  const port = parseInt(this.value);
  if(!port) return;
  
  if(port < 1 || port > 65535){
    this.classList.add('error');
    toast('端口范围应在 1-65535 之间','error');
  } else {
    this.classList.remove('error');
    this.classList.add('success');
    setTimeout(()=>this.classList.remove('success'), 2000);
  }
});
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
  wrap.className='panel max-w-md mx-auto border p-8 animate-in';
  wrap.innerHTML='<div class="text-center mb-6">'+
    '<div class="inline-flex items-center justify-center w-16 h-16 rounded-full mb-4" style="background:#007AFF">'+
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
      '<button type="submit" class="w-full btn-primary">'+
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
        '<div class="inline-flex items-center justify-center w-12 h-12 rounded-xl" style="background:#007AFF">'+
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
      '<div class="panel px-5 py-2.5 border">'+
        '<span class="text-sm">👤</span>'+
        '<span class="text-sm font-medium">'+name+'</span>'+
      '</div>'+
      '<button id="theme-toggle" class="btn-secondary">浅色模式</button>'+
      '<button id="btn-admin-logout" class="btn-danger">'+
        '退出登录'+
      '</button>'+
    '</div>'+
  '</div>';
  root.appendChild(header);

  const themeBtn = document.getElementById('theme-toggle');
  if(themeBtn){
    updateThemeBtn();
    themeBtn.addEventListener('click', toggleTheme);
  }
  document.getElementById('btn-admin-logout').addEventListener('click', async()=>{
    try{await fetch('/api/admin/logout',{credentials:'same-origin'})}catch{}
    location.reload();
  });

  const stats=document.createElement('section');
  stats.id='admin-stats';
  root.appendChild(stats);
  
  const distMap=document.createElement('section');
  distMap.className='mt-6';
  distMap.innerHTML='<div class="panel border p-6">'+
    '<div class="flex items-center justify-between mb-4">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-2xl">🗺️</span>'+
        '<h2 class="text-lg font-bold">全球服务器分布</h2>'+
      '</div>'+
      '<button id="btn-toggle-map" class="btn-secondary text-xs">展开</button>'+
    '</div>'+
      '<div id="map-body" class="hidden">'+
        '<div class="mb-4">'+
          '<div id="server-map-chart" style="width:100%;height:450px;min-height:450px;"></div>'+
        '</div>'+
        '<div class="border-t pt-4">'+
          '<h3 class="text-sm font-semibold mb-3 flex items-center gap-2">'+
            '<span>📊</span>'+
            '<span>国家/地区统计</span>'+
          '</h3>'+
          '<div id="server-distribution-admin" class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3"></div>'+
        '</div>'+
      '</div>'+
  '</div>';
  root.appendChild(distMap);

  document.getElementById('btn-toggle-map').addEventListener('click',()=>{
    const b=document.getElementById('map-body');
    const btn=document.getElementById('btn-toggle-map');
    if(b.classList.contains('hidden')){
      b.classList.remove('hidden');
      btn.textContent='收起';
      
      // 延迟执行以确保DOM已渲染
      setTimeout(()=>{
        renderServerMapChart();
        renderServerDistributionAdmin();
      }, 100);
    } else {
      b.classList.add('hidden');
      btn.textContent='展开';
    }
  });

  const cfg=document.createElement('section');
  cfg.id='admin-config';
  cfg.className='mt-6 space-y-4';
  cfg.innerHTML=
  '<div class="panel border p-6">'+
    '<div class="flex items-center justify-between mb-4">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-xl">🔗</span>'+
        '<h2 class="text-lg font-bold">OAuth 配置</h2>'+
      '</div>'+
      '<button id="btn-toggle-oauth" class="btn-secondary text-xs">展开</button>'+
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
        '<button id="btn-save-oauth" class="btn-primary">'+
          '<span>💾</span> 保存 OAuth 配置'+
        '</button>'+
      '</div>'+
    '</div>'+
  '</div>'+
  '<div class="panel border p-6">'+
    '<div class="flex items-center justify-between mb-4">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-xl">🔑</span>'+
        '<h2 class="text-lg font-bold">管理员密码</h2>'+
      '</div>'+
      '<button id="btn-toggle-password" class="btn-secondary text-xs">展开</button>'+
    '</div>'+
    '<div id="password-body" class="hidden">'+
      '<div class="alert-warning text-sm mb-4 rounded-xl px-3 py-2">'+
        '⚠️ 仅用于 <code>/admin</code> 后台登录，至少 6 位，建议与 Linux.do 账号密码不同'+
      '</div>'+
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
      '<button id="btn-save-admin-pass" class="btn-primary">'+
        '<span>🔒</span> 保存密码'+
      '</button>'+
      '<p class="text-xs muted mt-3">💡 修改成功后立即生效，下次登录需要使用新密码</p>'+
    '</div>'+
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
  
  document.getElementById('btn-toggle-password').addEventListener('click',()=>{
    const b=document.getElementById('password-body');
    const btn=document.getElementById('btn-toggle-password');
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
  listWrap.innerHTML='<div class="panel border p-6 mb-6">'+
    '<div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">'+
      '<div class="flex items-center gap-3">'+
        '<span class="text-2xl">📋</span>'+
        '<h2 class="text-2xl font-bold">VPS 列表</h2>'+
      '</div>'+
      '<button id="btn-verify-all" class="btn-primary">'+
        '<span>🔄</span> 一键验证全部'+
      '</button>'+
    '</div>'+
    '<div class="flex flex-col md:flex-row gap-3">'+
      '<div class="flex flex-wrap items-center gap-2">'+
        '<span class="text-sm font-medium">筛选：</span>'+
        '<button data-status="all" class="btn-secondary text-xs">全部</button>'+
        '<button data-status="active" class="btn-secondary text-xs">✅ 运行中</button>'+
        '<button data-status="failed" class="btn-secondary text-xs">❌ 失败</button>'+
      '</div>'+
      '<div class="flex-1 flex gap-2">'+
        '<input id="filter-input" placeholder="🔍 搜索 IP / 用户名 / 备注..." class="flex-1"/>'+
        '<button id="filter-btn" class="btn-secondary">搜索</button>'+
        '<button id="filter-clear-btn" class="btn-secondary">清除</button>'+
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
    function card(label,value,key,icon){
      const percent = d.totalVPS > 0 ? Math.round((value / d.totalVPS) * 100) : 0;
      return '<button data-gok="'+key+'" class="stat-card stat-'+key+' border px-4 py-3 text-left">'+
        '<div class="flex items-center justify-between mb-2">'+
          '<div class="stat-label text-xs muted">'+icon+' '+label+'</div>'+
          '<div class="text-xs muted">'+percent+'%</div>'+
        '</div>'+
        '<div class="stat-value mb-2">'+value+'</div>'+
        '<div class="w-full h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">'+
          '<div class="h-full rounded-full transition-all duration-500" style="width:'+percent+'%;background:currentColor"></div>'+
        '</div>'+
        '</button>';
    }
    wrap.innerHTML='<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">'+
      card('总投喂数',d.totalVPS||0,'all','📊')+
      card('运行中',d.activeVPS||0,'active','✅')+
      card('失败',d.failedVPS||0,'failed','❌')+
      card('今日新增',d.todayNewVPS||0,'today','🆕')+'</div>';
    
    // 添加数字计数动画
    setTimeout(()=>{
      wrap.querySelectorAll('.stat-value').forEach(el => {
        const target = parseInt(el.textContent);
        if(!isNaN(target)){
          el.classList.add('count-up');
          animateNumber(el, target);
        }
      });
    }, 100);
    
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

let mapChartInstance = null;
let mapLoaded = false;

function renderServerMapChart(){
  const chartDom = document.getElementById('server-map-chart');
  if(!chartDom) return;
  
  if(!window.echarts){
    chartDom.innerHTML = '<div class="text-center py-8 text-red-400">ECharts 库未加载</div>';
    return;
  }

  // 如果已经初始化过，只更新数据
  if(mapChartInstance && mapLoaded){
    updateMapData();
    return;
  }

  mapChartInstance = echarts.init(chartDom);

  if(!allVpsList.length) {
    mapChartInstance.showLoading({
      text: '暂无数据',
      color: '#007AFF',
      textColor: '#1d1d1f',
      maskColor: 'rgba(255, 255, 255, 0.2)'
    });
    return;
  }
  
  mapChartInstance.showLoading({
    text: '加载地图中...',
    color: '#007AFF',
    textColor: '#1d1d1f',
    maskColor: 'rgba(255, 255, 255, 0.2)'
  });

  // 统计各国家/地区的服务器数量
  const countryMap = new Map();
  allVpsList.forEach(vps => {
    const country = vps.country || '未知';
    const count = countryMap.get(country) || 0;
    countryMap.set(country, count + 1);
  });

  // 国家名称映射函数 - 将数据库中的名称映射到地图标准名称
  const mapCountryName = (name) => {
    // 提取国家名称（去掉emoji和多余空格）
    const cleanName = name.replace(/[\u{1F1E6}-\u{1F1FF}]/gu, '').trim();

    // 中文到地图名称的映射表
    const nameMap = {
      '中国大陆': '中国',
      '中国香港': '香港',
      '中国澳门': '澳门',
      '中国台湾': '台湾',
      '美国': '美国',
      '日本': '日本',
      '韩国': '韩国',
      '新加坡': '新加坡',
      '英国': '英国',
      '德国': '德国',
      '法国': '法国',
      '加拿大': '加拿大',
      '澳大利亚': '澳大利亚',
      '俄罗斯': '俄罗斯',
      '印度': '印度',
      '巴西': '巴西',
      '荷兰': '荷兰',
      '意大利': '意大利',
      '西班牙': '西班牙',
      // 可根据需要继续添加更多映射
    };

    return nameMap[cleanName] || cleanName;
  };

  // 转换为 ECharts 需要的数据格式
  const mapData = Array.from(countryMap.entries()).map(([name, value]) => {
    const mappedName = mapCountryName(name);
    return { name: mappedName, value: value };
  });

  const isDark = document.body.getAttribute('data-theme') === 'dark';

  const option = {
    tooltip: {
      trigger: 'item',
      formatter: function(params) {
        if(params.value) {
          return params.name + '<br/>服务器数量：' + params.value + ' 台';
        }
        return params.name + '<br/>暂无服务器';
      },
      backgroundColor: isDark ? 'rgba(28, 28, 30, 0.95)' : 'rgba(255, 255, 255, 0.95)',
      borderColor: isDark ? 'rgba(56, 56, 58, 0.8)' : 'rgba(210, 210, 215, 0.8)',
      textStyle: {
        color: isDark ? '#f5f5f7' : '#1d1d1f'
      }
    },
    visualMap: {
      min: 0,
      max: Math.max(...Array.from(countryMap.values()), 1),
      text: ['多', '少'],
      realtime: false,
      calculable: true,
      inRange: {
        color: isDark
          ? ['#1a1a2e', '#0f3460', '#16213e', '#0A84FF', '#0066CC']
          : ['#f0e6ff', '#ddd6fe', '#c4b5fd', '#a78bfa', '#8b5cf6']
      },
      textStyle: {
        color: isDark ? '#f5f5f7' : '#1d1d1f'
      },
      bottom: 20,
      left: 'center',
      orient: 'horizontal'
    },
    series: [
      {
        name: '服务器数量',
        type: 'map',
        map: 'world',
        roam: true,
        emphasis: {
          label: {
            show: true,
            color: isDark ? '#f5f5f7' : '#1d1d1f'
          },
          itemStyle: {
            areaColor: isDark ? '#0A84FF' : '#8b5cf6',
            borderColor: '#fff',
            borderWidth: 2
          }
        },
        itemStyle: {
          borderColor: isDark ? '#38383a' : '#d2d2d7',
          borderWidth: 0.5,
          areaColor: isDark ? '#1c1c1e' : '#f5f5f7'
        },
        label: {
          show: false,
          color: isDark ? '#f5f5f7' : '#1d1d1f'
        },
        data: mapData
      }
    ]
  };

  // 多个备用地图数据源（按优先级排序）
  const mapSources = [
    // jsDelivr CDN - 通常最快且稳定
    'https://cdn.jsdelivr.net/npm/echarts@5.4.3/map/json/world.json',
    // Fastly CDN - jsDelivr 的备用节点
    'https://fastly.jsdelivr.net/npm/echarts@5.4.3/map/json/world.json',
    // unpkg CDN - 备用源
    'https://unpkg.com/echarts@5.4.3/map/json/world.json',
    // GitHub 原始文件 - 最后的备用方案
    'https://raw.githubusercontent.com/apache/echarts/5.4.3/map/json/world.json'
  ];

  async function loadWorldMap(sources, index = 0){
    if(index >= sources.length){
      throw new Error('所有地图数据源均加载失败，请检查网络连接');
    }

    const currentSource = sources[index];
    console.log('尝试加载地图数据源 '+(index + 1)+'/'+sources.length+': '+currentSource);

    try{
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10秒超时

      const response = await fetch(currentSource, {
        signal: controller.signal,
        cache: 'default' // 允许浏览器缓存
      });

      clearTimeout(timeoutId);

      if(!response.ok) {
        throw new Error('HTTP '+response.status+': '+response.statusText);
      }

      const data = await response.json();
      console.log('✓ 地图数据源 '+(index + 1)+' 加载成功');
      return data;

    } catch(err){
      const errorMsg = err.name === 'AbortError'
        ? '请求超时'
        : (err.message || '未知错误');

      console.warn('✗ 地图数据源 '+(index + 1)+' 加载失败: '+errorMsg);

      // 如果还有备用源，继续尝试
      if(index + 1 < sources.length){
        console.log('正在尝试下一个备用数据源...');
        return loadWorldMap(sources, index + 1);
      }

      // 所有源都失败了
      throw new Error('所有地图数据源均加载失败。最后一次错误: '+errorMsg);
    }
  }
  
  loadWorldMap(mapSources)
    .then(worldJson => {
      if(!worldJson || !worldJson.features){
        throw new Error('地图数据格式无效');
      }

      echarts.registerMap('world', worldJson);
      mapChartInstance.setOption(option);
      mapChartInstance.hideLoading();
      mapLoaded = true;

      console.log('✓ 世界地图渲染成功');
      toast('地图加载成功','success');

      // 监听主题切换（只注册一次）
      if(!window.mapThemeHandler){
        window.mapThemeHandler = () => {
          if(!mapChartInstance || !mapLoaded) return;
          const newIsDark = document.body.getAttribute('data-theme') === 'dark';
          option.visualMap.textStyle.color = newIsDark ? '#f5f5f7' : '#1d1d1f';
          option.visualMap.inRange.color = newIsDark
            ? ['#1a1a2e', '#0f3460', '#16213e', '#0A84FF', '#0066CC']
            : ['#f0e6ff', '#ddd6fe', '#c4b5fd', '#a78bfa', '#8b5cf6'];
          option.tooltip.backgroundColor = newIsDark ? 'rgba(28, 28, 30, 0.95)' : 'rgba(255, 255, 255, 0.95)';
          option.tooltip.borderColor = newIsDark ? 'rgba(56, 56, 58, 0.8)' : 'rgba(210, 210, 215, 0.8)';
          option.tooltip.textStyle.color = newIsDark ? '#f5f5f7' : '#1d1d1f';
          option.series[0].emphasis.label.color = newIsDark ? '#f5f5f7' : '#1d1d1f';
          option.series[0].emphasis.itemStyle.areaColor = newIsDark ? '#0A84FF' : '#8b5cf6';
          option.series[0].itemStyle.borderColor = newIsDark ? '#38383a' : '#d2d2d7';
          option.series[0].itemStyle.areaColor = newIsDark ? '#1c1c1e' : '#f5f5f7';
          option.series[0].label.color = newIsDark ? '#f5f5f7' : '#1d1d1f';
          mapChartInstance.setOption(option);
        };
        window.addEventListener('themeChanged', window.mapThemeHandler);
      }

      // 响应式调整（只注册一次）
      if(!window.mapResizeHandler){
        window.mapResizeHandler = () => {
          if(mapChartInstance) mapChartInstance.resize();
        };
        window.addEventListener('resize', window.mapResizeHandler);
      }
    })
    .catch(err => {
      console.error('✗ 世界地图加载失败:', err);
      if(mapChartInstance) mapChartInstance.hideLoading();

      const errorDetail = err.message || '未知错误';

      chartDom.innerHTML = '<div class="text-center py-12 px-6">'+
        '<div class="text-6xl mb-4">🗺️</div>'+
        '<div class="text-red-400 mb-3 text-xl font-semibold">地图加载失败</div>'+
        '<div class="text-sm muted mb-2">无法从任何CDN源加载地图数据</div>'+
        '<div class="text-xs muted mb-6 max-w-md mx-auto">'+
          '<details class="mt-2">'+
            '<summary class="cursor-pointer hover:text-sky-400">查看详细错误信息</summary>'+
            '<div class="mt-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-left">'+
              '<code class="text-xs">'+errorDetail+'</code>'+
            '</div>'+
          '</details>'+
        '</div>'+
        '<div class="flex gap-3 justify-center">'+
          '<button onclick="location.reload()" class="btn-primary">刷新页面重试</button>'+
          '<button onclick="document.getElementById(&quot;btn-toggle-map&quot;).click()" class="btn-secondary">收起地图</button>'+
        '</div>'+
        '<div class="mt-6 text-xs muted">'+
          '<p>💡 提示：地图功能为可选功能，不影响其他管理功能的使用</p>'+
        '</div>'+
      '</div>';

      toast('地图加载失败，但不影响其他功能','warn');
    });
}

function updateMapData(){
  if(!mapChartInstance || !mapLoaded) return;
  
  // 重新统计数据
  const countryMap = new Map();
  allVpsList.forEach(vps => {
    const country = vps.country || '未知';
    const count = countryMap.get(country) || 0;
    countryMap.set(country, count + 1);
  });
  
  const mapData = Array.from(countryMap.entries()).map(([name, value]) => {
    const cleanName = name.replace(/[\u{1F1E6}-\u{1F1FF}]/gu, '').trim();
    return { name: cleanName, value: value };
  });
  
  mapChartInstance.setOption({
    series: [{
      data: mapData
    }]
  });
  
  toast('地图数据已更新','success');
}

function renderServerDistributionAdmin(){
  const distBox = document.getElementById('server-distribution-admin');
  if(!allVpsList.length) {
    distBox.innerHTML = '<div class="col-span-full text-sm muted text-center py-4">暂无数据</div>';
    return;
  }
  
  // 统计各国家/地区的服务器数量
  const countryMap = new Map();
  allVpsList.forEach(vps => {
    const country = vps.country || '未知';
    const count = countryMap.get(country) || 0;
    countryMap.set(country, count + 1);
  });
  
  // 按数量排序
  const sorted = Array.from(countryMap.entries())
    .sort((a, b) => b[1] - a[1]);
  
  if(!sorted.length){
    distBox.innerHTML = '<div class="col-span-full text-sm muted text-center py-4">暂无数据</div>';
    return;
  }
  
  distBox.innerHTML = '';
  sorted.forEach(([country, count]) => {
    const item = document.createElement('div');
    item.className = 'panel border rounded-lg px-3 py-3 text-center transition-all hover:shadow-sm animate-slide-in';
    item.innerHTML = '<div class="text-2xl mb-1.5">'+country.split(' ')[0]+'</div>'+
      '<div class="text-xs muted mb-2">'+country.split(' ').slice(1).join(' ')+'</div>'+
      '<div class="font-bold text-xl mb-0.5 count-up">'+count+'</div>'+
      '<div class="text-xs muted">台服务器</div>';
    distBox.appendChild(item);
  });
  
  // 数字计数动画
  setTimeout(()=>{
    distBox.querySelectorAll('.count-up').forEach(el => {
      const target = parseInt(el.textContent);
      if(!isNaN(target)){
        animateNumber(el, target);
      }
    });
  }, 100);
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
        '<button class="btn-secondary text-xs" data-act="login" data-id="'+v.id+'">🔍 查看</button>'+
        '<button class="btn-secondary text-xs" data-act="verify" data-id="'+v.id+'">✅ 验证</button>'+
        '<button class="btn-secondary text-xs" data-act="edit" data-id="'+v.id+'">✏️ 编辑</button>'+
        '<button class="btn-danger text-xs" data-act="del" data-id="'+v.id+'">🗑️ 删除</button>'+
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
          if(!confirm('确定要删除这台 VPS 吗？此操作不可恢复。')) return;
          
          btn.classList.add('loading');
          btn.disabled = true;
          
          try{
            const r=await fetch('/api/admin/vps/'+id,{method:'DELETE',credentials:'same-origin'});
            const j=await r.json();
            if(r.ok){
              card.style.animation = 'slideOut 0.3s ease-out forwards';
              setTimeout(()=>{
                toast(j.message||'已删除', 'success');
              }, 300);
            } else {
              toast(j.message||'删除失败', 'error');
            }
          }catch{
            toast('删除失败','error');
          } finally {
            btn.classList.remove('loading');
            btn.disabled = false;
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
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🧡</text></svg>" />
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<script>
tailwind.config = {
  theme: {
    extend: {
      colors: {
        apple: {
          blue: { light: '#007AFF', dark: '#0A84FF' },
          gray: { 50: '#fbfbfd', 100: '#f5f5f7', 200: '#d2d2d7', 300: '#86868b', 900: '#1d1d1f' },
          darkgray: { 50: '#38383a', 100: '#2c2c2e', 200: '#1c1c1e', 900: '#000000' },
          success: { light: '#34C759', dark: '#32D74B' },
          error: { light: '#FF3B30', dark: '#FF453A' },
          warning: { light: '#FF9500', dark: '#FF9F0A' },
        }
      },
      borderRadius: {
        'apple-sm': '8px',
        'apple': '10px',
        'apple-lg': '12px',
        'apple-xl': '16px',
      },
      boxShadow: {
        'apple-sm': '0 2px 8px rgba(0,0,0,0.04)',
        'apple': '0 4px 16px rgba(0,0,0,0.08)',
        'apple-lg': '0 8px 32px rgba(0,0,0,0.12)',
        'apple-dark': '0 2px 8px rgba(0,0,0,0.3)',
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
html{
  scroll-behavior: smooth;
}
html,body{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-size: 15px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  overflow-x: hidden;
}
body{
  background: linear-gradient(135deg,
    #f0e6ff 0%,    /* 淡紫色 */
    #e9d5ff 20%,   /* 浅紫色 */
    #ddd6fe 40%,   /* 紫罗兰 */
    #c4b5fd 60%,   /* 中紫色 */
    #e9d5ff 80%,   /* 浅紫色 */
    #f0e6ff 100%   /* 淡紫色 */
  );
  background-size: 400% 400%;
  animation: gradientShift 15s ease infinite;
  color: #1d1d1f;
  min-height: 100vh;
  transition: color 0.3s ease;
  position: relative;
}
@keyframes gradientShift {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
body::before{
  content: '';
  position: fixed;
  inset: 0;
  background: linear-gradient(135deg,
    rgba(139, 92, 246, 0.05) 0%,
    rgba(168, 85, 247, 0.04) 25%,
    rgba(147, 51, 234, 0.03) 50%,
    rgba(126, 34, 206, 0.04) 75%,
    rgba(139, 92, 246, 0.05) 100%
  );
  pointer-events: none;
  z-index: 0;
}
body > *{
  position: relative;
  z-index: 1;
}

body[data-theme="dark"]{
  color-scheme: dark;
  background: linear-gradient(135deg,
    #1a0a2e 0%,    /* 深紫蓝 */
    #16213e 25%,   /* 深蓝灰 */
    #0f3460 50%,   /* 深蓝 */
    #1a1a2e 75%,   /* 深灰蓝 */
    #0a0e27 100%   /* 极深蓝 */
  );
  background-size: 400% 400%;
  animation: gradientShift 15s ease infinite;
  color: #f5f5f7;
}
body[data-theme="dark"]::before{
  background: linear-gradient(135deg,
    rgba(138, 43, 226, 0.1) 0%,
    rgba(72, 52, 212, 0.08) 25%,
    rgba(59, 130, 246, 0.06) 50%,
    rgba(16, 185, 129, 0.05) 75%,
    rgba(14, 165, 233, 0.08) 100%
  );
}

/* ========== 动画 ========== */
@keyframes slideUpAndFade {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}
@keyframes slideDown {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes scaleUp {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}
@keyframes spin {
  to { transform: rotate(360deg); }
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
@keyframes slideInFromBottom {
  from {
    opacity: 0;
    transform: translateY(30px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
@keyframes slideOut {
  from {
    opacity: 1;
    transform: translateX(0) scale(1);
  }
  to {
    opacity: 0;
    transform: translateX(-50px) scale(0.9);
  }
}

.animate-in {
  animation: slideUpAndFade 0.3s ease-out;
}
.animate-fade-in {
  animation: fadeIn 0.3s ease-out;
}
.animate-slide-in {
  animation: slideInFromBottom 0.4s ease-out forwards;
}

/* ========== 加载指示器 ========== */
.loading-spinner {
  width: 20px;
  height: 20px;
  border: 2px solid transparent;
  border-top-color: #007AFF;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
body[data-theme="dark"] .loading-spinner {
  border-top-color: #0A84FF;
}

/* ========== 骨架屏 ========== */
.skeleton {
  background: linear-gradient(
    90deg,
    rgba(220, 220, 225, 0.6) 0%,
    rgba(235, 235, 240, 0.8) 50%,
    rgba(220, 220, 225, 0.6) 100%
  );
  background-size: 200% 100%;
  animation: skeletonLoading 1.5s ease-in-out infinite;
  border-radius: 8px;
}
@keyframes skeletonLoading {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
body[data-theme="dark"] .skeleton {
  background: linear-gradient(
    90deg,
    rgba(44, 44, 46, 0.6) 0%,
    rgba(56, 56, 58, 0.8) 50%,
    rgba(44, 44, 46, 0.6) 100%
  );
  background-size: 200% 100%;
  animation: skeletonLoading 1.5s ease-in-out infinite;
}

/* 骨架屏卡片 */
.skeleton-card {
  padding: 20px;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.6);
}
body[data-theme="dark"] .skeleton-card {
  background: rgba(28, 28, 30, 0.8);
  border-color: rgba(56, 56, 58, 0.6);
}

.skeleton-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}
.skeleton-avatar {
  width: 48px;
  height: 48px;
  border-radius: 50%;
}
.skeleton-title {
  height: 20px;
  width: 40%;
  border-radius: 4px;
}
.skeleton-text {
  height: 16px;
  width: 100%;
  border-radius: 4px;
  margin-bottom: 8px;
}
.skeleton-text.short {
  width: 60%;
}
.skeleton-text.medium {
  width: 80%;
}

/* ========== 卡片与面板 ========== */
.panel,.card{
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid rgba(255, 255, 255, 0.6);
  border-radius: 12px;
  box-shadow:
    0 2px 16px rgba(0, 0, 0, 0.06),
    0 0 0 1px rgba(255, 255, 255, 0.8),
    inset 0 1px 0 rgba(255, 255, 255, 0.9);
  transition: all 0.2s ease;
  word-break: break-word;
  overflow: hidden; /* 防止内容溢出 */
}
.card:hover {
  box-shadow: 
    0 8px 32px rgba(0, 0, 0, 0.12),
    0 0 0 1px rgba(255, 255, 255, 0.9),
    inset 0 1px 0 rgba(255, 255, 255, 1);
  transform: translateY(-2px);
}

body[data-theme="dark"] .panel,
body[data-theme="dark"] .card{
  background: rgba(28, 28, 30, 0.8);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border-color: rgba(56, 56, 58, 0.6);
  box-shadow: 
    0 2px 16px rgba(0, 0, 0, 0.4),
    0 0 0 1px rgba(56, 56, 58, 0.5),
    inset 0 1px 0 rgba(255, 255, 255, 0.03);
}
body[data-theme="dark"] .card:hover{
  box-shadow: 
    0 8px 32px rgba(0, 0, 0, 0.6),
    0 0 0 1px rgba(56, 56, 58, 0.8),
    inset 0 1px 0 rgba(255, 255, 255, 0.05);
}

/* ========== 弹窗内文本块 ========== */
.modal-text-block{
  word-break: break-all;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
  max-height: 260px;
  overflow-y: auto;
  padding: 8px 12px;
  border-radius: 8px;
  background: rgba(245, 245, 247, 0.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(210, 210, 215, 0.8);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 13px;
  line-height: 1.5;
}
body[data-theme="dark"] .modal-text-block{
  background: rgba(44, 44, 46, 0.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border-color: rgba(56, 56, 58, 0.8);
  color: #f5f5f7;
}

/* ========== 文字样式 ========== */
.muted{
  color: #6b6b6f;
}
body[data-theme="dark"] .muted{
  color: #a8a8ad;
}

.grad-title{
  color: #1d1d1f;
  font-weight: 700;
  text-shadow: 0 1px 2px rgba(255, 255, 255, 0.5);
}
body[data-theme="dark"] .grad-title{
  color: #f5f5f7;
  text-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

/* ========== Toast 通知 ========== */
#toast-root{
  position: fixed;
  top: 20px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 9999;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  pointer-events: none;
}
.toast{
  padding: 12px 20px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  color: #1d1d1f;
  border: 1px solid rgba(255, 255, 255, 0.8);
  box-shadow: 0 8px 32px rgba(0,0,0,0.15), 0 0 0 1px rgba(255,255,255,0.8);
  transform: translateY(-20px);
  opacity: 0;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  pointer-events: auto;
  min-width: 280px;
  max-width: 420px;
  font-size: 14px;
  font-weight: 500;
}
.toast.show{ 
  transform: translateY(0); 
  opacity: 1;
  animation: slideDown 0.25s ease-out;
}
.toast.success{ 
  border-left: 3px solid #34C759;
}
.toast.error{ 
  border-left: 3px solid #FF3B30;
}
.toast.warn{ 
  border-left: 3px solid #FF9500;
}
body[data-theme="dark"] .toast{
  background: rgba(44, 44, 46, 0.9);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  color: #f5f5f7;
  border-color: rgba(56, 56, 58, 0.8);
  box-shadow: 0 8px 32px rgba(0,0,0,0.7), 0 0 0 1px rgba(56,56,58,0.6);
}
body[data-theme="dark"] .toast.success{ border-left-color: #32D74B; }
body[data-theme="dark"] .toast.error{ border-left-color: #FF453A; }
body[data-theme="dark"] .toast.warn{ border-left-color: #FF9F0A; }

/* ========== 辅助文字 ========== */
.help{ 
  font-size: 12px;
  color: #86868b;
}
body[data-theme="dark"] .help{
  color: #98989d;
}

/* ========== 警告框 ========== */
.alert-warning{
  background: linear-gradient(135deg, rgba(255, 149, 0, 0.08), rgba(255, 204, 0, 0.05));
  border: 1px solid rgba(255, 149, 0, 0.25);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}
body[data-theme="dark"] .alert-warning{
  background: linear-gradient(135deg, rgba(255, 159, 10, 0.12), rgba(255, 214, 10, 0.08));
  border-color: rgba(255, 159, 10, 0.3);
}

/* ========== 状态徽章 ========== */
.badge-ok{
  color: #34C759;
  font-weight: 600;
  position: relative;
}
.badge-ok::before{
  content: '';
  position: absolute;
  left: -12px;
  top: 50%;
  transform: translateY(-50%);
  width: 6px;
  height: 6px;
  background: #34C759;
  border-radius: 50%;
  animation: pulse-green 2s ease-in-out infinite;
}
@keyframes pulse-green {
  0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(52,199,89,0.7); }
  50% { opacity: 0.8; box-shadow: 0 0 0 4px rgba(52,199,89,0); }
}
.badge-fail{
  color: #FF3B30;
  font-weight: 600;
}
.badge-idle{
  color: #86868b;
  font-weight: 600;
}
body[data-theme="dark"] .badge-ok{ color: #32D74B; }
body[data-theme="dark"] .badge-ok::before{ background: #32D74B; }
body[data-theme="dark"] .badge-fail{ color: #FF453A; }
body[data-theme="dark"] .badge-idle{ color: #98989d; }

/* ========== 主题切换按钮 ========== */
#theme-toggle{
  border-radius: 10px;
  padding: 8px 16px;
  border: 1px solid rgba(210, 210, 215, 0.8);
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #1d1d1f;
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s ease;
  cursor: pointer;
}
#theme-toggle:hover{
  background: rgba(245, 245, 247, 0.95);
  transform: scale(0.98);
}
#theme-toggle:active{
  transform: scale(0.96);
  opacity: 0.8;
}
body[data-theme="dark"] #theme-toggle{
  background: rgba(44, 44, 46, 0.85);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #f5f5f7;
  border-color: rgba(56, 56, 58, 0.8);
}
body[data-theme="dark"] #theme-toggle:hover{
  background: rgba(56, 56, 58, 0.9);
}

/* ========== 统计卡片 ========== */
.stat-card{
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border: 1px solid rgba(255, 255, 255, 0.6);
  border-radius: 12px;
  transition: all 0.2s ease;
  cursor: pointer;
  box-shadow: 0 2px 12px rgba(0,0,0,0.06), 0 0 0 1px rgba(255,255,255,0.8);
}
.stat-card:hover{
  transform: translateY(-2px);
  box-shadow: 0 4px 20px rgba(0,0,0,0.1), 0 0 0 1px rgba(255,255,255,0.9);
}
.stat-card:active{
  transform: translateY(-1px) scale(0.98);
}
.stat-card .stat-label{
  font-size: 12px;
  font-weight: 500;
  color: #86868b;
}
.stat-card .stat-value{
  font-size: 28px;
  font-weight: 700;
  color: #007AFF;
}
.stat-card.stat-all .stat-value{ color: #007AFF; }
.stat-card.stat-active .stat-value{ color: #34C759; }
.stat-card.stat-failed .stat-value{ color: #FF3B30; }
.stat-card.stat-inactive .stat-value{ color: #FF9500; }
.stat-card.stat-pending .stat-value{ color: #FF9500; }
.stat-card.stat-today .stat-value{ color: #007AFF; }

body[data-theme="dark"] .stat-card{
  background: rgba(28, 28, 30, 0.8);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
  border-color: rgba(56, 56, 58, 0.6);
  box-shadow: 0 2px 12px rgba(0,0,0,0.4), 0 0 0 1px rgba(56,56,58,0.5);
}
body[data-theme="dark"] .stat-card:hover{
  box-shadow: 0 4px 20px rgba(0,0,0,0.5), 0 0 0 1px rgba(56,56,58,0.8);
}
body[data-theme="dark"] .stat-card .stat-label{
  color: #98989d;
}
body[data-theme="dark"] .stat-card .stat-value{
  color: #0A84FF;
}
body[data-theme="dark"] .stat-card.stat-all .stat-value{ color: #0A84FF; }
body[data-theme="dark"] .stat-card.stat-active .stat-value{ color: #32D74B; }
body[data-theme="dark"] .stat-card.stat-failed .stat-value{ color: #FF453A; }
body[data-theme="dark"] .stat-card.stat-inactive .stat-value{ color: #FF9F0A; }
body[data-theme="dark"] .stat-card.stat-pending .stat-value{ color: #FF9F0A; }
body[data-theme="dark"] .stat-card.stat-today .stat-value{ color: #0A84FF; }

/* ========== 文字大小 ========== */
.text-xs{ font-size: 13px; line-height: 1.4; }
.text-sm{ font-size: 14px; line-height: 1.45; }

/* ========== 表单元素 ========== */
input, textarea, select{
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #1d1d1f;
  border: 1px solid rgba(210, 210, 215, 0.8);
  border-radius: 10px;
  padding: 10px 14px;
  font-size: 15px;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
  position: relative;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
}
select{
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 14 14'%3E%3Cpath fill='%231d1d1f' stroke='%231d1d1f' stroke-width='0.5' d='M7 10L2 5h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  background-size: 12px;
  padding-right: 40px;
  cursor: pointer;
}
optgroup{
  font-weight: 600;
  color: #6b6b6f;
  font-size: 14px;
  padding: 10px 14px;
  background: #f5f5f7;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
}
option{
  padding: 10px 14px;
  color: #1d1d1f;
  background: #ffffff;
  font-size: 14.5px;
  font-weight: 400;
  line-height: 1.6;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
  letter-spacing: 0.01em;
}
option:hover,
option:focus{
  background: #f5f5f7;
  color: #000000;
}
input:hover, textarea:hover, select:hover{
  border-color: #86868b;
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}
input:focus, textarea:focus, select:focus{
  border-color: #8b5cf6;
  box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.12), 0 2px 8px rgba(139, 92, 246, 0.15);
  outline: none;
  transform: translateY(-2px);
}
input::placeholder,
textarea::placeholder{
  color: #86868b;
  transition: opacity 0.2s ease;
}
input:focus::placeholder,
textarea:focus::placeholder{
  opacity: 0.5;
}
input:disabled, textarea:disabled, select:disabled{
  opacity: 0.5;
  cursor: not-allowed;
  background: #f5f5f7;
}

/* 输入框错误状态 */
input.error, textarea.error, select.error{
  border-color: #FF3B30;
  animation: shake 0.3s ease;
}
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-8px); }
  75% { transform: translateX(8px); }
}

/* 输入框成功状态 */
input.success, textarea.success, select.success{
  border-color: #34C759;
}

body[data-theme="dark"] input,
body[data-theme="dark"] textarea,
body[data-theme="dark"] select{
  background: rgba(44, 44, 46, 0.95);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #f5f5f7;
  border-color: rgba(56, 56, 58, 0.8);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
}
body[data-theme="dark"] select{
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 14 14'%3E%3Cpath fill='%23f5f5f7' stroke='%23f5f5f7' stroke-width='0.5' d='M7 10L2 5h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  background-size: 12px;
}
body[data-theme="dark"] optgroup{
  color: #d1d1d6;
  background: #1c1c1e;
  font-size: 14px;
  font-weight: 600;
  padding: 10px 14px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
  border: none;
}
body[data-theme="dark"] option{
  color: #f5f5f7;
  background: #2c2c2e;
  font-size: 14.5px;
  font-weight: 400;
  padding: 10px 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "kern" 1;
  letter-spacing: 0.01em;
}
body[data-theme="dark"] option:hover,
body[data-theme="dark"] option:focus{
  background: #3a3a3c;
  color: #ffffff;
}
body[data-theme="dark"] input:hover,
body[data-theme="dark"] textarea:hover,
body[data-theme="dark"] select:hover{
  border-color: #98989d;
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}
body[data-theme="dark"] input:focus,
body[data-theme="dark"] textarea:focus,
body[data-theme="dark"] select:focus{
  border-color: #8b5cf6;
  box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.18), 0 2px 8px rgba(139, 92, 246, 0.2);
  transform: translateY(-2px);
}
body[data-theme="dark"] input.error,
body[data-theme="dark"] textarea.error,
body[data-theme="dark"] select.error{
  border-color: #FF453A;
}
body[data-theme="dark"] input.success,
body[data-theme="dark"] textarea.success,
body[data-theme="dark"] select.success{
  border-color: #32D74B;
}
body[data-theme="dark"] input::placeholder,
body[data-theme="dark"] textarea::placeholder{
  color: #98989d;
}
body[data-theme="dark"] input:disabled,
body[data-theme="dark"] textarea:disabled,
body[data-theme="dark"] select:disabled{
  background: #1c1c1e;
}

/* ========== 按钮 ========== */
button{
  transition: all 0.15s ease;
  cursor: pointer;
  font-weight: 500;
  border-radius: 10px;
  -webkit-tap-highlight-color: transparent;
}
button:hover{
  opacity: 0.85;
  transform: scale(0.98);
}
button:active{
  opacity: 0.7;
  transform: scale(0.96);
}
button:disabled{
  opacity: 0.4;
  cursor: not-allowed;
  transform: none !important;
}

/* 主按钮（渐变蓝色背景）*/
.btn-primary{
  background: #007AFF;
  color: #ffffff;
  border: none;
  padding: 12px 24px;
  font-size: 15px;
  box-shadow: 0 2px 8px rgba(0,122,255,0.2);
  position: relative;
  overflow: hidden;
}
.btn-primary:hover{
  background: #0077ED;
  box-shadow: 0 4px 12px rgba(0,122,255,0.3);
}
.btn-primary.loading{
  pointer-events: none;
  opacity: 0.8;
}
.btn-primary.loading::after{
  content: '';
  position: absolute;
  width: 16px;
  height: 16px;
  border: 2px solid #ffffff;
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
  margin-left: 8px;
}
.btn-primary.success{
  background: #34C759;
  animation: successPulse 0.5s ease;
}
.btn-primary.error{
  background: #FF3B30;
  animation: errorShake 0.4s ease;
}
@keyframes successPulse {
  0% { transform: scale(1); }
  50% { transform: scale(1.05); box-shadow: 0 0 20px rgba(52,199,89,0.5); }
  100% { transform: scale(1); }
}
@keyframes errorShake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-10px); }
  75% { transform: translateX(10px); }
}
body[data-theme="dark"] .btn-primary{
  background: #0A84FF;
  box-shadow: 0 2px 8px rgba(10,132,255,0.3);
}
body[data-theme="dark"] .btn-primary:hover{
  background: #0077ED;
}
body[data-theme="dark"] .btn-primary.success{
  background: #32D74B;
}
body[data-theme="dark"] .btn-primary.error{
  background: #FF453A;
}

/* 次要按钮（边框按钮）*/
.btn-secondary{
  background: transparent;
  color: #1d1d1f;
  border: 1px solid #d2d2d7;
  padding: 8px 16px;
  font-size: 13px;
}
.btn-secondary:hover{
  background: #f5f5f7;
  opacity: 1;
}
body[data-theme="dark"] .btn-secondary{
  color: #f5f5f7;
  border-color: #38383a;
}
body[data-theme="dark"] .btn-secondary:hover{
  background: #2c2c2e;
}

/* 危险按钮（删除等）*/
.btn-danger{
  background: transparent;
  color: #FF3B30;
  border: 1px solid #FF3B30;
  padding: 8px 16px;
  font-size: 13px;
}
.btn-danger:hover{
  background: #FF3B30;
  color: #ffffff;
  opacity: 1;
}
body[data-theme="dark"] .btn-danger{
  color: #FF453A;
  border-color: #FF453A;
}
body[data-theme="dark"] .btn-danger:hover{
  background: #FF453A;
}

/* ========== 响应式设计 ========== */
@media (max-width: 640px){
  html,body{
    font-size: 14px;
  }
  .grad-title{
    font-size: 24px;
    line-height: 1.3;
  }
  .panel,.card{
    border-radius: 12px;
  }
  button{
    min-height: 44px;
    min-width: 44px;
  }
  .toast{
    min-width: 260px;
    max-width: calc(100vw - 40px);
  }
  /* 移动端卡片可左右滑动 */
  .swipeable{
    touch-action: pan-y;
    user-select: none;
  }
}

/* ========== 数字计数动画 ========== */
.count-up {
  display: inline-block;
  animation: countUp 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}
@keyframes countUp {
  0% { 
    opacity: 0;
    transform: translateY(20px) scale(0.8);
  }
  100% { 
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

/* ========== 进度条动画 ========== */
.progress-bar {
  transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}

/* ========== ECharts 地图容器 ========== */
#server-map-chart {
  border-radius: 12px;
  overflow: hidden;
  background: rgba(255, 255, 255, 0.5);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}
body[data-theme="dark"] #server-map-chart {
  background: rgba(28, 28, 30, 0.5);
}

/* ========== 卡片展开/收起 ========== */
.expandable {
  max-height: 0 !important;
  overflow: hidden;
  transition: max-height 0.4s cubic-bezier(0.4, 0, 0.2, 1),
              opacity 0.3s ease,
              padding 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  opacity: 0;
  padding-top: 0 !important;
  padding-bottom: 0 !important;
}
.server-list {
  max-height: 5000px; /* 足够大的值以容纳所有内容 */
  opacity: 1;
  transition: max-height 0.4s cubic-bezier(0.4, 0, 0.2, 1),
              opacity 0.3s ease,
              padding 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}

/* 展开/收起按钮样式优化 */
.toggle-expand {
  user-select: none;
  -webkit-user-select: none;
  -moz-user-select: none;
}
.toggle-expand:active {
  transform: scale(0.95);
}
body[data-theme="dark"] .toggle-expand:hover {
  background: rgba(10, 132, 255, 0.1);
  border-color: rgba(10, 132, 255, 0.3);
}

/* ========== 链接样式 ========== */
a{
  color: #007AFF;
  text-decoration: none;
  transition: all 0.2s ease;
}
a:hover{
  opacity: 0.8;
}
body[data-theme="dark"] a{
  color: #0A84FF;
}

/* ========== Code 标签 ========== */
code{
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(0, 0, 0, 0.05);
  color: #1d1d1f;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.9em;
}
body[data-theme="dark"] code{
  background: rgba(255, 255, 255, 0.1);
  color: #f5f5f7;
}

/* ========== 可访问性 ========== */
button:focus-visible,
input:focus-visible,
textarea:focus-visible,
select:focus-visible,
a:focus-visible{
  outline: 2px solid #007AFF;
  outline-offset: 2px;
}
body[data-theme="dark"] button:focus-visible,
body[data-theme="dark"] input:focus-visible,
body[data-theme="dark"] textarea:focus-visible,
body[data-theme="dark"] select:focus-visible,
body[data-theme="dark"] a:focus-visible{
  outline-color: #0A84FF;
}

/* ========== 滚动条样式 ========== */
::-webkit-scrollbar{
  width: 8px;
  height: 8px;
}
::-webkit-scrollbar-track{
  background: transparent;
}
::-webkit-scrollbar-thumb{
  background: #d2d2d7;
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover{
  background: #86868b;
}
body[data-theme="dark"] ::-webkit-scrollbar-thumb{
  background: #38383a;
}
body[data-theme="dark"] ::-webkit-scrollbar-thumb:hover{
  background: #98989d;
}
</style>
<script>
(function(){
  const saved = localStorage.getItem('theme') || 'dark';
  const accent = localStorage.getItem('accent-color') || 'blue';
  document.documentElement.setAttribute('data-theme', saved);
  document.documentElement.setAttribute('data-accent', accent);
  document.addEventListener('DOMContentLoaded', () => {
    document.body.setAttribute('data-theme', saved);
    document.body.setAttribute('data-accent', accent);
  });
})();

function toggleTheme(){
  const cur = document.body.getAttribute('data-theme') || 'dark';
  const nxt = cur === 'dark' ? 'light' : 'dark';
  document.body.setAttribute('data-theme', nxt);
  document.documentElement.setAttribute('data-theme', nxt);
  localStorage.setItem('theme', nxt);
  updateThemeBtn && updateThemeBtn();

  // 触发主题切换事件，通知地图更新
  window.dispatchEvent(new Event('themeChanged'));
}

function updateThemeBtn(){
  const b=document.getElementById('theme-toggle');
  if(b){
    const cur=document.body.getAttribute('data-theme')||'dark';
    b.textContent = cur==='dark' ? '浅色模式' : '深色模式';
  }
}

// 主题色切换（可选功能）
function setAccentColor(color){
  document.body.setAttribute('data-accent', color);
  document.documentElement.setAttribute('data-accent', color);
  localStorage.setItem('accent-color', color);
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
  wrap.style.cssText='position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(8px);animation:fadeIn 0.2s ease-out;';
  const card=document.createElement('div');
  card.className='panel border p-6';
  card.style.width='min(680px,92vw)';
  card.style.animation='scaleUp 0.25s ease-out';
  const h=document.createElement('div');
  h.className='text-lg font-semibold mb-4';
  h.textContent=title;
  card.appendChild(h);
  const form=document.createElement('div');
  form.className='grid grid-cols-2 gap-4 text-sm';
  fields.forEach(f=>{
    const box=document.createElement('div');
    const lab=document.createElement('div');
    lab.className='muted text-xs mb-2 font-medium';
    lab.textContent=f.label;
    const inp=f.type==='textarea'?document.createElement('textarea'):document.createElement('input');
    if(f.type!=='textarea') inp.type='text';
    inp.value=f.value||'';
    inp.placeholder=f.placeholder||'';
    if(f.type==='textarea') inp.rows=3;
    inp.className='w-full';
    box.appendChild(lab);
    box.appendChild(inp);
    box._get=()=>inp.value;
    box._key=f.key;
    form.appendChild(box);
  });
  card.appendChild(form);
  const actions=document.createElement('div');
  actions.className='mt-6 flex items-center justify-end gap-3';
  const btn1=document.createElement('button');
  btn1.textContent='取消';
  btn1.className='btn-secondary';
  btn1.onclick=()=>wrap.remove();
  const btn2=document.createElement('button');
  btn2.textContent='保存';
  btn2.className='btn-primary';
  btn2.onclick=()=>{ const data={}; form.childNodes.forEach((n)=>{ data[n._key]=n._get(); }); try{ onOk(data,()=>wrap.remove()); }catch(e){ console.error(e); } };
  actions.append(btn1,btn2);
  card.appendChild(actions);
  wrap.appendChild(card);
  document.body.appendChild(wrap);
  
  // 添加 ESC 键关闭
  const handleEsc = (e) => {
    if(e.key === 'Escape') {
      wrap.remove();
      document.removeEventListener('keydown', handleEsc);
    }
  };
  document.addEventListener('keydown', handleEsc);
  
  // 点击背景关闭
  wrap.addEventListener('click', (e) => {
    if(e.target === wrap) {
      wrap.remove();
      document.removeEventListener('keydown', handleEsc);
    }
  });
  
  // 聚焦第一个输入框
  setTimeout(() => {
    const firstInput = form.querySelector('input, textarea');
    if(firstInput) firstInput.focus();
  }, 100);
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
  wrap.style.cssText='position:fixed;inset:0;z-index:9998;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;backdrop-filter:blur(8px);animation:fadeIn 0.2s ease-out;';
  const card=document.createElement('div');
  card.className='panel border p-6';
  card.style.width='min(640px,96vw)';
  card.style.maxHeight='90vh';
  card.style.overflowY='auto';
  card.style.animation='scaleUp 0.25s ease-out';

  const title=document.createElement('div');
  title.className='text-lg font-semibold mb-4';
  title.textContent='VPS 登录信息（仅管理员可见）';
  card.appendChild(title);

  const rows=document.createElement('div');
  rows.className='space-y-4 text-sm';

  function addRow(label,value,canCopy=true,isCode=false){
    const row=document.createElement('div');
    row.className='space-y-2';

    const head=document.createElement('div');
    head.className='muted text-xs font-medium';
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
      btn.className='btn-secondary text-xs px-3 py-2 whitespace-nowrap self-start';
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
  footer.className='mt-6 flex justify-end';
  const closeBtn=document.createElement('button');
  closeBtn.textContent='关闭';
  closeBtn.className='btn-secondary';
  closeBtn.onclick=()=>{
    wrap.remove();
    document.removeEventListener('keydown', handleEsc);
  };
  footer.appendChild(closeBtn);
  card.appendChild(footer);

  wrap.appendChild(card);
  document.body.appendChild(wrap);
  
  // 添加 ESC 键关闭
  const handleEsc = (e) => {
    if(e.key === 'Escape') {
      wrap.remove();
      document.removeEventListener('keydown', handleEsc);
    }
  };
  document.addEventListener('keydown', handleEsc);
  
  // 点击背景关闭
  wrap.addEventListener('click', (e) => {
    if(e.target === wrap) {
      wrap.remove();
      document.removeEventListener('keydown', handleEsc);
    }
  });
}

function medalByRank(i){
  const arr=["👑","🏆","🥇","🥈","🥉","💎","🔥","🌟","✨","⚡","🎖️","🛡️","🎗️","🎯","🚀","🧿","🪙","🧭","🗡️","🦄","🐉","🦅","🦁","🐯","🐺","🐻","🐼","🐧","🐬","🐳","🛰️","🪐","🌙","🌈","🌊","🌋","🏔️","🏰","🧱","⚙️","🔧","🔭","🧪","🧠","🪄","🔮","🎩","🎼","🎷","🎻","🥁","🎹"];
  return arr[i%arr.length];
}

// 勋章系统
function getBadge(count){
  if(count >= 10) return {emoji:'👑',name:'超级赞助商',color:'#FFD700',desc:'投喂10台+'};
  if(count >= 5) return {emoji:'💎',name:'白金赞助商',color:'#E5E4E2',desc:'投喂5-9台'};
  if(count >= 3) return {emoji:'🏆',name:'金牌赞助商',color:'#CD7F32',desc:'投喂3-4台'};
  if(count >= 2) return {emoji:'🥇',name:'银牌赞助商',color:'#C0C0C0',desc:'投喂2台'};
  return {emoji:'⭐',name:'新星赞助商',color:'#4A90E2',desc:'投喂1台'};
}

function renderBadge(badge){
  return '<div class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold" '+
    'style="background:'+badge.color+'22;border:1px solid '+badge.color+'44;color:'+badge.color+'">'+
    '<span>'+badge.emoji+'</span>'+
    '<span>'+badge.name+'</span>'+
    '</div>';
}

// 数字计数动画
function animateNumber(element, target, duration = 800){
  const start = 0;
  const startTime = performance.now();
  
  function update(currentTime){
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easeProgress = 1 - Math.pow(1 - progress, 3); // easeOutCubic
    const current = Math.floor(start + (target - start) * easeProgress);
    
    element.textContent = current;
    
    if(progress < 1){
      requestAnimationFrame(update);
    } else {
      element.textContent = target;
    }
  }
  
  requestAnimationFrame(update);
}
</script>
`;
}

/* ==================== 导出 ==================== */
export default app;