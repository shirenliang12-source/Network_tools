'use strict';
/**
 * 认证与分权
 * 角色：
 *   admin  管理员 - 全部权限（用户、凭据、配置、下发、抓包、扫描）
 *   ops    运维   - 设备查看、终端、配置下发、抓包、测速、告警处理、网络扫描
 *   audit  审计   - 只读查看 + 会话回放 + 日志，不能下发/抓包/扫描
 *               （审计角色不给 scan：扫描会主动向网段发包，属主动行为，需单独授权）
 * 令牌：HMAC-SHA256 签名令牌（12 小时有效）
 *       默认存 settings.tokenSecret 以支撑多实例共享；
 *       设置 AUTH_SHARED_SECRET 环境变量时用环境变量值（彻底无状态，多副本一致）。
 */
const crypto = require('crypto');
const store = require('./store');
const db = require('./db');

const ROLES = {
  admin: { name: '管理员', perms: ['*'] },
  ops: {
    name: '运维', perms: ['view', 'terminal', 'deploy', 'capture', 'speed', 'alarm', 'ai', 'scan', 'session.read', 'audit.read']
  },
  audit: { name: '审计', perms: ['view', 'session.read', 'audit.read', 'alarm', 'ai'] }
};

/* 令牌密钥：优先环境变量（多副本共享），其次落 settings（重启不掉线） */
let _secret = null;
async function tokenSecret() {
  if (_secret) return _secret;
  const env = (process.env.AUTH_SHARED_SECRET || '').trim();
  if (env) { _secret = env; return _secret; }
  const s = await db.settingsGet();
  if (!s || !s.tokenSecret) {
    await db.settingsUpdate({ tokenSecret: crypto.randomBytes(32).toString('hex') });
  }
  const after = await db.settingsGet();
  _secret = (after && after.tokenSecret) || crypto.randomBytes(32).toString('hex');
  return _secret;
}
async function rotateSecret() {
  _secret = crypto.randomBytes(32).toString('hex');
  await db.settingsUpdate({ tokenSecret: _secret });
  return _secret;
}

async function sign(payload) {
  const key = await tokenSecret();
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', key).update(body).digest('base64url');
  return `${body}.${sig}`;
}
async function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const key = await tokenSecret();
  const want = crypto.createHmac('sha256', key).update(body).digest('base64url');
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { return null; }
  if (!p.exp || p.exp < store.nowSec()) return null;
  return p;
}

async function findUser(username) {
  const all = await db.usersList();
  return all.find(u => u.username.toLowerCase() === String(username || '').toLowerCase()) || null;
}
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, username: u.username, displayName: u.displayName, role: u.role,
    roleName: (ROLES[u.role] || {}).name || u.role, enabled: u.enabled !== false,
    perms: permsOf(u.role), lastLoginAt: u.lastLoginAt || null, createdAt: u.createdAt
  };
}
function permsOf(role) { return (ROLES[role] || ROLES.audit).perms; }

async function createUser({ username, password, displayName, role = 'ops' }) {
  if (!username || !password) throw new Error('用户名与密码必填');
  if (await findUser(username)) throw new Error('用户名已存在');
  if (!ROLES[role]) throw new Error('角色不合法');
  if (String(password).length < 6) throw new Error('密码至少 6 位');
  return db.usersCreate({
    username: String(username).trim(), displayName: displayName || username,
    role, enabled: true, password: store.hash(password),
    createdAt: new Date().toISOString(), lastLoginAt: null, pwdChangedAt: new Date().toISOString()
  });
}
async function setPassword(id, password) {
  const u = await db.usersFind(id);
  if (!u) throw new Error('用户不存在');
  if (String(password).length < 6) throw new Error('密码至少 6 位');
  await db.usersUpdate(id, {
    password: store.hash(password),
    pwdChangedAt: new Date().toISOString()
  });
  await rotateSecret();   // 改密后使所有旧令牌失效
}

async function login(username, password, ip) {
  const u = await findUser(username);
  if (!u) { await store.audit({ user: username, ip, action: 'auth.login', result: 'fail', detail: '用户不存在' }); return null; }
  if (u.enabled === false) { await store.audit({ user: username, ip, action: 'auth.login', result: 'fail', detail: '账号已停用' }); return null; }
  if (!store.verify(password, u.password)) { await store.audit({ user: username, ip, action: 'auth.login', result: 'fail', detail: '密码错误' }); return null; }
  await db.usersUpdate(u.id, { lastLoginAt: new Date().toISOString() });
  const token = await sign({ uid: u.id, username: u.username, role: u.role, exp: store.nowSec() + 12 * 3600 });
  await store.audit({ user: u.username, role: u.role, ip, action: 'auth.login', result: 'ok' });
  return { token, user: publicUser(u) };
}

async function ensureSeed() {
  const users = await db.usersList();
  if (users.length) return;
  await createUser({ username: 'admin', password: 'admin@123', displayName: '系统管理员', role: 'admin' });
  await createUser({ username: 'ops', password: 'ops@123', displayName: '值班运维', role: 'ops' });
  await createUser({ username: 'audit', password: 'audit@123', displayName: '审计员', role: 'audit' });
}

/* ------------------------------- Express 中间件 ----------------------------- */
async function attach(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : (req.query.token || '');
  const p = await verifyToken(token);
  if (!p) return null;
  const u = (await db.usersList()).find(x => x.id === p.uid);
  if (!u || u.enabled === false) return null;
  req.user = u;
  return u;
}
function authRequired(req, res, next) {
  attach(req).then(u => {
    if (!u) return res.status(401).json({ ok: false, error: '未登录或登录已过期' });
    next();
  }).catch(() => res.status(401).json({ ok: false, error: '认证服务异常' }));
}
function requirePerm(perm) {
  return (req, res, next) => {
    Promise.resolve(req.user || attach(req)).then(u => {
      if (!u) return res.status(401).json({ ok: false, error: '未登录或登录已过期' });
      const perms = permsOf(u.role);
      if (!(perms.includes('*') || perms.includes(perm))) {
        store.audit({ user: u.username, role: u.role, ip: clientIp(req), action: 'perm.denied', target: req.path, result: 'deny', detail: `缺少权限 ${perm}` });
        return res.status(403).json({ ok: false, error: '权限不足' });
      }
      req.user = u;
      next();
    }).catch(() => res.status(401).json({ ok: false, error: '认证服务异常' }));
  };
}
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || '-';
}
/** 便捷：记录一次审计（含请求上下文） */
function logAction(req, action, target, detail, result = 'ok') {
  return store.audit({
    user: req.user?.username || 'anonymous',
    role: req.user?.role || '-',
    ip: clientIp(req), action, target, detail,
    result
  });
}

module.exports = {
  ROLES, permsOf, publicUser, findUser, createUser, setPassword, login,
  ensureSeed, authRequired, requirePerm, attach, verifyToken, clientIp, logAction,
  tokenSecret, rotateSecret
};
