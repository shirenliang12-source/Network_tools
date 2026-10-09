'use strict';
/**
 * 通知推送
 * 通道：企业微信群机器人 / 钉钉机器人（含加签）/ 通用 Webhook / 邮件 SMTP
 * 特性：严重级别过滤、同标题冷却（防止刷屏）、推送结果入库审计
 */
const store = require('./store');
const db = require('./db');
const crypto = require('crypto');

const SEV_ORDER = { information: 0, warning: 1, average: 2, high: 3, disaster: 4, critical: 4 };
const SEV_CN = { information: '信息', warning: '警告', average: '一般', high: '严重', disaster: '灾难', critical: '紧急' };
const SEV_COLOR = { information: '#4a90d9', warning: '#e8a33d', average: '#e8a33d', high: '#e5484d', disaster: '#a01b1b', critical: '#a01b1b' };

const _last = new Map();   // 冷却表

function dingSign(secret) {
  const ts = Date.now();
  const str = `${ts}\n${secret}`;
  const sign = crypto.createHmac('sha256', secret).update(str, 'utf8').digest('base64');
  return { ts, sign: encodeURIComponent(sign) };
}

async function postJson(url, body, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: ctrl.signal
    });
    const txt = await res.text();
    return { ok: res.ok, status: res.status, body: txt.slice(0, 500) };
  } catch (e) {
    return { ok: false, status: 0, body: e.message };
  } finally { clearTimeout(t); }
}

function textOf(alarm, prefix = '') {
  return [
    `${prefix}【${SEV_CN[alarm.severity] || alarm.severity}】${alarm.title}`,
    `设备：${alarm.host}`,
    alarm.message ? `详情：${alarm.message}` : '',
    `时间：${new Date((alarm.clock || store.nowSec()) * 1000).toLocaleString('zh-CN')}`
  ].filter(Boolean).join('\n');
}

function markdown(alarm) {
  return [
    `## ${SEV_CN[alarm.severity] || alarm.severity} 告警`,
    `> **${alarm.title}**`,
    `- 设备：\`${alarm.host}\``,
    alarm.message ? `- 详情：${alarm.message}` : '',
    `- 时间：${new Date((alarm.clock || store.nowSec()) * 1000).toLocaleString('zh-CN')}`,
    `- 级别：<font color="${SEV_COLOR[alarm.severity] || '#666'}">${SEV_CN[alarm.severity] || alarm.severity}</font>`
  ].filter(Boolean).join('\n');
}

async function send(alarm, { force = false } = {}) {
  const cfg = ((await db.settingsGet()).notify) || {};
  const min = SEV_ORDER[cfg.minSeverity || 'high'] ?? 3;
  if (!force && (SEV_ORDER[alarm.severity] ?? 0) < min) return { skipped: '低于推送级别' };

  const key = alarm.host + '|' + alarm.title;
  const cool = (cfg.cooldownSec || 300) * 1000;
  const last = _last.get(key) || 0;
  if (!force && Date.now() - last < cool) return { skipped: '冷却中' };
  _last.set(key, Date.now());

  const results = [];

  if (cfg.wecom?.enabled && cfg.wecom.url) {
    results.push({ ch: 'wecom', ...(await postJson(cfg.wecom.url, { msgtype: 'markdown', markdown: { content: markdown(alarm) } })) });
  }
  if (cfg.dingtalk?.enabled && cfg.dingtalk.url) {
    let url = cfg.dingtalk.url;
    if (cfg.dingtalk.secret) {
      const { ts, sign } = dingSign(cfg.dingtalk.secret);
      url += (url.includes('?') ? '&' : '?') + `timestamp=${ts}&sign=${sign}`;
    }
    results.push({
      ch: 'dingtalk', ...(await postJson(url, {
        msgtype: 'markdown', markdown: { title: alarm.title, text: markdown(alarm) }
      }))
    });
  }
  if (cfg.webhook?.enabled && cfg.webhook.url) {
    const payload = { source: 'netops-console', ...alarm, text: textOf(alarm), tsSec: store.nowSec() };
    if (cfg.webhook.secret) {
      payload.sign = crypto.createHmac('sha256', cfg.webhook.secret).update(JSON.stringify(alarm)).digest('hex');
    }
    results.push({ ch: 'webhook', ...(await postJson(cfg.webhook.url, payload)) });
  }
  if (cfg.smtp?.enabled && cfg.smtp.host) {
    try {
      const nodemailer = require('nodemailer');
      const t = nodemailer.createTransport({
        host: cfg.smtp.host, port: cfg.smtp.port || 465, secure: cfg.smtp.secure !== false,
        auth: cfg.smtp.user ? { user: cfg.smtp.user, pass: cfg.smtp.pass } : undefined,
        tls: { rejectUnauthorized: false }
      });
      const info = await t.sendMail({
        from: cfg.smtp.from || cfg.smtp.user,
        to: cfg.smtp.to,
        subject: `[${SEV_CN[alarm.severity] || alarm.severity}] ${alarm.title} - ${alarm.host}`,
        text: textOf(alarm)
      });
      results.push({ ch: 'smtp', ok: true, status: 200, body: info.messageId || 'sent' });
    } catch (e) {
      results.push({ ch: 'smtp', ok: false, status: 0, body: e.message });
    }
  }

  if (results.length) {
    store.audit({
      user: 'system', action: 'notify.push', target: alarm.host,
      result: results.every(r => r.ok) ? 'ok' : 'partial',
      detail: `${alarm.title} → ${results.map(r => `${r.ch}:${r.ok ? 'ok' : r.body}`).join('; ')}`
    });
  }
  return { results };
}

async function test(channel) {
  const now = store.nowSec();
  const alarm = { severity: 'high', host: 'TEST-HOST', title: '测试告警：链路中断', message: '这是一条来自网络运维控制台的测试消息', clock: now };
  const cfg = ((await db.settingsGet()).notify) || {};
  const snapshot = JSON.parse(JSON.stringify(cfg));
  if (channel && cfg[channel]) {
    for (const k of Object.keys(cfg)) if (k !== channel && cfg[k] && typeof cfg[k] === 'object') cfg[k].enabled = false;
    cfg[channel].enabled = true;
  }
  const r = await send(alarm, { force: true });
  Object.assign(cfg, snapshot);
  return r;
}

module.exports = { send, test, SEV_CN, SEV_ORDER };
