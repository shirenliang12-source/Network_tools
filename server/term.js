'use strict';
/**
 * Web 终端引擎
 *  - /ws/terminal  WebSocket 交互式终端（真机走 ssh2 shell；演示设备走内置 CLI 模拟器）
 *  - 全程录制：每一次输入输出按 ndjson 落盘，可回放、可审计
 *  - 危险命令拦截：命中 dangerPatterns 时要求二次确认
 *  - 命令模板 / 批量执行 / 配置下发：POST /api/terminal/deploy
 */
const store = require('./store');
const db = require('./db');
const netutil = require('./netutil');
const auth = require('./auth');
const ds = require('./datasource');

/* ======================= 内置 CLI 模拟器（演示模式） ======================= */
function makeSimulator(host) {
  const dev = ds.DEMO_DEVICES.find(d => d.host === host) || ds.DEMO_DEVICES[0];
  const det = (() => {
    try { return JSON.parse(JSON.stringify(require('./datasource').DEMO_DEVICES)); } catch { return []; }
  })();
  const vendor = dev.vendor;
  const st = {
    host, dev, vendor, mode: vendor === 'Cisco' ? 'user' : 'user', hostname: host,
    ctx: '', line: '', history: [], ifaceCtx: ''
  };
  const prompt = () => {
    if (st.mode === 'user') return `${st.hostname}>`;
    if (st.mode === 'priv') return `${st.hostname}#`;
    if (st.mode === 'config') return st.ifaceCtx ? `${st.hostname}(config-if)#` : `${st.hostname}(config)#`;
    return `${st.hostname}>`;
  };
  const ok = (t) => `\r\n${t}\r\n`;
  const ciscoVer = `Cisco IOS Software, ${dev.model} Software, Version ${dev.os}\r
Technical Support: http://www.cisco.com/techsupport\r
${dev.model} uptime is ${ds.human(86400 * 120)}\r
System returned to ROM by reload\r
System restarted at 03:14:22\r
System image file is "flash:packages.conf"\r
cisco ${dev.model} (X86) processor with 4194304K/6144K bytes of memory.\r
Processor board ID ${dev.host}-SN\r
Configuration register is 0x102\r`;
  const hw = `Huawei Versatile Routing Platform Software\r
VRP (R) software, Version ${dev.os}\r
Copyright (C) 2012-2024 Huawei Technologies Co., Ltd.\r
${dev.model} uptime is ${Math.floor(120)} days, 4 hours, 12 minutes\r
MPU 1(Master) : uptime is 120 days, 4 hours\r
        512 M bytes DDR3 SDRAM Memory\r
        16 M bytes Flash Memory\r
        Pcb      Version :  VER.B\r`;
  const h3c = `H3C Comware Software, Version ${dev.os}, Release 1118P02\r
Copyright (c) 2004-2024 New H3C Technologies Co., Ltd.\r
${dev.model} uptime is 12 weeks, 3 days, 6 hours, 2 minutes\r
Last reboot reason : User reboot\r
Boot image: flash:/boot.bin\r`;

  function portBrief() {
    const d = ds.DEMO_DEVICES.find(x => x.host === host) || ds.DEMO_DEVICES[0];
    let lines = [];
    if (vendor === 'Cisco') {
      lines.push('Port      Name               Status       Vlan       Duplex  Speed Type');
      for (let i = 1; i <= Math.min(d.ports, 24); i++) {
        const name = `${d.portPrefix}${i}`;
        const up = i <= 4 || (i * 7) % 11 > 3;
        lines.push(`${name.padEnd(9).slice(0, 9)} ${(i <= 4 ? 'Uplink-Trunk' : 'PC-' + (200 + i)).padEnd(18)} ${(up ? 'connected' : 'notconnect').padEnd(12)} ${(i <= 4 ? 'trunk' : '10').padEnd(10)} ${up ? 'a-full  a-1000' : 'auto    auto'} ${up ? '10/100/1000BaseTX' : ''}`);
      }
    } else {
      lines.push('PHY: Physical  *down: administratively down');
      lines.push('#: Serial  (l): loopback  (s): spoofing  (b): BFD down  (e): EFM down  (u): UPoE');
      lines.push('Interface                   PHY   Protocol InUti OutUti   inErrors  outErrors');
      for (let i = 0; i < Math.min(d.ports, 24); i++) {
        const nm = `${d.portPrefix}${i + 1}`;
        const up = i <= 4 || (i * 7) % 11 > 3;
        lines.push(`${nm.padEnd(27)} ${up ? 'up' : 'down'}    ${up ? 'up' : 'down'}     ${up ? (1 + i % 9) : 0}%     ${up ? (1 + (i * 3) % 12) : 0}%   ${up ? 0 : 0}       ${up ? 0 : 0}`);
      }
    }
    return lines.join('\r\n') + '\r\n';
  }

  function macTable() {
    const d = ds.DEMO_DEVICES.find(x => x.host === host) || ds.DEMO_DEVICES[0];
    let out = '';
    if (vendor === 'Cisco') {
      out = '          Mac Address Table\r\n-------------------------------------------\r\nVlan    Mac Address       Type        Ports\r\n----    -----------       --------    -----\r\n';
      for (let i = 1; i <= 12; i++) out += ` ${[10, 20, 30][i % 3]}    ${rndMac(i)}   DYNAMIC     Gi1/0/${i + 4}\r\n`;
      out += `Total Mac Addresses for this criterion: 12\r\n`;
    } else if (vendor === 'H3C') {
      out = 'MAC Address      VLAN ID    State        Port/Nickname       Aging\r\n';
      for (let i = 1; i <= 12; i++) out += `${rndMacH(i)}  ${[10, 20, 30][i % 3]}   Learned      GE1/0/${i + 4}              Y\r\n`;
    } else {
      out = 'MAC Address    VLAN/VSI                          Learned-From        Type\r\n';
      for (let i = 1; i <= 12; i++) out += `${rndMacH(i)}  ${[10, 20, 30][i % 3]}/-                             GE0/0/${i + 4}         dynamic\r\n`;
    }
    return out;
  }
  const rndMac = i => `${(0x1000 + i * 7).toString(16)}.${(0x2000 + i * 13).toString(16).slice(-4)}.${(0x3000 + i * 31).toString(16).slice(-4)}`;
  const rndMacH = i => `${(0x1000 + i * 7).toString(16).slice(-4)}-${(0x2000 + i * 13).toString(16).slice(-4)}-${(0x3000 + i * 31).toString(16).slice(-4)}`;

  function arpTable() {
    let out = '';
    if (vendor === 'Cisco') {
      out = 'Protocol  Address          Age (min)  Hardware Addr   Type   Interface\r\n';
      for (let i = 1; i <= 8; i++) out += `Internet  10.252.28.${40 + i}      ${i * 3}   ${rndMac(i)}   ARPA   Vlan${[10, 20, 30][i % 3]}\r\n`;
    } else {
      out = 'Address         MAC Address      VLAN     Interface                Type  Age\r\n';
      for (let i = 1; i <= 8; i++) out += `10.252.28.${40 + i}     ${rndMacH(i)}  ${[10, 20, 30][i % 3]}       GE0/0/${i + 4}               D      ${i * 3}\r\n`;
    }
    return out;
  }

  function counters() {
    const d = ds.DEMO_DEVICES.find(x => x.host === host) || ds.DEMO_DEVICES[0];
    let out = 'Port            Align-Err    FCS-Err   Xmit-Err    Rcv-Err  UnderSize  OutDiscards\r\n';
    for (let i = 1; i <= 8; i++) {
      out += `Gi1/0/${i}`.padEnd(16) + `0            0            0           0            0          ${i === 5 ? 128 : 0}\r\n`;
    }
    return out;
  }

  function pingOut(target) {
    let out = `\r\nPING ${target} (${target}): 56 data bytes\r\n`;
    const base = 1 + Math.random() * 6;
    for (let i = 0; i < 5; i++) out += `64 bytes from ${target}: icmp_seq=${i} ttl=254 time=${(base + Math.random() * 2).toFixed(1)} ms\r\n`;
    out += `\r\n--- ${target} ping statistics ---\r\n5 packets transmitted, 5 packets received, 0.00% packet loss\r\nround-trip min/avg/max = ${base.toFixed(1)}/${(base + 1).toFixed(1)}/${(base + 2).toFixed(1)} ms\r\n`;
    return out;
  }

  function exec(cmd) {
    const c = cmd.trim();
    const lc = c.toLowerCase();
    if (!c) return ok('');
    if (lc === 'enable' || lc === 'en') {
      st.mode = 'priv';
      return vendor === 'Cisco' ? '' : ok('Enter system view, return user view with Ctrl+Z.');
    }
    if (lc === 'disable') { st.mode = 'user'; return ''; }
    if (lc === 'system-view' || lc === 'sys') { st.mode = 'config'; st.ifaceCtx = ''; return ok('Enter system view, return user view with Ctrl+Z.'); }
    if (lc === 'configure terminal' || lc === 'conf t') { st.mode = 'config'; st.ifaceCtx = ''; return ok('Enter configuration commands, one per line.  End with CNTL/Z.'); }
    if (lc.startsWith('interface ') || lc.startsWith('int ')) {
      st.mode = 'config'; st.ifaceCtx = c.split(/\s+/)[1]; return ok('');
    }
    if (lc === 'exit' || lc === 'quit' || lc === 'q') {
      if (st.ifaceCtx) { st.ifaceCtx = ''; return ok(''); }
      if (st.mode === 'config') { st.mode = vendor === 'Cisco' ? 'priv' : 'user'; return ok(''); }
      return ok('');
    }
    if (lc === 'end' || lc === 'return' || lc === 'ctrl+z') { st.mode = 'priv'; st.ifaceCtx = ''; return ok(''); }
    if (lc.startsWith('show version') || lc.startsWith('display version')) {
      return ok(vendor === 'Cisco' ? ciscoVer : vendor === 'H3C' ? h3c : hw);
    }
    if (lc.startsWith('show run') || lc.startsWith('display current-config')) {
      let out = [];
      if (vendor === 'Cisco') {
        out.push('Building configuration...', '', 'Current configuration : 8421 bytes', '!', 'version 17.9', `hostname ${st.hostname}`, '!',
          'no ip domain lookup', 'ip domain name corp.local', '!', 'vlan 10', ' name Office', 'vlan 20', ' name IPPhone', 'vlan 30', ' name WiFi', '!',
          'interface GigabitEthernet1/0/1', ' description Uplink-Trunk', ' switchport mode trunk', ' switchport trunk allowed vlan 1,10,20,30',
          ' spanning-tree portfast trunk', '!', 'interface GigabitEthernet1/0/5', ' description PC-205', ' switchport mode access', ' switchport access vlan 10',
          ' switchport port-security maximum 2', ' switchport port-security', ' spanning-tree portfast', '!',
          'line con 0', ' logging synchronous', 'line vty 0 4', ' login local', ' transport input ssh', '!', 'end');
        out.push('Note: 当前为演示模式输出，接入真实设备后此处显示实际 running-config');
      } else {
        out.push('#', `sysname ${st.hostname}`, '#', 'vlan batch 10 20 30', '#',
          'interface GigabitEthernet0/0/1', ' port link-type trunk', ' port trunk allow-pass vlan 10 20 30', '#',
          'interface GigabitEthernet0/0/5', ' port link-type access', ' port default vlan 10', ' stp edged-port enable', '#',
          'return', '', 'Note: 当前为演示模式输出，接入真实设备后此处显示实际 configuration');
      }
      return ok(out.join('\r\n'));
    }
    if (lc.startsWith('show interface status') || lc.startsWith('show int status') || lc.startsWith('display interface brief')) return ok(portBrief());
    if (lc.includes('mac address-table') || lc.includes('display mac-address')) return ok(macTable());
    if (lc.startsWith('show ip arp') || lc.startsWith('show arp') || lc.startsWith('display arp')) return ok(arpTable());
    if (lc.includes('counters errors') || lc.includes('error')) return ok(counters());
    if (lc.startsWith('show cpu') || lc.startsWith('display cpu')) return ok(`CPU utilization for five seconds: 12%/3%; one minute: 14%; five minutes: 13%\r\n`);
    if (lc.startsWith('show mem') || lc.startsWith('display memory')) return ok(`Processor Pool Total: 1187754696 Used: 512345678 Free: 675409018\r\n`);
    if (lc.startsWith('show clock') || lc.startsWith('display clock')) return ok(`${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC\r\n`);
    if (lc.startsWith('show ip int brief')) {
      let out = 'Interface              IP-Address      OK? Method Status                Protocol\r\n';
      out += `Vlan1                  ${st.dev.ip}     YES NVRAM  up                    up\r\n`;
      out += 'Vlan10                 10.252.30.1     YES NVRAM  up                    up\r\n';
      out += 'Vlan20                 10.252.31.1     YES NVRAM  up                    up\r\n';
      return ok(out);
    }
    if (lc.startsWith('ping ') || lc.startsWith('display ') && lc.includes('ping')) return ok(pingOut(c.split(/\s+/).pop()));
    if (lc.startsWith('write') || lc === 'save' || lc.startsWith('copy run start')) {
      return ok(vendor === 'Cisco' ? 'Building configuration...\r\n[OK]' : 'The current configuration is saved successfully.\r\n');
    }
    // 配置类命令：回显像真机一样静默或提示
    if (st.mode === 'config') {
      if (lc.startsWith('no shutdown') || lc.startsWith('undo shutdown')) return ok('');
      if (lc.startsWith('shutdown')) return ok(host.includes('ACC') ? '\r\n%LINK-5-CHANGED: Interface down\r\n' : '');
      return ok('');
    }
    return ok(`% Invalid input detected at '^' marker.\r\n` + '提示：演示模式仅内置常用 show/display 命令。接入真实设备后支持全部命令。');
  }

  return {
    banner: `\x1b[1;36m网络运维控制台 · 演示终端\x1b[0m\r\n已连接到 \x1b[1m${dev.name}\x1b[0m (${dev.host} / ${dev.ip})\r\n型号 \x1b[33m${dev.vendor} ${dev.model}\x1b[0m  系统 ${dev.os}\r\n\x1b[90m当前为演示模式，命令由内置 CLI 模拟器应答；在系统管理→凭据库配置真机凭据后即为真实会话。\x1b[0m\r\n\r\n`,
    prompt,
    exec,
    state: st
  };
}

/* ============================ 终端会话处理 ============================ */
function terminalSocket(wss) {
  const { WebSocketServer } = require('ws');
  const wssTerm = new WebSocketServer({ noServer: true });

  wss.on('upgrade', (req, socket, head) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname !== '/ws/terminal') return;
    wssTerm.handleUpgrade(req, socket, head, ws => wssTerm.emit('connection', ws, req));
  });

  wssTerm.on('connection', async (ws, req) => {
    const u = new URL(req.url, 'http://x');
    const token = u.searchParams.get('token') || '';
    const payload = auth.verifyToken(token);
    const user = payload ? (await db.usersList()).find(x => x.id === payload.uid) : null;
    if (!user) { ws.send('\r\n\x1b[31m认证失败，请重新登录。\x1b[0m\r\n'); return ws.close(); }
    if (!(auth.permsOf(user.role).includes('*') || auth.permsOf(user.role).includes('terminal'))) {
      ws.send('\r\n\x1b[31m当前角色无终端权限。\x1b[0m\r\n'); return ws.close();
    }

    const host = u.searchParams.get('host') || '';
    const credId = u.searchParams.get('credId') || '';
    const cols = Number(u.searchParams.get('cols') || 140);
    const rows = Number(u.searchParams.get('rows') || 36);
    const ip = auth.clientIp(req);

    const cred = credId ? await db.credentialsFind(credId) : null;
    const dev = ds.DEMO_DEVICES.find(d => d.host === host);
    const isDemo = !cred;

    const rec = (db.settingsSync() || {}).terminal?.recordSessions
      ? await db.recNew({ user: user.username, role: user.role, ip, host, kind: isDemo ? 'demo' : cred.kind, cols, rows })
      : null;

    const write = (data) => {
      if (ws.readyState === 1) ws.send(typeof data === 'string' ? data : data.toString('utf8'));
      if (rec) db.recAppend(rec.file, { t: 'o', d: typeof data === 'string' ? data : data.toString('utf8') });
    };

    store.audit({ user: user.username, role: user.role, ip, action: 'terminal.open', target: host, result: 'ok', detail: isDemo ? '演示会话' : `凭据 ${cred.name}` });

    let sim = null, conn = null, stream = null, lineBuf = '';

    if (isDemo) {
      sim = makeSimulator(host || ds.DEMO_DEVICES[0].host);
      write(sim.banner);
      write(sim.prompt());
    } else {
      try {
        conn = await netutil.sshConnect({
          host: cred.host || dev?.ip, port: cred.port || 22, username: cred.username,
          secret: store.decrypt(cred.secretEnc), kind: cred.kind
        });
        conn.shell({ term: 'xterm-256color', cols, rows }, (err, s) => {
          if (err) { write(`\r\n\x1b[31m打开 shell 失败：${err.message}\x1b[0m\r\n`); return ws.close(); }
          stream = s;
          s.on('data', d => write(d));
          s.stderr.on('data', d => write(d));
          s.on('close', () => { write('\r\n\x1b[90m会话已结束。\x1b[0m\r\n'); ws.close(); });
          ws.send(JSON.stringify({ t: 'ready' }));
        });
        conn.on('error', e => write(`\r\n\x1b[31m连接错误：${e.message}\x1b[0m\r\n`));
      } catch (e) {
        write(`\r\n\x1b[31mSSH 连接失败：${e.message}\r\n请检查设备可达性与凭据库配置。\x1b[0m\r\n`);
        store.audit({ user: user.username, role: user.role, ip, action: 'terminal.open', target: host, result: 'fail', detail: e.message });
        return ws.close();
      }
    }

    let idleTimer = setTimeout(() => { write('\r\n\x1b[33m空闲超时，会话自动断开。\x1b[0m\r\n'); ws.close(); },
      ((db.settingsSync() || {}).terminal?.idleTimeoutSec || 600) * 1000);

    ws.on('message', raw => {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => { write('\r\n\x1b[33m空闲超时，会话自动断开。\x1b[0m\r\n'); ws.close(); },
        ((db.settingsSync() || {}).terminal?.idleTimeoutSec || 600) * 1000);
      let msg; try { msg = JSON.parse(raw.toString()); } catch { msg = { t: 'i', d: raw.toString() }; }

      if (msg.t === 'resize') {
        if (stream) stream.setWindow(msg.rows || 36, msg.cols || 140, 0, 0);
        return;
      }
      if (msg.t === 'i') {
        const d = msg.d || '';
        if (rec) db.recAppend(rec.file, { t: 'i', d });
        if (stream) return stream.write(d);
        if (sim) {
          for (const ch of String(d)) {
            if (ch === '\r' || ch === '\n') {
              const cmd = lineBuf; lineBuf = '';
              const danger = checkDanger(cmd);
              if (danger) {
                write(`\r\n\x1b[31m⚠ 危险命令被拦截：命中规则「${danger}」\x1b[0m\r\n`);
                store.audit({ user: user.username, role: user.role, ip, action: 'terminal.danger-blocked', target: host, result: 'deny', detail: cmd });
              } else {
                if (cmd.trim()) store.audit({ user: user.username, role: user.role, ip, action: 'terminal.cmd', target: host, result: 'ok', detail: cmd.trim().slice(0, 300) });
                write(sim.exec(cmd));
              }
              write(sim.prompt());
            } else if (ch === '\u007f' || ch === '\b') {
              if (lineBuf.length) { lineBuf = lineBuf.slice(0, -1); write('\b \b'); }
            } else if (ch >= ' ') {
              lineBuf += ch; write(ch);
            }
          }
        }
        return;
      }
      if (msg.t === 'close') ws.close();
    });

    ws.on('close', () => {
      if (rec) db.recAppend(rec.file, { t: 'close', at: new Date().toISOString() });
      if (conn) { try { conn.end(); } catch { } }
      store.audit({ user: user.username, role: user.role, ip, action: 'terminal.close', target: host, result: 'ok', detail: rec ? `录像 ${rec.id}` : '' });
    });
  });

  return wssTerm;
}

function checkDanger(cmd) {
  const pats = (db.settingsSync() || {}).terminal?.dangerPatterns || [];
  const c = String(cmd || '');
  for (const p of pats) {
    try { if (new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i').test(c)) return p; } catch { }
  }
  return null;
}

/* ============================ 批量执行 / 配置下发 ============================ */
async function deploy({ hosts, commands, credentialId, user, ip, confirmText, reason }) {
  const results = [];
  const dangerHits = commands.map(c => checkDanger(c)).filter(Boolean);
  if (dangerHits.length && !confirmText) {
    return { requiresConfirm: true, dangerHits, message: '命令中包含高风险操作，请确认后再执行' };
  }
  for (const host of hosts) {
    const started = Date.now();
    const dev = ds.DEMO_DEVICES.find(d => d.host === host);
    const out = { host, ok: true, output: '', error: '', ms: 0, demo: false };
    const cred = credentialId ? await db.credentialsFind(credentialId) : null;
    try {
      if (!cred) {
        // 演示模式：用模拟器逐条执行，产生"看起来真实"的回显
        out.demo = true;
        const sim = makeSimulator(host);
        let buf = sim.banner;
        sim.state.mode = 'priv';
        for (const c of commands) { buf += sim.prompt() + c + '\r\n' + sim.exec(c); }
        setTimeout(() => { }, 0);
        out.output = buf;
      } else {
        const r = await netutil.sshExec({
          host: dev?.ip || cred.host, port: cred.port || 22, username: cred.username,
          secret: store.decrypt(cred.secretEnc), kind: cred.kind
        }, commands, { timeoutMs: 120000, perCmdDelay: 800 });
        out.output = r.out;
        out.timeout = r.timeout;
      }
    } catch (e) {
      out.ok = false; out.error = e.message;
    }
    out.ms = Date.now() - started;
    results.push(out);
    store.audit({
      user, ip, action: 'config.deploy', target: host,
      result: out.ok ? 'ok' : 'fail',
      detail: `命令 ${commands.length} 条${reason ? ' | 事由: ' + reason : ''} | ${commands.join(' ; ').slice(0, 400)}`
    });
  }
  const recId = store.uid('deploy_');
  store.saveSpeedResult({ id: recId, kind: 'deploy', at: new Date().toISOString(), user, hosts, commands, reason, results });
  return { requiresConfirm: false, results, recordId: recId, dangerHits };
}

module.exports = { terminalSocket, deploy, checkDanger, makeSimulator };
