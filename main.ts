// forge — a standalone GitHub-compatible git forge in one Node process.
// Serves git smart HTTP (upload-pack v2, receive-pack v0), REST v3, GraphQL
// and MCP from its own in-memory store. Standard library only, no git binary,
// no model calls, no wall clock in anything it sends (all timestamps derive
// from MAKEFUN_TRIAL_NOW plus a deterministic counter).
import http from 'node:http';
import zlib from 'node:zlib';
import crypto from 'node:crypto';

const ZERO_OID = '0'.repeat(40);
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');

// ---------------------------------------------------------------------------
// The scenario's fixed seed (wire.ts): the viewer login the token names is
// derived from it, so the forge can tell the token owner from any other login.
// ---------------------------------------------------------------------------
const U64 = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;
function fnv1a64(text: string): bigint {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i++) { h ^= BigInt(text.charCodeAt(i)); h = (h * 0x100000001b3n) & U64; }
  return h;
}
function mix64(v: bigint): bigint {
  let z = (v + 0x9e3779b97f4a7c15n) & U64;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64;
  return (z ^ (z >> 31n)) & U64;
}
class ScenRng {
  #s: bigint;
  constructor(seed: bigint) { this.#s = (seed & U64) === 0n ? SCENARIO_SEED : seed & U64; }
  nextU64(): bigint {
    let x = this.#s;
    x = (x ^ (x >> 12n)) & U64; x = (x ^ (x << 25n)) & U64; x = (x ^ (x >> 27n)) & U64;
    this.#s = x; return (x * 0x2545f4914f6cdd1dn) & U64;
  }
  nextU32(): number { return Number(this.nextU64() >> 32n); }
  nextInt(m: number): number {
    if (m === 1) return 0;
    const r = 4294967296, lim = r - (r % m);
    for (;;) { const v = this.nextU32(); if (v < lim) return v % m; }
  }
  pick<T>(a: readonly T[]): T { return a[this.nextInt(a.length)] as T; }
}
const FIRST = ['ada','bram','cora','dmitri','elena','felix','greta','hugo','iris','jonas','kira','lars','mira','nico','olga','pavel','quinn','rosa','sven','tess','ulla','vito','wren','yara','zane'];
const LAST = ['anders','bauer','costa','dahl','eriksen','fischer','garcia','holm','iversen','jansen','keller','lind','moreau','novak','olsen','peters','quist','rossi','sato','turi','ulrich','vega','weber','xu','yilmaz','zimmer'];
function scenarioUsers(): { login: string; name: string; email: string; id: number }[] {
  const rng = new ScenRng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const used = new Set<string>(); const out: { login: string; name: string; email: string; id: number }[] = [];
  for (let i = 0; i < 12; i++) {
    const f = rng.pick(FIRST), l = rng.pick(LAST);
    const base = `${f}${l}`; let login = base, s = 2;
    while (used.has(login)) { login = `${base}-${s}`; s++; }
    used.add(login);
    out.push({ login, name: `${f} ${l}`, email: `${login}@example.invalid`, id: 1000 + i });
  }
  return out;
}
const USERS = scenarioUsers();
const VIEWER = USERS[0] as { login: string; name: string; email: string; id: number };
const STRANGER = USERS[2] as { login: string; name: string; email: string; id: number };

// ---------------------------------------------------------------------------
// Deterministic clock: every timestamp the forge sends is MAKEFUN_TRIAL_NOW
// plus a counter, so two runs that receive the same requests send the same
// bytes. Never Date.now() / new Date() in a response.
// ---------------------------------------------------------------------------
const TRIAL_NOW_RAW = process.env.MAKEFUN_TRIAL_NOW ?? '';
const TRIAL_NOW_MS = (() => { const t = Date.parse(TRIAL_NOW_RAW); return Number.isFinite(t) ? t : Date.parse('2025-01-01T00:00:00Z'); })();
let tick = 0;
function nextStamp(): { epoch: number; iso: string } {
  const epoch = Math.floor(TRIAL_NOW_MS / 1000) + tick++;
  return { epoch, iso: new Date(epoch * 1000).toISOString() };
}
function identLine(): string {
  const s = nextStamp();
  return `${VIEWER.name} <${VIEWER.email}> ${s.epoch} +0000`;
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
const sha1 = (b: Buffer): string => crypto.createHash('sha1').update(b).digest('hex');
const isOid = (s: string): boolean => /^[0-9a-f]{40}$/.test(s);
const b64enc = (b: Buffer): string => b.toString('base64');
const b64dec = (s: string): Buffer => Buffer.from(s.replace(/[\r\n\t ]+/g, ''), 'base64');
const esc = (s: string): string => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4); head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
const pktFlush = (): Buffer => Buffer.from('0000', 'ascii');
const pktDelim = (): Buffer => Buffer.from('0001', 'ascii');
const pktLines = (items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer => {
  const parts: Buffer[] = [];
  for (const it of items) {
    if (it === 'flush') parts.push(pktFlush());
    else if (it === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(it));
  }
  return Buffer.concat(parts);
};
interface Pkt { kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }
function parsePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = []; let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.toString('ascii', off, off + 4);
    if (head === '0000') { out.push({ kind: 'flush', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (head === '0001') { out.push({ kind: 'delim', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (head === '0002') { out.push({ kind: 'end', payload: Buffer.alloc(0) }); off += 4; continue; }
    const len = parseInt(head, 16);
    if (!Number.isFinite(len) || len < 4 || off + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// Inflate one zlib stream starting at `off` inside `buf`; the stream's length
// is unknown, so find it: a truncated prefix throws, a prefix at or past the
// true end succeeds (trailing bytes are ignored), so the predicate is
// monotone in the prefix length.
function inflateAt(buf: Buffer, off: number): { data: Buffer; next: number } {
  const remaining = buf.length - off;
  if (remaining <= 0) throw new Error('inflate past end of pack');
  const ok = (len: number): Buffer | null => {
    try { return zlib.inflateSync(buf.subarray(off, off + len)); } catch { return null; }
  };
  let lo = 1; let hi = 16; let got: Buffer | null = null;
  for (;;) {
    const h = Math.min(hi, remaining);
    const d = ok(h);
    if (d !== null) { got = d; hi = h; break; }
    if (h >= remaining) throw new Error('bad zlib stream in pack');
    lo = h + 1; hi = h * 2;
  }
  let best = hi; let bestData = got as Buffer;
  let l = lo; let r = hi;
  while (l <= r) {
    const mid = Math.floor((l + r) / 2);
    const d = ok(mid);
    if (d !== null) { best = mid; bestData = d; r = mid - 1; } else l = mid + 1;
  }
  return { data: bestData, next: off + best };
}
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let p = 0;
  const readVarint = (): number => {
    let v = 0, shift = 0;
    for (;;) { const b = delta[p++] as number; v |= (b & 0x7f) << shift; shift += 7; if ((b & 0x80) === 0) break; }
    return v;
  };
  const srcSize = readVarint(); const dstSize = readVarint();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out: Buffer[] = []; let total = 0;
  while (p < delta.length) {
    const op = delta[p++] as number;
    if (op & 0x80) {
      let off = 0, size = 0;
      if (op & 0x01) off = delta[p++] as number;
      if (op & 0x02) off |= (delta[p++] as number) << 8;
      if (op & 0x04) off |= (delta[p++] as number) << 16;
      if (op & 0x08) off |= (delta[p++] as number) << 24;
      if (op & 0x10) size = delta[p++] as number;
      if (op & 0x20) size |= (delta[p++] as number) << 8;
      if (op & 0x40) size |= (delta[p++] as number) << 16;
      if (size === 0) size = 0x10000;
      const chunk = base.subarray(off, off + size); out.push(chunk); total += chunk.length;
    } else if (op !== 0) {
      const chunk = delta.subarray(p, p + op); p += op; out.push(chunk); total += chunk.length;
    } else throw new Error('delta op 0');
  }
  const res = Buffer.concat(out);
  if (res.length !== dstSize || total !== dstSize) throw new Error('delta size mismatch');
  return res;
}

// ---------------------------------------------------------------------------
// Git object model (sha1). Objects live per repository in a Map.
// ---------------------------------------------------------------------------
type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj { type: ObjType; data: Buffer }
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
function hashObject(type: ObjType, data: Buffer): string {
  return sha1(Buffer.concat([Buffer.from(`${type} ${data.length}\0`, 'utf8'), data]));
}
interface TreeEntry { mode: string; name: string; oid: string }
function parseTree(data: Buffer): TreeEntry[] {
  const out: TreeEntry[] = []; let p = 0;
  while (p < data.length) {
    const sp = data.indexOf(0x20, p); const nul = data.indexOf(0, sp);
    if (sp < 0 || nul < 0) throw new Error('bad tree');
    out.push({ mode: data.toString('utf8', p, sp), name: data.toString('utf8', sp + 1, nul), oid: data.subarray(nul + 1, nul + 21).toString('hex') });
    p = nul + 21;
  }
  return out;
}
function treeSortKey(e: TreeEntry): string { return e.name + (e.mode === '40000' ? '/' : ''); }
function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
interface CommitView { tree: string; parents: string[]; author: string; committer: string; message: string }
function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  // GitHub surfaces commit messages without the trailing newline that
  // buildCommit appends as framing; strip it here so every consumer
  // (GET /commits, GraphQL) sees the GitHub form.
  const message = blank < 0 ? '' : text.slice(blank + 2).replace(/\n+$/, '');
  const v: CommitView = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) v.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) v.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) v.author = line.slice(7);
    else if (line.startsWith('committer ')) v.committer = line.slice(10);
  }
  return v;
}
function buildCommit(tree: string, parents: string[], message: string): Buffer {
  const ident = identLine();
  const lines = [`tree ${tree}`, ...parents.map((p) => `parent ${p}`), `author ${ident}`, `committer ${ident}`, '', message.endsWith('\n') ? message : `${message}\n`];
  return Buffer.from(lines.join('\n'), 'utf8');
}
function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const v = { object: '', type: '', tag: '', tagger: '', message: blank < 0 ? '' : text.slice(blank + 2) };
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) v.object = line.slice(7).trim();
    else if (line.startsWith('type ')) v.type = line.slice(5).trim();
    else if (line.startsWith('tag ')) v.tag = line.slice(4);
    else if (line.startsWith('tagger ')) v.tagger = line.slice(7);
  }
  return v;
}
// Peel a tag (possibly nested) to its commit oid.
function peelToCommit(repo: Repo, oid: string): string | null {
  let cur = oid; const seen = new Set<string>();
  for (let i = 0; i < 16; i++) {
    if (seen.has(cur)) return null; seen.add(cur);
    const o = repo.objects.get(cur); if (!o) return null;
    if (o.type === 'commit') return cur;
    if (o.type === 'tag') { cur = parseTag(o.data).object; continue; }
    return null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Packfiles: read (incl. OFS_DELTA / REF_DELTA) and write (plain objects).
// ---------------------------------------------------------------------------
function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [(code << 4) | (size & 0x0f)];
  let rest = size >>> 4;
  while (rest > 0) { bytes[bytes.length - 1] |= 0x80; bytes.push(rest & 0x7f); rest >>>= 7; }
  return Buffer.from(bytes);
}
function writePack(objects: Iterable<GitObj & { oid: string }>): Buffer {
  const list = [...objects];
  const head = Buffer.alloc(12); head.write('PACK', 0, 'ascii'); head.writeUInt32BE(2, 4); head.writeUInt32BE(list.length, 8);
  const parts: Buffer[] = [head];
  for (const o of list) {
    const deflated = zlib.deflateSync(o.data, { level: 6 });
    parts.push(writePackObjectHeader(o.type, o.data.length), deflated);
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, crypto.createHash('sha1').update(body).digest()]);
}
interface PackEntry { type: ObjType; data: Buffer; oid: string }
function readPack(buf: Buffer, baseResolver?: (oid: string) => { type: ObjType; data: Buffer } | undefined): PackEntry[] {
  if (buf.length < 12 || buf.toString('ascii', 0, 4) !== 'PACK') throw new Error('bad pack header');
  const version = buf.readUInt32BE(4); const count = buf.readUInt32BE(8);
  if (version !== 2) throw new Error('bad pack version');
  const entries: PackEntry[] = [];
  const byOffset = new Map<number, PackEntry>();
  let off = 12;
  for (let i = 0; i < count; i++) {
    const start = off;
    const b0 = buf[off++] as number;
    let typeCode = (b0 >> 4) & 0x7;
    let byte = b0; let size = byte & 0x0f; let shift = 4;
    while (byte & 0x80) { byte = buf[off++] as number; size |= (byte & 0x7f) << shift; shift += 7; }
    let baseOid: string | null = null; let baseOff: number | null = null;
    if (typeCode === 6) {
      byte = buf[off++] as number; let v = byte & 0x7f;
      while (byte & 0x80) { byte = buf[off++] as number; v = ((v + 1) << 7) | (byte & 0x7f); }
      baseOff = start - v;
    } else if (typeCode === 7) {
      baseOid = buf.subarray(off, off + 20).toString('hex'); off += 20;
    }
    const inf = inflateAt(buf, off); off = inf.next;
    // `size` is the size of the inflated stream: for a delta object that
    // is the delta-instruction size, NOT the reconstructed object size,
    // so it must be checked against the raw inflated data before the
    // delta is applied (applyDelta validates the result size itself).
    if (inf.data.length !== size) throw new Error('pack object size mismatch');
    let type: ObjType; let data: Buffer = inf.data;
    if (typeCode === 6 || typeCode === 7) {
      // OFS_DELTA bases are always in-pack (offset); REF_DELTA bases may
      // be thin-pack bases the server already holds, resolved via
      // baseResolver when given.
      const base = typeCode === 6
        ? byOffset.get(baseOff as number)
        : (entries.find((e) => e.oid === baseOid) ?? (baseResolver ? baseResolver(baseOid as string) : undefined));
      if (!base) throw new Error('delta base missing');
      data = applyDelta(base.data, inf.data); type = base.type;
    } else {
      type = CODE_TYPE[typeCode] as ObjType;
      if (!type) throw new Error(`bad pack object type ${typeCode}`);
    }
    const oid = hashObject(type, data);
    const entry: PackEntry = { type, data, oid };
    entries.push(entry); byOffset.set(start, entry);
  }
  const trailer = buf.subarray(buf.length - 20);
  const expect = crypto.createHash('sha1').update(buf.subarray(0, buf.length - 20)).digest();
  if (!trailer.equals(expect)) throw new Error('pack checksum mismatch');
  return entries;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------
interface IssueRec {
  number: number; title: string; body: string; state: 'open' | 'closed';
  labels: string[]; seq: number; dbId: number; createdAt: string; updatedAt: string;
  comments: { id: number; body: string; createdAt: string }[];
}
interface PullRec {
  number: number; title: string; body: string; state: 'open' | 'closed';
  head: string; base: string; headSha: string; baseSha: string;
  merged: boolean; mergeSha: string | null; mergedAt: string | null; seq: number;
}
interface Repo {
  dbId: number; name: string; owner: string; description: string; isPrivate: boolean;
  defaultBranch: string; createdSeq: number;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  labels: Map<string, { name: string; color: string }>;
  issues: Map<number, IssueRec>;
  pulls: Map<number, PullRec>;
  nextNumber: number; // shared issue/PR numbering, GitHub-style
  nextCommentId: number;
}
const repos = new Map<string, Repo>();
let nextRepoDbId = 1000;
let nextGlobalId = 1;
let reqCounter = 0;

function repoKey(owner: string, name: string): string { return `${owner}/${name}`; }
function getRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER.login) return undefined;
  return repos.get(repoKey(owner, name));
}
function createRepo(name: string, isPrivate: boolean, description: string): Repo {
  const r: Repo = {
    dbId: nextRepoDbId++, name, owner: VIEWER.login, description, isPrivate,
    defaultBranch: 'main', createdSeq: tick,
    objects: new Map(), refs: new Map(), labels: new Map(),
    issues: new Map(), pulls: new Map(), nextNumber: 1, nextCommentId: 1,
  };
  repos.set(repoKey(VIEWER.login, name), r);
  return r;
}
function putObj(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}
function globalId(kind: string, ...parts: (string | number)[]): string {
  return Buffer.from(`${kind}:${parts.join(':')}`, 'utf8').toString('base64');
}
function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const [kind, ...parts] = text.split(':');
    if (!kind || parts.length === 0) return null;
    return { kind, parts };
  } catch { return null; }
}
function findRepoByDbId(dbId: number): Repo | undefined {
  for (const r of repos.values()) if (r.dbId === dbId) return r;
  return undefined;
}
// Build a nested tree from a flat file map and store every tree object.
function buildTreeFromFiles(repo: Repo, files: Map<string, { oid: string; mode: string }>): string {
  interface Node { files: Map<string, { oid: string; mode: string }>; dirs: Map<string, Node> }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, f] of files) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i++) {
      const s = segs[i] as string;
      if (!node.dirs.has(s)) node.dirs.set(s, make());
      node = node.dirs.get(s) as Node;
    }
    node.files.set(segs[segs.length - 1] as string, f);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, f] of [...node.files].sort((a, b) => (a[0] < b[0] ? -1 : 1))) entries.push({ mode: f.mode, name, oid: f.oid });
    for (const [name, child] of [...node.dirs].sort((a, b) => (a[0] < b[0] ? -1 : 1))) entries.push({ mode: '40000', name, oid: build(child) });
    return putObj(repo, 'tree', buildTree(entries));
  };
  return build(root);
}
// Flat file map of a commit (path -> blob oid + mode), or null if unresolvable.
function filesOfCommit(repo: Repo, commitOid: string): Map<string, { oid: string; mode: string }> | null {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (treeOid: string, prefix: string): boolean => {
    const t = repo.objects.get(treeOid); if (!t || t.type !== 'tree') return false;
    for (const e of parseTree(t.data)) {
      const path = prefix ? `${prefix}/${e.name}` : e.name;
      if (e.mode === '40000') { if (!walk(e.oid, path)) return false; }
      else out.set(path, { oid: e.oid, mode: e.mode });
    }
    return true;
  };
  const c = repo.objects.get(commitOid); if (!c || c.type !== 'commit') return null;
  const tree = parseCommit(c.data).tree;
  return walk(tree, '') ? out : null;
}
function resolveRef(repo: Repo, ref: string): string | null {
  if (isOid(ref)) return repo.objects.has(ref) ? ref : null;
  if (repo.refs.has(ref)) return repo.refs.get(ref) as string;
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`) as string;
  if (ref === 'HEAD') return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  return null;
}
// Ancestor test: is `anc` reachable from `tip` following parents?
function isAncestor(repo: Repo, anc: string, tip: string): boolean {
  if (anc === tip) return true;
  const seen = new Set<string>(); const stack = [tip];
  while (stack.length) {
    const cur = stack.pop() as string;
    if (cur === anc) return true;
    if (seen.has(cur)) continue; seen.add(cur);
    const o = repo.objects.get(cur); if (!o || o.type !== 'commit') continue;
    for (const p of parseCommit(o.data).parents) stack.push(p);
  }
  return false;
}
// First common ancestor of two commits (nearest by BFS from both sides).
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancA = new Set<string>(); const qa = [a];
  while (qa.length) { const c = qa.pop() as string; if (ancA.has(c)) continue; ancA.add(c); const o = repo.objects.get(c); if (o && o.type === 'commit') for (const p of parseCommit(o.data).parents) qa.push(p); }
  const seen = new Set<string>(); const qb = [b];
  while (qb.length) { const c = qb.shift() as string; if (ancA.has(c)) return c; if (seen.has(c)) continue; seen.add(c); const o = repo.objects.get(c); if (o && o.type === 'commit') for (const p of parseCommit(o.data).parents) qb.push(p); }
  return null;
}
// Reachable objects from tips. depth limits commit generations (1 = tips only).
// boundary: commits treated as shallow leaves (parents not traversed).
function collectReachable(repo: Repo, tips: Iterable<string>, opts: { depth?: number; boundary?: Set<string> } = {}): { objects: Map<string, GitObj>; shallow: string[] } {
  const objects = new Map<string, GitObj>();
  const shallow: string[] = [];
  const queue: { oid: string; dist: number }[] = [];
  for (const t of tips) queue.push({ oid: t, dist: 0 });
  const seenCommit = new Set<string>();
  const addObj = (oid: string): GitObj | null => {
    const o = repo.objects.get(oid); if (!o) return null;
    if (!objects.has(oid)) objects.set(oid, o);
    return o;
  };
  const addTree = (treeOid: string): void => {
    const t = addObj(treeOid); if (!t || t.type !== 'tree') return;
    for (const e of parseTree(t.data)) {
      if (e.mode === '40000') addTree(e.oid);
      else addObj(e.oid);
    }
  };
  while (queue.length) {
    const { oid, dist } = queue.shift() as { oid: string; dist: number };
    if (seenCommit.has(oid)) continue;
    seenCommit.add(oid);
    const o = addObj(oid); if (!o) continue;
    if (o.type === 'tag') {
      const target = parseTag(o.data).object;
      const to = repo.objects.get(target);
      if (to && to.type === 'commit') queue.push({ oid: target, dist });
      else if (to) addObj(target);
      continue;
    }
    if (o.type !== 'commit') continue;
    const c = parseCommit(o.data);
    addTree(c.tree);
    const cut = opts.depth !== undefined && dist >= opts.depth - 1;
    // A client's current shallow boundary only stops traversal when it is
    // NOT deepening: with a deepen/depth request the server walks through
    // the old boundary up to the requested depth.
    const leaf = opts.depth === undefined && opts.boundary?.has(oid) === true;
    if (cut || leaf) { shallow.push(oid); continue; }
    for (const p of c.parents) queue.push({ oid: p, dist: dist + 1 });
  }
  return { objects, shallow };
}
function diffTrees(repo: Repo, baseFiles: Map<string, { oid: string; mode: string }> | null, headFiles: Map<string, { oid: string; mode: string }>): { path: string; status: string; additions: number; deletions: number }[] {
  const out: { path: string; status: string; additions: number; deletions: number }[] = [];
  const base = baseFiles ?? new Map();
  const paths = new Set([...base.keys(), ...headFiles.keys()]);
  const lineCount = (oid: string): number => {
    const o = repo.objects.get(oid); if (!o) return 0;
    const s = o.data.toString('utf8'); if (s === '') return 0;
    return s.split('\n').length - (s.endsWith('\n') ? 1 : 0);
  };
  for (const path of [...paths].sort()) {
    const b = base.get(path); const h = headFiles.get(path);
    if (b && !h) out.push({ path, status: 'removed', additions: 0, deletions: lineCount(b.oid) });
    else if (!b && h) out.push({ path, status: 'added', additions: lineCount(h.oid), deletions: 0 });
    else if (b && h && b.oid !== h.oid) out.push({ path, status: 'modified', additions: lineCount(h.oid), deletions: lineCount(b.oid) });
  }
  return out;
}
// Three-way merge check: returns {conflict: paths[]} or {tree: merged files}.
function squashMerge(repo: Repo, baseTip: string, headTip: string): { conflict: string[] } | { files: Map<string, { oid: string; mode: string }> } {
  const mb = mergeBase(repo, baseTip, headTip);
  const baseFiles = filesOfCommit(repo, baseTip) ?? new Map<string, { oid: string; mode: string }>();
  const headFiles = filesOfCommit(repo, headTip) ?? new Map<string, { oid: string; mode: string }>();
  const mbFiles = mb ? filesOfCommit(repo, mb) ?? new Map<string, { oid: string; mode: string }>() : new Map<string, { oid: string; mode: string }>();
  const conflict: string[] = [];
  const merged = new Map(baseFiles);
  const paths = new Set([...mbFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of paths) {
    const m = mbFiles.get(path); const b = baseFiles.get(path); const h = headFiles.get(path);
    const mOid = m?.oid ?? null; const bOid = b?.oid ?? null; const hOid = h?.oid ?? null;
    const baseChanged = bOid !== mOid; const headChanged = hOid !== mOid;
    if (headChanged && baseChanged && bOid !== hOid) { conflict.push(path); continue; }
    if (headChanged) { if (h) merged.set(path, h); else merged.delete(path); }
  }
  if (conflict.length) return { conflict };
  return { files: merged };
}
function doMerge(repo: Repo, pr: PullRec): { sha: string } | { conflict: string[] } {
  const baseTip = repo.refs.get(`refs/heads/${pr.base}`) ?? '';
  const headTip = repo.refs.get(`refs/heads/${pr.head}`) ?? '';
  if (!baseTip || !headTip) return { conflict: ['missing ref'] };
  const res = squashMerge(repo, baseTip, headTip);
  if ('conflict' in res) return res;
  const tree = buildTreeFromFiles(repo, res.files);
  const msg = `Merge pull request #${pr.number} from ${pr.head}`;
  const commitOid = putObj(repo, 'commit', buildCommit(tree, [baseTip], msg));
  repo.refs.set(`refs/heads/${pr.base}`, commitOid);
  const stamp = nextStamp();
  pr.state = 'closed'; pr.merged = true; pr.mergeSha = commitOid; pr.mergedAt = stamp.iso;
  return { sha: commitOid };
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------
const GIT_CAPS_V0_UP = 'side-band-64k thin-pack ofs-delta multi_ack_detailed shallow symref=HEAD:refs/heads/main agent=forge/1.0';
const GIT_CAPS_V0_RX = 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0';
function sortedRefs(repo: Repo): { name: string; oid: string }[] {
  const out: { name: string; oid: string }[] = [];
  for (const [name, oid] of repo.refs) out.push({ name, oid });
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return out;
}
function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? GIT_CAPS_V0_UP : GIT_CAPS_V0_RX;
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), pktFlush()];
  const refs = sortedRefs(repo);
  const lines: string[] = [];
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (headTip) lines.push(`${headTip} HEAD`);
  for (const r of refs) lines.push(`${r.oid} ${r.name}`);
  for (const r of refs) {
    if (r.name.startsWith('refs/tags/')) {
      const peeled = peelToCommit(repo, r.oid);
      if (peeled) lines.push(`${peeled} ${r.name}^{}`);
    }
  }
  if (lines.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    lines.forEach((line, i) => parts.push(pktLine(i === 0 ? `${line}\0${caps}\n` : `${line}\n`)));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}
function v2Advertisement(): Buffer {
  return pktLines(['version 2\n', 'agent=forge/1.0\n', 'ls-refs=unborn\n', 'fetch=shallow wait-for-done filter\n', 'server-option\n', 'object-format=sha1\n', 'flush']);
}
function lsRefsResponse(repo: Repo, args: { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] }): Buffer {
  const lines: string[] = [];
  const keep = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((p) => name.startsWith(p));
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    if (args.unborn && keep('HEAD')) lines.push(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}`);
  } else {
    if (headTip && keep('HEAD')) lines.push(`${headTip} HEAD symref-target:refs/heads/${repo.defaultBranch}`);
    for (const r of refs) {
      if (!keep(r.name)) continue;
      let line = `${r.oid} ${r.name}`;
      if (args.peel && r.name.startsWith('refs/tags/')) {
        const peeled = peelToCommit(repo, r.oid);
        if (peeled) line += ` peeled:${peeled}`;
      }
      lines.push(line);
    }
  }
  const parts = lines.map((l) => pktLine(`${l}\n`));
  parts.push(pktFlush());
  return Buffer.concat(parts);
}
function sidebandPack(pack: Buffer | null): Buffer[] {
  if (!pack || pack.length === 0) return [];
  const out: Buffer[] = [];
  for (let off = 0; off < pack.length; off += 60000) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 60000));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  return out;
}
interface FetchArgs {
  wants: string[]; haves: string[]; shallow: string[]; depth: number | null;
  deepenSince: number | null; deepenNot: string[]; wantRefs: string[];
  deepenRelative: boolean;
}
// BFS distance (parent edges) from a tip to the nearest commit in boundary.
function distanceToBoundary(repo: Repo, tip: string, boundary: Set<string>): number | null {
  const seen = new Set<string>();
  const queue: { oid: string; dist: number }[] = [{ oid: tip, dist: 0 }];
  while (queue.length) {
    const { oid, dist } = queue.shift() as { oid: string; dist: number };
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (boundary.has(oid)) return dist;
    const o = repo.objects.get(oid); if (!o) continue;
    if (o.type === 'tag') { queue.push({ oid: parseTag(o.data).object, dist }); continue; }
    if (o.type !== 'commit') continue;
    for (const p of parseCommit(o.data).parents) queue.push({ oid: p, dist: dist + 1 });
  }
  return null;
}
function computeFetch(repo: Repo, a: FetchArgs): { acks: string[]; shallow: string[]; unshallow: string[]; pack: Buffer | null; wantedRefs: { oid: string; ref: string }[] } {
  const wantedRefs: { oid: string; ref: string }[] = [];
  for (const w of a.wants) {
    for (const [name, oid] of repo.refs) if (oid === w) wantedRefs.push({ oid: w, ref: name });
  }
  const acks: string[] = [];
  for (const h of a.haves) {
    if (a.wants.some((w) => isAncestor(repo, h, w))) acks.push(h);
  }
  const boundary = new Set(a.shallow);
  // Real git sends "deepen N" as an ADDITIONAL depth plus a separate
  // "deepen-relative" line; the kit client sends a TOTAL depth with no
  // deepen-relative line. Reconcile: effective total depth = (distance
  // from the want to the nearest client shallow boundary) + N + 1.
  let depth = a.depth ?? undefined;
  if (a.depth !== null && a.deepenRelative && a.shallow.length > 0) {
    let maxDist = 0; let found = false;
    for (const w of a.wants) {
      const d = distanceToBoundary(repo, w, boundary);
      if (d !== null) { found = true; if (d > maxDist) maxDist = d; }
    }
    if (found) depth = maxDist + a.depth + 1;
  }
  const { objects, shallow } = collectReachable(repo, a.wants, { depth, boundary });
  const held = collectReachable(repo, a.haves, { boundary }).objects;
  const send = new Map<string, GitObj>();
  for (const [oid, o] of objects) if (!held.has(oid)) send.set(oid, o);
  const unshallow: string[] = [];
  if (a.shallow.length) {
    for (const s of a.shallow) {
      if (objects.has(s) && !shallow.includes(s)) unshallow.push(s);
    }
  }
  const pack = send.size ? writePack([...send.entries()].map(([oid, o]) => ({ ...o, oid }))) : null;
  return { acks, shallow, unshallow, pack, wantedRefs };
}
function fetchResponseV2(repo: Repo, a: FetchArgs): Buffer {
  const { acks, shallow, unshallow, pack, wantedRefs } = computeFetch(repo, a);
  const parts: Buffer[] = [];
  // Protocol v2: the acknowledgments section is sent only when the client
  // sent 'have' lines; wanted-refs only when it sent 'want-ref' lines.
  // Real git dies ("expected 'packfile'") if either appears unprompted.
  if (a.haves.length) {
    parts.push(pktLine('acknowledgments\n'));
    if (acks.length) { for (const ack of acks) parts.push(pktLine(`ACK ${ack}\n`)); parts.push(pktLine('ready\n')); }
    else parts.push(pktLine('NAK\n'));
    parts.push(pktDelim());
  }
  if (a.depth !== null || a.shallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(pktDelim());
  }
  if (a.wantRefs.length && wantedRefs.length) {
    parts.push(pktLine('wanted-refs\n'));
    for (const w of wantedRefs) parts.push(pktLine(`${w.oid} ${w.ref}\n`));
    parts.push(pktDelim());
  }
  if (pack) {
    parts.push(pktLine('packfile\n'));
    parts.push(...sidebandPack(pack));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}
function fetchResponseV0(repo: Repo, a: FetchArgs): Buffer {
  const { acks, shallow, unshallow, pack } = computeFetch(repo, a);
  const parts: Buffer[] = [];
  if (acks.length) for (const ack of acks) parts.push(pktLine(`ACK ${ack}\n`));
  else parts.push(pktLine('NAK\n'));
  for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
  parts.push(...sidebandPack(pack));
  parts.push(pktFlush());
  return Buffer.concat(parts);
}
function parseFetchArgs(lines: string[]): FetchArgs {
  const a: FetchArgs = { wants: [], haves: [], shallow: [], depth: null, deepenSince: null, deepenNot: [], wantRefs: [], deepenRelative: false };
  for (const line of lines) {
    const t = line.trim();
    if (t.startsWith('want ')) a.wants.push(t.slice(5).split(' ')[0] as string);
    else if (t.startsWith('want-ref ')) a.wantRefs.push(t.slice(9).trim());
    else if (t.startsWith('have ')) a.haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) a.shallow.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) { const n = parseInt(t.slice(7), 10); if (Number.isFinite(n)) a.depth = n; }
    else if (t === 'deepen-relative') a.deepenRelative = true;
    else if (t.startsWith('deepen-since ')) { const n = parseInt(t.slice(13), 10); if (Number.isFinite(n)) a.deepenSince = n; }
    else if (t.startsWith('deepen-not ')) a.deepenNot.push(t.slice(11).trim());
  }
  return a;
}
function gitTextLines(buf: Buffer): string[] {
  return parsePktLines(buf).filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
}
interface PushCommand { oldOid: string; newOid: string; ref: string }
function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const packets = parsePktLines(body);
  const commands: PushCommand[] = [];
  let packStart = body.length;
  for (let i = 0; i < packets.length; i++) {
    const p = packets[i] as Pkt;
    if (p.kind === 'flush') {
      // pack bytes follow the flush packet: recompute offset by walking
      let off = 0;
      for (let j = 0; j <= i; j++) {
        const q = packets[j] as Pkt;
        off += 4 + (q.kind === 'data' ? q.payload.length : 0);
      }
      packStart = off;
      break;
    }
    if (p.kind !== 'data') continue;
    const text = p.payload.toString('utf8').replace(/\n$/, '');
    const nul = text.indexOf('\0');
    const cmdText = nul >= 0 ? text.slice(0, nul) : text;
    const parts = cmdText.split(' ');
    if (parts.length >= 3 && isOid(parts[0] as string) && isOid(parts[1] as string)) {
      commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
    }
  }
  let unpackOk = true;
  const packBytes = body.subarray(packStart);
  if (packBytes.length > 0) {
    try {
      for (const e of readPack(packBytes, (oid) => repo.objects.get(oid))) {
        if (!repo.objects.has(e.oid)) repo.objects.set(e.oid, { type: e.type, data: e.data });
      }
    } catch {
      unpackOk = false;
    }
  } else if (commands.some((c) => c.newOid !== ZERO_OID)) {
    unpackOk = false;
  }
  const reportLines: string[] = [unpackOk ? 'unpack ok\n' : 'unpack error\n'];
  for (const c of commands) {
    let ok = false; let reason = '';
    if (!unpackOk) { reason = 'unpack error'; }
    else {
      const cur = repo.refs.get(c.ref);
      if (c.newOid === ZERO_OID) {
        if (!cur) reason = 'remote ref does not exist';
        else if (c.oldOid !== ZERO_OID && c.oldOid !== cur) reason = 'non-fast-forward';
        else { repo.refs.delete(c.ref); ok = true; }
      } else if (!repo.objects.has(c.newOid)) {
        reason = 'object not found';
      } else if (!cur) {
        if (c.oldOid !== ZERO_OID) reason = 'non-fast-forward';
        else { repo.refs.set(c.ref, c.newOid); ok = true; }
      } else if (c.oldOid !== cur) {
        reason = 'non-fast-forward';
      } else if (c.newOid === cur || isAncestor(repo, cur, c.newOid)) {
        repo.refs.set(c.ref, c.newOid); ok = true;
      } else reason = 'non-fast-forward';
    }
    reportLines.push(ok ? `ok ${c.ref}\n` : `ng ${c.ref} ${reason}\n`);
  }
  // report-status over side-band-64k: the band-1 payload is itself a
  // pkt-line stream ("unpack ok\n", "ok <ref>\n" / "ng <ref> <reason>\n").
  // Real git demuxes the sideband and then reads those pkt-lines; raw
  // text here makes it die with "bad line length character: unpa".
  // git's own receive-pack also appends a flush INSIDE the band-1
  // payload (packet_buf_flush before send_sideband) and then a bare
  // flush after it; without the inner flush the client's packet_reader
  // hits EOF after the last report line and dies with
  // "the remote end hung up unexpectedly".
  const inner = Buffer.concat([pktLines(reportLines.map((l) => l as string)), pktFlush()]);
  const bandParts: Buffer[] = [];
  for (let off = 0; off < inner.length; off += 60000) {
    bandParts.push(pktLine(Buffer.concat([Buffer.from([1]), inner.subarray(off, Math.min(inner.length, off + 60000))])));
  }
  return Buffer.concat([...bandParts, pktFlush()]);
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------
interface ReqCtx {
  method: string; segs: string[]; query: URLSearchParams; host: string;
  body: unknown; bodyRaw: Buffer; authed: boolean;
}
function reqId(): string { return `req-${++reqCounter}`; }
function jsonBody(res: http.ServerResponse, status: number, obj: unknown, extra: Record<string, string> = {}): void {
  const text = status === 204 ? '' : JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json', 'x-github-request-id': reqId(), ...extra });
  res.end(text);
}
function errJson(res: http.ServerResponse, status: number, message: string): void {
  jsonBody(res, status, { message });
}
function isoOfSeq(seq: number): string { return new Date((TRIAL_NOW_MS / 1000 + seq) * 1000).toISOString(); }
function repoJson(r: Repo): Record<string, unknown> {
  const stamp = isoOfSeq(r.createdSeq);
  return {
    id: r.dbId, node_id: globalId('R', r.dbId), name: r.name, full_name: `${r.owner}/${r.name}`,
    owner: { login: r.owner, id: VIEWER.id, type: 'User' },
    private: r.isPrivate, description: r.description, default_branch: r.defaultBranch,
    html_url: `https://example.invalid/${r.owner}/${r.name}`, url: `/api/v3/repos/${r.owner}/${r.name}`,
    created_at: stamp, updated_at: stamp, pushed_at: stamp,
    has_issues: true, has_projects: false, has_wiki: false, fork: false, archived: false,
    open_issues_count: [...r.issues.values()].filter((i) => i.state === 'open').length,
  };
}
function issueJson(r: Repo, i: IssueRec): Record<string, unknown> {
  return {
    id: i.dbId, node_id: globalId('I', r.dbId, i.number), number: i.number,
    title: i.title, body: i.body, state: i.state,
    labels: i.labels.map((name) => ({ name, color: r.labels.get(name)?.color ?? 'ededed' })),
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    created_at: i.createdAt, updated_at: i.updatedAt,
    url: `/api/v3/repos/${r.owner}/${r.name}/issues/${i.number}`,
    html_url: `https://example.invalid/${r.owner}/${r.name}/issues/${i.number}`,
    comments: i.comments.length,
  };
}
function prMergeable(r: Repo, p: PullRec): string {
  if (p.merged) return 'MERGEABLE';
  const baseTip = r.refs.get(`refs/heads/${p.base}`) ?? '';
  const headTip = r.refs.get(`refs/heads/${p.head}`) ?? '';
  if (!baseTip || !headTip) return 'UNKNOWN';
  const res = squashMerge(r, baseTip, headTip);
  return 'conflict' in res ? 'CONFLICTING' : 'MERGEABLE';
}
function pullJson(r: Repo, p: PullRec): Record<string, unknown> {
  const stamp = isoOfSeq(p.seq);
  return {
    id: p.seq, node_id: globalId('P', r.dbId, p.number), number: p.number,
    title: p.title, body: p.body, state: p.state,
    head: { ref: p.head, sha: p.headSha, label: `${r.owner}:${p.head}`, user: { login: r.owner } },
    base: { ref: p.base, sha: p.baseSha, label: `${r.owner}:${p.base}`, user: { login: r.owner } },
    merged: p.merged, mergeable: prMergeable(r, p), merge_commit_sha: p.mergeSha, merged_at: p.mergedAt,
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    created_at: stamp, updated_at: stamp,
    url: `/api/v3/repos/${r.owner}/${r.name}/pulls/${p.number}`,
    html_url: `https://example.invalid/${r.owner}/${r.name}/pulls/${p.number}`,
  };
}
function paginate<T>(items: T[], query: URLSearchParams): { page: T[]; total: number; perPage: number; pageNum: number } {
  const perPage = Math.max(1, Math.min(100, parseInt(query.get('per_page') ?? '30', 10) || 30));
  const pageNum = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), total: items.length, perPage, pageNum };
}
function pageLink(host: string, path: string, query: URLSearchParams, perPage: number, pageNum: number, total: number): string | null {
  if (pageNum * perPage >= total) return null;
  const q = new URLSearchParams(query); q.set('per_page', String(perPage)); q.set('page', String(pageNum + 1));
  return `<http://${host}${path}?${q.toString()}>; rel="next"`;
}
// Commit a file-map change on a branch; returns the new commit oid.
function commitOnBranch(r: Repo, branch: string, files: Map<string, { oid: string; mode: string }>, message: string): string {
  const tree = buildTreeFromFiles(r, files);
  const tip = r.refs.get(`refs/heads/${branch}`);
  const parents = tip ? [tip] : [];
  const commitOid = putObj(r, 'commit', buildCommit(tree, parents, message));
  r.refs.set(`refs/heads/${branch}`, commitOid);
  return commitOid;
}
function handleRest(ctx: ReqCtx, res: http.ServerResponse): void {
  const { method, segs, query } = ctx;
  const body = (ctx.body ?? {}) as Record<string, unknown>;
  // Root / meta / user
  if (segs.length === 0 && method === 'GET') {
    jsonBody(res, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}', meta: { installed_version: '1.0.0' } }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (segs.length === 1 && segs[0] === 'meta' && method === 'GET') {
    jsonBody(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: false, github_services_sha: '0000000000000000000000000000000000000000', hook_deliveries: [] });
    return;
  }
  if (segs.length === 1 && segs[0] === 'user' && method === 'GET') {
    jsonBody(res, 200, { login: VIEWER.login, id: VIEWER.id, node_id: globalId('U', VIEWER.id), name: VIEWER.name, email: VIEWER.email, type: 'User' });
    return;
  }
  if (segs.length === 2 && segs[0] === 'user' && segs[1] === 'repos') {
    if (method === 'GET') {
      const all = [...repos.values()].filter((r) => r.owner === VIEWER.login).sort((a, b) => a.createdSeq - b.createdSeq);
      const { page, total, perPage, pageNum } = paginate(all.map(repoJson), query);
      const link = pageLink(ctx.host, '/api/v3/user/repos', query, perPage, pageNum, total);
      jsonBody(res, 200, page, link ? { link } : {});
      return;
    }
    if (method === 'POST') {
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (!name) { errJson(res, 422, 'name is required'); return; }
      if (repos.has(repoKey(VIEWER.login, name))) { errJson(res, 422, `Repository ${VIEWER.login}/${name} already exists`); return; }
      const r = createRepo(name, body.private === true, typeof body.description === 'string' ? body.description : '');
      jsonBody(res, 201, repoJson(r));
      return;
    }
  }
  // Repository-scoped routes
  if (segs.length >= 3 && segs[0] === 'repos') {
    const owner = decodeURIComponent(segs[1] as string);
    const name = decodeURIComponent(segs[2] as string);
    const repo = getRepo(owner, name);
    if (!repo) { errJson(res, 404, 'Not Found'); return; }
    const rest = segs.slice(3);
    // /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') { jsonBody(res, 200, repoJson(repo)); return; }
      if (method === 'PATCH') {
        if (typeof body.description === 'string') repo.description = body.description;
        jsonBody(res, 200, repoJson(repo)); return;
      }
      if (method === 'DELETE') { repos.delete(repoKey(owner, name)); jsonBody(res, 204, null); return; }
      errJson(res, 404, 'Not Found'); return;
    }
    // branches
    if (rest[0] === 'branches' && method === 'GET') {
      if (rest.length === 1) {
        const list = [...repo.refs.keys()].filter((n) => n.startsWith('refs/heads/')).sort().map((n) => ({ name: n.slice('refs/heads/'.length), commit: { sha: repo.refs.get(n) }, protected: false }));
        jsonBody(res, 200, list); return;
      }
      const branch = rest.slice(1).map(decodeURIComponent).join('/');
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (!sha) { errJson(res, 404, 'Not Found'); return; }
      jsonBody(res, 200, { name: branch, commit: { sha }, protected: false }); return;
    }
    // git refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST') {
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) { errJson(res, 422, 'Invalid ref or sha'); return; }
        if (repo.refs.has(ref)) { errJson(res, 422, 'Reference already exists'); return; }
        repo.refs.set(ref, sha);
        jsonBody(res, 201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } }); return;
      }
      if (method === 'GET' && rest.length > 2) {
        const ref = rest.slice(2).map(decodeURIComponent).join('/');
        const sha = repo.refs.get(ref);
        if (!sha) { errJson(res, 404, 'Not Found'); return; }
        jsonBody(res, 200, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' } }); return;
      }
      errJson(res, 404, 'Not Found'); return;
    }
    // commits
    if (rest[0] === 'commits' && method === 'GET') {
      const refParam = query.get('sha') ?? repo.defaultBranch;
      const tip = resolveRef(repo, refParam);
      if (!tip) { errJson(res, 404, 'Not Found'); return; }
      const out: Record<string, unknown>[] = [];
      const seen = new Set<string>(); const stack = [tip];
      while (stack.length) {
        const cur = stack.shift() as string;
        if (seen.has(cur)) continue; seen.add(cur);
        const o = repo.objects.get(cur); if (!o || o.type !== 'commit') continue;
        const c = parseCommit(o.data);
        const parseIdent = (s: string): { name: string; email: string; date: string } => {
          const m = /^([^<]*?) <([^>]*)> (\d+) [+-]\d{4}$/.exec(s.trim());
          if (!m) return { name: VIEWER.name, email: VIEWER.email, date: isoOfSeq(0) };
          return { name: (m[1] as string).trim() || VIEWER.name, email: m[2] as string, date: new Date(Number(m[3]) * 1000).toISOString() };
        };
        const author = parseIdent(c.author); const committer = parseIdent(c.committer);
        out.push({ sha: cur, node_id: globalId('C', cur), commit: { message: c.message, author, committer }, author: { login: VIEWER.login }, committer: { login: VIEWER.login } });
        for (const p of c.parents) stack.push(p);
      }
      jsonBody(res, 200, out); return;
    }
    // contents
    if (rest[0] === 'contents') {
      const path = rest.slice(1).map(decodeURIComponent).join('/');
      const refParam = query.get('ref') ?? repo.defaultBranch;
      if (method === 'GET') {
        const tip = resolveRef(repo, refParam);
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        const files = filesOfCommit(repo, tip);
        if (!files) { errJson(res, 404, 'Not Found'); return; }
        if (path === '') {
          const entries: Record<string, unknown>[] = [];
          const seen = new Set<string>();
          for (const p of [...files.keys()].sort()) {
            const top = p.split('/')[0] as string;
            if (seen.has(top)) continue; seen.add(top);
            const isDir = [...files.keys()].some((q) => q.startsWith(`${top}/`));
            if (isDir) entries.push({ type: 'dir', name: top, path: top, sha: '' });
            else { const f = files.get(p) as { oid: string }; entries.push({ type: 'file', name: top, path: top, sha: f.oid, size: repo.objects.get(f.oid)?.data.length ?? 0 }); }
          }
          jsonBody(res, 200, entries); return;
        }
        const file = files.get(path);
        if (file) {
          const data = repo.objects.get(file.oid)?.data ?? Buffer.alloc(0);
          jsonBody(res, 200, { type: 'file', encoding: 'base64', content: b64enc(data), sha: file.oid, size: data.length, name: path.split('/').pop(), path });
          return;
        }
        const prefix = `${path}/`;
        const children = [...files.keys()].filter((p) => p.startsWith(prefix));
        if (children.length) {
          const entries: Record<string, unknown>[] = [];
          const seen = new Set<string>();
          for (const p of children.sort()) {
            const rel = p.slice(prefix.length); const top = rel.split('/')[0] as string;
            if (seen.has(top)) continue; seen.add(top);
            const isDir = rel.includes('/');
            if (isDir) entries.push({ type: 'dir', name: top, path: `${path}/${top}`, sha: '' });
            else { const f = files.get(p) as { oid: string }; entries.push({ type: 'file', name: top, path: p, sha: f.oid, size: repo.objects.get(f.oid)?.data.length ?? 0 }); }
          }
          jsonBody(res, 200, entries); return;
        }
        errJson(res, 404, 'Not Found'); return;
      }
      if (method === 'PUT') {
        const contentB64 = typeof body.content === 'string' ? body.content : '';
        if (!contentB64) { errJson(res, 422, 'content is required'); return; }
        const data = b64dec(contentB64);
        const message = typeof body.message === 'string' ? body.message : `Update ${path}`;
        const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
        let tip = repo.refs.get(`refs/heads/${branch}`);
        if (!tip) {
          const defTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
          if (defTip) repo.refs.set(`refs/heads/${branch}`, defTip);
          tip = repo.refs.get(`refs/heads/${branch}`);
        }
        const files = tip ? filesOfCommit(repo, tip) ?? new Map<string, { oid: string; mode: string }>() : new Map<string, { oid: string; mode: string }>();
        const existing = files.get(path);
        const shaParam = typeof body.sha === 'string' ? body.sha : undefined;
        if (existing && shaParam && shaParam.toLowerCase() !== existing.oid.toLowerCase()) { errJson(res, 409, 'sha does not match'); return; }
        const blobOid = putObj(repo, 'blob', data);
        files.set(path, { oid: blobOid, mode: '100644' });
        const commitOid = commitOnBranch(repo, branch, files, message);
        jsonBody(res, existing ? 200 : 201, { content: { name: path.split('/').pop(), path, sha: blobOid, encoding: 'base64', size: data.length }, commit: { sha: commitOid } });
        return;
      }
      if (method === 'DELETE') {
        const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        const files = filesOfCommit(repo, tip) ?? new Map<string, { oid: string; mode: string }>();
        const existing = files.get(path);
        if (!existing) { errJson(res, 404, 'Not Found'); return; }
        const shaParam = typeof body.sha === 'string' ? body.sha : undefined;
        if (shaParam && shaParam.toLowerCase() !== existing.oid.toLowerCase()) { errJson(res, 409, 'sha does not match'); return; }
        files.delete(path);
        const message = typeof body.message === 'string' ? body.message : `Delete ${path}`;
        const commitOid = commitOnBranch(repo, branch, files, message);
        jsonBody(res, 200, { commit: { sha: commitOid } });
        return;
      }
      errJson(res, 404, 'Not Found'); return;
    }
    // labels
    if (rest[0] === 'labels' && method === 'POST') {
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (!name) { errJson(res, 422, 'name is required'); return; }
      const color = typeof body.color === 'string' ? body.color : 'ededed';
      if (!repo.labels.has(name)) repo.labels.set(name, { name, color });
      const label = repo.labels.get(name) as { name: string; color: string };
      jsonBody(res, 201, { name: label.name, color: label.color, id: nextGlobalId++ }); return;
    }
    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          if (sort === 'created') list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          const { page } = paginate(list.map((i) => issueJson(repo, i)), query);
          jsonBody(res, 200, page); return;
        }
        if (method === 'POST') {
          const title = typeof body.title === 'string' ? body.title : '';
          if (!title) { errJson(res, 422, 'title is required'); return; }
          const labels = Array.isArray(body.labels) ? (body.labels as unknown[]).map((l) => String(l)) : [];
          for (const l of labels) if (!repo.labels.has(l)) { errJson(res, 422, `Label "${l}" does not exist`); return; }
          const stamp = nextStamp();
          const issue: IssueRec = {
            number: repo.nextNumber++, title, body: typeof body.body === 'string' ? body.body : '',
            state: 'open', labels, seq: tick, dbId: nextGlobalId++, createdAt: stamp.iso, updatedAt: stamp.iso, comments: [],
          };
          repo.issues.set(issue.number, issue);
          jsonBody(res, 201, issueJson(repo, issue)); return;
        }
      }
      const num = parseInt(rest[1] as string, 10);
      const issue = repo.issues.get(num);
      if (rest.length === 2) {
        if (!issue) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'GET') { jsonBody(res, 200, issueJson(repo, issue)); return; }
        if (method === 'PATCH') {
          if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
          if (typeof body.title === 'string') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          issue.updatedAt = nextStamp().iso;
          jsonBody(res, 200, issueJson(repo, issue)); return;
        }
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (!issue) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'GET') {
          jsonBody(res, 200, issue.comments.map((c) => ({ id: c.id, node_id: globalId('CM', repo.dbId, issue.number, c.id), body: c.body, user: { login: VIEWER.login }, created_at: c.createdAt })));
          return;
        }
        if (method === 'POST') {
          const cb = typeof body.body === 'string' ? body.body : '';
          if (!cb) { errJson(res, 422, 'body is required'); return; }
          const comment = { id: repo.nextCommentId++, body: cb, createdAt: nextStamp().iso };
          issue.comments.push(comment);
          jsonBody(res, 201, { id: comment.id, node_id: globalId('CM', repo.dbId, issue.number, comment.id), body: comment.body, user: { login: VIEWER.login }, created_at: comment.createdAt });
          return;
        }
      }
      errJson(res, 404, 'Not Found'); return;
    }
    // pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.pulls.values()];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          list.sort((a, b) => b.seq - a.seq);
          const { page } = paginate(list.map((p) => pullJson(repo, p)), query);
          jsonBody(res, 200, page); return;
        }
        if (method === 'POST') {
          const head = typeof body.head === 'string' ? body.head : '';
          const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
          const title = typeof body.title === 'string' ? body.title : '';
          if (!head || !title) { errJson(res, 422, 'head and title are required'); return; }
          const headSha = repo.refs.get(`refs/heads/${head}`);
          const baseSha = repo.refs.get(`refs/heads/${base}`);
          if (!headSha || !baseSha) { errJson(res, 422, 'head or base branch does not exist'); return; }
          const dup = [...repo.pulls.values()].find((p) => p.state === 'open' && p.head === head && p.base === base);
          if (dup) { errJson(res, 422, 'A pull request already exists for this head and base'); return; }
          const pr: PullRec = {
            number: repo.nextNumber++, title, body: typeof body.body === 'string' ? body.body : '',
            state: 'open', head, base, headSha, baseSha, merged: false, mergeSha: null, mergedAt: null, seq: tick,
          };
          repo.pulls.set(pr.number, pr);
          jsonBody(res, 201, pullJson(repo, pr)); return;
        }
      }
      const num = parseInt(rest[1] as string, 10);
      const pr = repo.pulls.get(num);
      if (rest.length === 2 && method === 'GET') {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        jsonBody(res, 200, pullJson(repo, pr)); return;
      }
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        const baseFiles = filesOfCommit(repo, pr.baseSha);
        const headFiles = filesOfCommit(repo, pr.headSha) ?? new Map<string, { oid: string; mode: string }>();
        const files = diffTrees(repo, baseFiles, headFiles);
        jsonBody(res, 200, files.map((f) => ({ filename: f.path, status: f.status, additions: f.additions, deletions: f.deletions, changes: f.additions + f.deletions })));
        return;
      }
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        if (pr.merged || pr.state === 'closed') { errJson(res, 405, 'Pull request is already merged or closed'); return; }
        const res2 = doMerge(repo, pr);
        if ('conflict' in res2) { errJson(res, 405, 'Merge conflict'); return; }
        jsonBody(res, 200, { sha: res2.sha, merged: true, message: `Pull request #${pr.number} merged` });
        return;
      }
      errJson(res, 404, 'Not Found'); return;
    }
    errJson(res, 404, 'Not Found'); return;
  }
  errJson(res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// GraphQL: a small parser for the documents gh / github-mcp-server send,
// plus an executor over the same store as REST.
// ---------------------------------------------------------------------------
type GqlValue = string | number | boolean | null | GqlValue[] | { [k: string]: GqlValue };
interface GqlField {
  alias: string; name: string; args: Record<string, GqlValue>;
  selections: GqlField[] | null; fragmentType: string | null;
}
interface GqlDoc { operation: 'query' | 'mutation'; name: string | null; selections: GqlField[]; fragments: Map<string, { type: string; selections: GqlField[] }> }
function tokenizeGql(src: string): string[] {
  const toks: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (/\s/.test(c) || c === ',') { i++; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '.' && src.slice(i, i + 3) === '...') { toks.push('...'); i += 3; continue; }
    if ('{}():![]=$'.includes(c)) { toks.push(c); i++; continue; }
    if (c === '"') {
      let j = i + 1; let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) { const e = src[j + 1]; out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e; j += 2; }
        else { out += src[j]; j++; }
      }
      toks.push(JSON.stringify(out)); i = j + 1; continue;
    }
    let j = i;
    while (j < src.length && /[A-Za-z0-9_.-]/.test(src[j] as string)) j++;
    if (j === i) { i++; continue; }
    toks.push(src.slice(i, j)); i = j;
  }
  return toks;
}
class GqlParser {
  toks: string[]; pos = 0; vars: Record<string, GqlValue>;
  constructor(src: string, vars: Record<string, GqlValue>) { this.toks = tokenizeGql(src); this.vars = vars; }
  peek(): string { return this.toks[this.pos] ?? ''; }
  next(): string { return this.toks[this.pos++] ?? ''; }
  expect(t: string): void { if (this.next() !== t) throw new Error(`expected ${t}`); }
  parseValue(): GqlValue {
    const t = this.next();
    if (t === '$') { const name = this.next(); return this.vars[name] ?? null; }
    if (t === '{') {
      const obj: Record<string, GqlValue> = {};
      while (this.peek() !== '}') { const k = this.next(); this.expect(':'); obj[k] = this.parseValue(); }
      this.expect('}'); return obj;
    }
    if (t === '[') {
      const arr: GqlValue[] = [];
      while (this.peek() !== ']') arr.push(this.parseValue());
      this.expect(']'); return arr;
    }
    if (t.startsWith('"')) return JSON.parse(t) as string;
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === 'null') return null;
    const n = Number(t);
    if (t !== '' && Number.isFinite(n) && /^-?\d+(\.\d+)?$/.test(t)) return n;
    return t; // enum
  }
  parseArgs(): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    if (this.peek() !== '(') return args;
    this.expect('(');
    while (this.peek() !== ')') { const k = this.next(); this.expect(':'); args[k] = this.parseValue(); }
    this.expect(')');
    return args;
  }
  parseSelections(fragments: Map<string, { type: string; selections: GqlField[] }>): GqlField[] {
    this.expect('{');
    const out: GqlField[] = [];
    while (this.peek() !== '}' && this.pos < this.toks.length) {
      if (this.peek() === '...') {
        this.next();
        const name = this.next();
        if (name === 'on') {
          const type = this.next();
          const sels = this.parseSelections(fragments);
          out.push({ alias: '', name: '', args: {}, selections: sels, fragmentType: type });
        } else {
          const frag = fragments.get(name);
          if (frag) out.push({ alias: '', name: '', args: {}, selections: frag.selections, fragmentType: frag.type });
          else throw new Error(`unknown fragment ${name}`);
        }
        continue;
      }
      let alias = ''; let name = this.next();
      if (this.peek() === ':') { this.next(); alias = name; name = this.next(); }
      const args = this.parseArgs();
      let sels: GqlField[] | null = null;
      if (this.peek() === '{') sels = this.parseSelections(fragments);
      out.push({ alias: alias || name, name, args, selections: sels, fragmentType: null });
    }
    this.expect('}');
    return out;
  }
  parseDocument(): GqlDoc {
    const fragments = new Map<string, { type: string; selections: GqlField[] }>();
    let operation: 'query' | 'mutation' = 'query'; let name: string | null = null;
    while (this.pos < this.toks.length) {
      const t = this.peek();
      if (t === 'fragment') {
        this.next(); const fname = this.next(); this.expect('on'); const ftype = this.next();
        fragments.set(fname, { type: ftype, selections: this.parseSelections(fragments) });
        continue;
      }
      if (t === 'query' || t === 'mutation') {
        operation = this.next() as 'query' | 'mutation';
        if (this.peek() !== '{' && this.peek() !== '(') name = this.next();
        if (this.peek() === '(') {
          // variable definitions: skip them (values come from `variables`)
          let depth = 0;
          while (this.pos < this.toks.length) {
            const tk = this.next();
            if (tk === '(') depth++;
            else if (tk === ')') { depth--; if (depth === 0) break; }
          }
        }
        const sels = this.parseSelections(fragments);
        return { operation, name, selections: sels, fragments };
      }
      if (t === '{') return { operation, name, selections: this.parseSelections(fragments), fragments };
      this.next();
    }
    throw new Error('empty document');
  }
}
const GQL_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  User: ['login', 'id', 'name', 'email', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'url', 'createdAt', 'updatedAt'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'labels', 'author'],
  PullRequest: ['id', 'number', 'title', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'body', 'url', 'createdAt'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'filename', 'additions', 'deletions', 'changes', 'status'],
  Ref: ['name'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'endCursor', 'startCursor'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'inputFields'],
  __Field: ['name', 'description', 'type'],
  __EnumValue: ['name', 'description'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  IssueCommentEdge: ['node', 'cursor'],
  IssueComment: ['id', 'body', 'author', 'createdAt'],
  __Schema: ['types', 'queryType', 'mutationType'],
};
const INTROSPECTION: Record<string, { kind: string; fields?: string[]; enumValues?: string[] }> = {
  Issue: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'labels', 'author', 'comments'] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'body', 'url', 'createdAt'] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'url', 'createdAt'] },
  User: { kind: 'OBJECT', fields: ['login', 'id', 'name', 'email', 'url'] },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'] },
  IssueState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enumValues: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'] },
  OrderDirection: { kind: 'ENUM', enumValues: ['ASC', 'DESC'] },
  IssueOrderField: { kind: 'ENUM', enumValues: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'] },
};
type GqlNode =
  | { kind: 'Query' } | { kind: 'Mutation' }
  | { kind: 'User'; login: string }
  | { kind: 'Repository'; repo: Repo }
  | { kind: 'Issue'; repo: Repo; issue: IssueRec }
  | { kind: 'PullRequest'; repo: Repo; pr: PullRec }
  | { kind: 'IssueConnection'; repo: Repo; issues: IssueRec[]; hasNext: boolean; endCursor: string | null }
  | { kind: 'PullRequestConnection'; repo: Repo; prs: PullRec[] }
  | { kind: 'ChangedFileConnection'; files: { path: string; status: string; additions: number; deletions: number }[] }
  | { kind: 'ChangedFile'; file: { path: string; status: string; additions: number; deletions: number } }
  | { kind: 'Ref'; name: string }
  | { kind: 'PageInfo'; hasNext: boolean; endCursor: string | null }
  | { kind: 'Type'; name: string }
  | { kind: 'Payload'; field: string; value: GqlNode | null }
  | { kind: 'CommentEdge'; repo: Repo; issue: IssueRec; comment: { id: number; body: string; createdAt: string } }
  | { kind: 'Comment'; repo: Repo; issue: IssueRec; comment: { id: number; body: string; createdAt: string } };
function gqlTypeOf(node: GqlNode): string {
  switch (node.kind) {
    case 'Query': return 'Query';
    case 'Mutation': return 'Mutation';
    case 'User': return 'User';
    case 'Repository': return 'Repository';
    case 'Issue': return 'Issue';
    case 'PullRequest': return 'PullRequest';
    case 'IssueConnection': return 'IssueConnection';
    case 'PullRequestConnection': return 'PullRequestConnection';
    case 'ChangedFileConnection': return 'PullRequestChangedFileConnection';
    case 'ChangedFile': return 'PullRequestChangedFile';
    case 'Ref': return 'Ref';
    case 'PageInfo': return 'PageInfo';
    case 'Type': return '__Type';
    case 'Payload': return node.field === 'issue' ? 'CreateIssuePayload' : node.field === 'pullRequest' ? 'CreatePullRequestPayload' : 'AddCommentPayload';
    case 'CommentEdge': return 'IssueCommentEdge';
    case 'Comment': return 'IssueComment';
  }
}
function issueStateGql(i: IssueRec): string { return i.state === 'open' ? 'OPEN' : 'CLOSED'; }
function prStateGql(p: PullRec): string { return p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED'; }
function cursorFor(n: number): string { return Buffer.from(`cursor:${n}`, 'utf8').toString('base64'); }
function cursorNum(c: string | null | undefined): number | null {
  if (!c) return null;
  try { const t = Buffer.from(c, 'base64').toString('utf8'); const m = /^cursor:(\d+)$/.exec(t); return m ? parseInt(m[1] as string, 10) : null; } catch { return null; }
}
function resolveIssues(repo: Repo, args: Record<string, GqlValue>): GqlNode {
  let list = [...repo.issues.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length) {
    const want = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((i) => want.has(i.state));
  }
  const orderBy = args.orderBy as Record<string, GqlValue> | undefined;
  const dir = orderBy && String(orderBy.direction ?? '') === 'DESC' ? -1 : 1;
  list.sort((a, b) => (a.number - b.number) * dir);
  const after = cursorNum(typeof args.after === 'string' ? args.after : null);
  if (after !== null) list = list.filter((i) => (dir === 1 ? i.number > after : i.number < after));
  const first = typeof args.first === 'number' ? args.first : 100;
  const page = list.slice(0, first);
  const hasNext = list.length > page.length;
  return { kind: 'IssueConnection', repo, issues: page, hasNext, endCursor: page.length ? cursorFor(page[page.length - 1]?.number ?? 0) : null };
}
function createIssueGql(repo: Repo, title: string, body: string): IssueRec {
  const stamp = nextStamp();
  const issue: IssueRec = {
    number: repo.nextNumber++, title, body: body ?? '', state: 'open', labels: [],
    seq: tick, dbId: nextGlobalId++, createdAt: stamp.iso, updatedAt: stamp.iso, comments: [],
  };
  repo.issues.set(issue.number, issue);
  return issue;
}
function createPullGql(repo: Repo, head: string, base: string, title: string, body: string): PullRec | null {
  const headSha = repo.refs.get(`refs/heads/${head}`);
  const baseSha = repo.refs.get(`refs/heads/${base}`);
  if (!headSha || !baseSha) return null;
  const pr: PullRec = {
    number: repo.nextNumber++, title, body: body ?? '', state: 'open', head, base,
    headSha, baseSha, merged: false, mergeSha: null, mergedAt: null, seq: tick,
  };
  repo.pulls.set(pr.number, pr);
  return pr;
}
function executeField(node: GqlNode | null, field: GqlField, errors: { message: string }[]): unknown {
  if (node === null) return null;
  if (field.fragmentType) {
    const t = gqlTypeOf(node);
    if (t !== field.fragmentType) return null;
    const out: Record<string, unknown> = {};
    for (const sub of field.selections ?? []) {
      const v = executeField(node, sub, errors);
      if (v === undefined) continue;
      // A nested fragment merges its fields into this object; a plain
      // field lands under its alias.
      if (sub.fragmentType) { if (v !== null && typeof v === 'object') Object.assign(out, v as Record<string, unknown>); }
      else out[sub.alias] = v;
    }
    return out;
  }
  const typeName = gqlTypeOf(node);
  const allowed = GQL_FIELDS[typeName] ?? [];
  if (!allowed.includes(field.name)) {
    errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
    return undefined;
  }
  const sel = field.selections;
  const sub = (child: GqlNode | null): Record<string, unknown> | null => {
    if (child === null || !sel) return null;
    const out: Record<string, unknown> = {};
    for (const s of sel) {
      const v = executeField(child, s, errors);
      if (v === undefined) continue;
      // An inline fragment (`... on Type`) merges its fields into the
      // parent object; without this the fields land under an empty key
      // and `node { ... on Repository { name } }` loses `name`.
      if (s.fragmentType) { if (v !== null && typeof v === 'object') Object.assign(out, v as Record<string, unknown>); }
      else out[s.alias] = v;
    }
    return out;
  };
  const subList = (children: GqlNode[]): unknown[] => children.map((c) => sub(c));
  switch (node.kind) {
    case 'Query': {
      if (field.name === 'viewer') return sub({ kind: 'User', login: VIEWER.login });
      if (field.name === 'repository') {
        const owner = String(field.args.owner ?? ''); const name = String(field.args.name ?? '');
        const repo = getRepo(owner, name);
        return repo ? sub({ kind: 'Repository', repo }) : null;
      }
      if (field.name === 'node') {
        const dec = decodeGlobalId(String(field.args.id ?? ''));
        if (!dec) return null;
        if (dec.kind === 'R') { const repo = findRepoByDbId(Number(dec.parts[0])); return repo ? sub({ kind: 'Repository', repo }) : null; }
        if (dec.kind === 'I') { const repo = findRepoByDbId(Number(dec.parts[0])); const issue = repo?.issues.get(Number(dec.parts[1])); return repo && issue ? sub({ kind: 'Issue', repo, issue }) : null; }
        if (dec.kind === 'P') { const repo = findRepoByDbId(Number(dec.parts[0])); const pr = repo?.pulls.get(Number(dec.parts[1])); return repo && pr ? sub({ kind: 'PullRequest', repo, pr }) : null; }
        return null;
      }
      if (field.name === '__type') return sub({ kind: 'Type', name: String(field.args.name ?? '') });
      if (field.name === '__schema') return sub({ kind: 'Type', name: '__schema' });
      return null;
    }
    case 'Mutation': {
      const input = (field.args.input ?? {}) as Record<string, GqlValue>;
      if (field.name === 'createIssue') {
        const dec = decodeGlobalId(String(input.repositoryId ?? ''));
        const repo = dec?.kind === 'R' ? findRepoByDbId(Number(dec.parts[0])) : undefined;
        if (!repo) { errors.push({ message: 'createIssue: repository not found' }); return null; }
        const issue = createIssueGql(repo, String(input.title ?? ''), String(input.body ?? ''));
        return sub({ kind: 'Payload', field: 'issue', value: { kind: 'Issue', repo, issue } });
      }
      if (field.name === 'closeIssue') {
        const dec = decodeGlobalId(String(input.issueId ?? ''));
        const repo = dec?.kind === 'I' ? findRepoByDbId(Number(dec.parts[0])) : undefined;
        const issue = repo?.issues.get(Number(dec?.parts[1] ?? NaN));
        if (!repo || !issue) { errors.push({ message: 'closeIssue: issue not found' }); return null; }
        issue.state = 'closed'; issue.updatedAt = nextStamp().iso;
        return sub({ kind: 'Payload', field: 'issue', value: { kind: 'Issue', repo, issue } });
      }
      if (field.name === 'createPullRequest') {
        const dec = decodeGlobalId(String(input.repositoryId ?? ''));
        const repo = dec?.kind === 'R' ? findRepoByDbId(Number(dec.parts[0])) : undefined;
        if (!repo) { errors.push({ message: 'createPullRequest: repository not found' }); return null; }
        const pr = createPullGql(repo, String(input.headRefName ?? ''), String(input.baseRefName ?? ''), String(input.title ?? ''), String((input as Record<string, unknown>).body ?? ''));
        if (!pr) { errors.push({ message: 'createPullRequest: head or base branch missing' }); return null; }
        return sub({ kind: 'Payload', field: 'pullRequest', value: { kind: 'PullRequest', repo, pr } });
      }
      if (field.name === 'mergePullRequest') {
        const dec = decodeGlobalId(String(input.pullRequestId ?? ''));
        const repo = dec?.kind === 'P' ? findRepoByDbId(Number(dec.parts[0])) : undefined;
        const pr = repo?.pulls.get(Number(dec?.parts[1] ?? NaN));
        if (!repo || !pr) { errors.push({ message: 'mergePullRequest: pull request not found' }); return null; }
        if (pr.merged || pr.state === 'closed') { errors.push({ message: 'mergePullRequest: already merged or closed' }); return null; }
        const r = doMerge(repo, pr);
        if ('conflict' in r) { errors.push({ message: 'mergePullRequest: merge conflict' }); return null; }
        return sub({ kind: 'Payload', field: 'pullRequest', value: { kind: 'PullRequest', repo, pr } });
      }
      if (field.name === 'addComment') {
        const dec = decodeGlobalId(String(input.subjectId ?? ''));
        const repo = dec?.kind === 'I' ? findRepoByDbId(Number(dec.parts[0])) : undefined;
        const issue = repo?.issues.get(Number(dec?.parts[1] ?? NaN));
        if (!repo || !issue) { errors.push({ message: 'addComment: subject not found' }); return null; }
        const comment = { id: repo.nextCommentId++, body: String(input.body ?? ''), createdAt: nextStamp().iso };
        issue.comments.push(comment);
        return sub({ kind: 'Payload', field: 'commentEdge', value: { kind: 'CommentEdge', repo, issue, comment } });
      }
      return null;
    }
    case 'User': {
      if (field.name === 'login') return node.login;
      if (field.name === 'id') return globalId('U', VIEWER.id);
      if (field.name === 'name') return VIEWER.name;
      if (field.name === 'email') return VIEWER.email;
      if (field.name === 'url') return `https://example.invalid/${node.login}`;
      return null;
    }
    case 'Repository': {
      const repo = node.repo;
      switch (field.name) {
        case 'id': return globalId('R', repo.dbId);
        case 'databaseId': return repo.dbId;
        case 'name': return repo.name;
        case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
        case 'owner': return sub({ kind: 'User', login: repo.owner });
        case 'defaultBranchRef': {
          const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
          return tip ? sub({ kind: 'Ref', name: repo.defaultBranch }) : null;
        }
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': return true;
        case 'description': return repo.description;
        case 'private': return repo.isPrivate;
        case 'url': return `https://example.invalid/${repo.owner}/${repo.name}`;
        case 'createdAt': return new Date((TRIAL_NOW_MS / 1000 + repo.createdSeq) * 1000).toISOString();
        case 'updatedAt': return new Date((TRIAL_NOW_MS / 1000 + repo.createdSeq) * 1000).toISOString();
        case 'issue': {
          const issue = repo.issues.get(Number(field.args.number));
          return issue ? sub({ kind: 'Issue', repo, issue }) : null;
        }
        case 'issues': return sub(resolveIssues(repo, field.args));
        case 'pullRequests': {
          let prs = [...repo.pulls.values()].filter((p) => p.state === 'open');
          const first = typeof field.args.first === 'number' ? field.args.first : 100;
          prs = prs.slice(0, first);
          return sub({ kind: 'PullRequestConnection', repo, prs });
        }
        case 'pullRequest': {
          const pr = repo.pulls.get(Number(field.args.number));
          return pr ? sub({ kind: 'PullRequest', repo, pr }) : null;
        }
        default: return null;
      }
    }
    case 'Issue': {
      const { repo, issue } = node;
      switch (field.name) {
        case 'id': return globalId('I', repo.dbId, issue.number);
        case 'number': return issue.number;
        case 'title': return issue.title;
        case 'state': return issueStateGql(issue);
        case 'body': return issue.body;
        case 'url': return `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`;
        case 'createdAt': return issue.createdAt;
        case 'updatedAt': return issue.updatedAt;
        case 'labels': return issue.labels.map((l) => ({ name: l }));
        case 'author': return sub({ kind: 'User', login: VIEWER.login });
        default: return null;
      }
    }
    case 'PullRequest': {
      const { repo, pr } = node;
      switch (field.name) {
        case 'id': return globalId('P', repo.dbId, pr.number);
        case 'number': return pr.number;
        case 'title': return pr.title;
        case 'state': return prStateGql(pr);
        case 'merged': return pr.merged;
        case 'headRefName': return pr.head;
        case 'baseRefName': return pr.base;
        case 'mergeable': return prMergeable(repo, pr);
        case 'body': return pr.body;
        case 'url': return `https://example.invalid/${repo.owner}/${repo.name}/pulls/${pr.number}`;
        case 'createdAt': return new Date((TRIAL_NOW_MS / 1000 + pr.seq) * 1000).toISOString();
        case 'files': {
          const baseFiles = filesOfCommit(repo, pr.baseSha);
          const headFiles = filesOfCommit(repo, pr.headSha) ?? new Map<string, { oid: string; mode: string }>();
          const files = diffTrees(repo, baseFiles, headFiles);
          const first = typeof field.args.first === 'number' ? field.args.first : 100;
          return sub({ kind: 'ChangedFileConnection', files: files.slice(0, first) });
        }
        default: return null;
      }
    }
    case 'IssueConnection': {
      if (field.name === 'nodes') return subList(node.issues.map((i) => ({ kind: 'Issue', repo: node.repo, issue: i }) as GqlNode));
      if (field.name === 'pageInfo') return sub({ kind: 'PageInfo', hasNext: node.hasNext, endCursor: node.endCursor });
      if (field.name === 'totalCount') return node.issues.length;
      return null;
    }
    case 'PullRequestConnection': {
      if (field.name === 'nodes') return subList(node.prs.map((p) => ({ kind: 'PullRequest', repo: node.repo, pr: p }) as GqlNode));
      if (field.name === 'pageInfo') return sub({ kind: 'PageInfo', hasNext: false, endCursor: null });
      if (field.name === 'totalCount') return node.prs.length;
      return null;
    }
    case 'ChangedFileConnection': {
      if (field.name === 'nodes') return subList(node.files.map((f) => ({ kind: 'ChangedFile', file: f }) as GqlNode));
      if (field.name === 'pageInfo') return sub({ kind: 'PageInfo', hasNext: false, endCursor: null });
      if (field.name === 'totalCount') return node.files.length;
      return null;
    }
    case 'ChangedFile': {
      const f = node.file;
      switch (field.name) {
        case 'path': return f.path;
        case 'filename': return f.path;
        case 'additions': return f.additions;
        case 'deletions': return f.deletions;
        case 'changes': return f.additions + f.deletions;
        case 'status': return f.status.toUpperCase();
        default: return null;
      }
    }
    case 'Ref': return field.name === 'name' ? node.name : null;
    case 'PageInfo': {
      if (field.name === 'hasNextPage') return node.hasNext;
      if (field.name === 'hasPreviousPage') return false;
      if (field.name === 'endCursor') return node.endCursor;
      if (field.name === 'startCursor') return null;
      return null;
    }
    case 'Type': {
      if (node.name === '__schema') return field.name === 'types' ? [] : null;
      const info = INTROSPECTION[node.name];
      if (!info) {
        if (field.name === 'name') return node.name;
        if (field.name === 'kind') return null;
        if (field.name === 'fields') return null;
        if (field.name === 'enumValues') return null;
        return null;
      }
      if (field.name === 'name') return node.name;
      if (field.name === 'kind') return info.kind;
      if (field.name === 'description') return null;
      if (field.name === 'fields') return (info.fields ?? []).map((n) => ({ name: n }));
      if (field.name === 'enumValues') return (info.enumValues ?? []).map((n) => ({ name: n }));
      if (field.name === 'inputFields') return null;
      return null;
    }
    case 'Payload': {
      if (field.name === node.field) return sub(node.value);
      if (field.name === 'clientMutationId') return null;
      return null;
    }
    case 'CommentEdge': {
      if (field.name === 'node') return sub({ kind: 'Comment', repo: node.repo, issue: node.issue, comment: node.comment });
      if (field.name === 'cursor') return cursorFor(node.comment.id);
      return null;
    }
    case 'Comment': {
      if (field.name === 'id') return globalId('CM', node.repo.dbId, node.issue.number, node.comment.id);
      if (field.name === 'body') return node.comment.body;
      if (field.name === 'author') return sub({ kind: 'User', login: VIEWER.login });
      if (field.name === 'createdAt') return node.comment.createdAt;
      return null;
    }
  }
}
function executeGql(query: string, variables: Record<string, GqlValue>): { data: Record<string, unknown>; errors?: { message: string }[] } {
  const errors: { message: string }[] = [];
  let doc: GqlDoc;
  try {
    doc = new GqlParser(query, variables).parseDocument();
  } catch (e) {
    return { data: {}, errors: [{ message: e instanceof Error ? e.message : 'parse error' }] };
  }
  const root: GqlNode = doc.operation === 'mutation' ? { kind: 'Mutation' } : { kind: 'Query' };
  const data: Record<string, unknown> = {};
  for (const f of doc.selections) {
    const v = executeField(root, f, errors);
    if (v !== undefined) data[f.alias] = v;
  }
  return errors.length ? { data, errors } : { data };
}

// ---------------------------------------------------------------------------
// MCP (JSON-RPC 2.0, Streamable HTTP, plain JSON answers)
// ---------------------------------------------------------------------------
const MCP_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const SERVER_INFO = { name: 'forge', version: '1.0.0' };
function toolDef(name: string, description: string, properties: Record<string, unknown>, required: string[]): Record<string, unknown> {
  return { name, description, inputSchema: { type: 'object', properties, required } };
}
const MCP_TOOLS: Record<string, unknown>[] = [
  toolDef('create_repo', 'Create a repository owned by the authenticated user.', { name: { type: 'string', description: 'Repository name' }, owner: { type: 'string', description: 'Owner login' }, description: { type: 'string' }, private: { type: 'boolean' } }, ['name']),
  toolDef('get_repo', 'Get a repository by owner and name.', { owner: { type: 'string' }, repo: { type: 'string' } }, ['owner', 'repo']),
  toolDef('create_issue', 'Create an issue in a repository.', { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, ['owner', 'repo', 'title']),
  toolDef('list_issues', 'List issues in a repository.', { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string', description: 'open, closed or all' } }, ['owner', 'repo']),
  toolDef('create_pull_request', 'Open a pull request from a head branch into a base branch.', { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' }, body: { type: 'string' } }, ['owner', 'repo', 'title', 'head', 'base']),
  toolDef('merge_pull_request', 'Merge a pull request by number.', { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'integer' } }, ['owner', 'repo', 'pull_number']),
];
const MCP_TOOLS_JSON = JSON.stringify(MCP_TOOLS);
function mcpArg(args: Record<string, unknown>, ...names: string[]): unknown {
  for (const n of names) if (args[n] !== undefined) return args[n];
  return undefined;
}
function mcpToolResult(obj: unknown, isError = false): Record<string, unknown> {
  return { content: [{ type: 'text', text: typeof obj === 'string' ? obj : JSON.stringify(obj) }], structuredContent: obj, ...(isError ? { isError: true } : {}) };
}
function mcpCall(name: string, args: Record<string, unknown>): { result?: Record<string, unknown>; error?: { code: number; message: string } } {
  const norm = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  const wanted = norm(name);
  const canon: [string, string[]][] = [
    ['create_repo', ['createrepo', 'createrepository']],
    ['get_repo', ['getrepo', 'getrepository']],
    ['create_issue', ['createissue']],
    ['list_issues', ['listissues', 'issueslist']],
    ['create_pull_request', ['createpullrequest', 'createpr']],
    ['merge_pull_request', ['mergepullrequest', 'mergepr']],
  ];
  let tool: string | null = null;
  for (const [c, aliases] of canon) {
    if (wanted === norm(c) || aliases.includes(wanted) || (wanted.length > norm(c).length && wanted.endsWith(norm(c)))) { tool = c; break; }
  }
  if (!tool) return { error: { code: -32601, message: `Unknown tool: ${name}` } };
  const owner = String(mcpArg(args, 'owner', 'owner_login', 'login') ?? '');
  const repoName = String(mcpArg(args, 'repo', 'repository', 'repository_name', 'repo_name') ?? '');
  const repo = owner && repoName ? getRepo(owner, repoName) : undefined;
  const needRepo = (): { result?: Record<string, unknown>; error?: { code: number; message: string } } | null => {
    if (!owner || !repoName) return { result: mcpToolResult({ error: 'owner and repo are required' }, true) };
    if (!repo) return { result: mcpToolResult({ error: `repository ${owner}/${repoName} not found` }, true) };
    return null;
  };
  switch (tool) {
    case 'create_repo': {
      const nm = String(mcpArg(args, 'name', 'repo', 'repository') ?? '');
      if (!nm) return { result: mcpToolResult({ error: 'name is required' }, true) };
      if (owner && owner !== VIEWER.login) return { result: mcpToolResult({ error: 'owner does not match the token owner' }, true) };
      if (repos.has(repoKey(VIEWER.login, nm))) return { result: mcpToolResult({ error: `repository ${nm} already exists` }, true) };
      const r = createRepo(nm, mcpArg(args, 'private', 'is_private') === true, String(mcpArg(args, 'description', 'about') ?? ''));
      return { result: mcpToolResult(repoJson(r)) };
    }
    case 'get_repo': {
      const miss = needRepo(); if (miss) return miss;
      return { result: mcpToolResult(repoJson(repo as Repo)) };
    }
    case 'create_issue': {
      const miss = needRepo(); if (miss) return miss;
      const title = String(mcpArg(args, 'title', 'issue_title') ?? '');
      if (!title) return { result: mcpToolResult({ error: 'title is required' }, true) };
      const issue = createIssueGql(repo as Repo, title, String(mcpArg(args, 'body', 'issue_body', 'description') ?? ''));
      return { result: mcpToolResult(issueJson(repo as Repo, issue)) };
    }
    case 'list_issues': {
      const miss = needRepo(); if (miss) return miss;
      const state = String(mcpArg(args, 'state', 'status') ?? 'open');
      let list = [...(repo as Repo).issues.values()];
      if (state !== 'all') list = list.filter((i) => i.state === state);
      list.sort((a, b) => a.number - b.number);
      const arr = list.map((i) => issueJson(repo as Repo, i));
      return { result: mcpToolResult({ issues: arr }) };
    }
    case 'create_pull_request': {
      const miss = needRepo(); if (miss) return miss;
      const title = String(mcpArg(args, 'title', 'pr_title') ?? '');
      const head = String(mcpArg(args, 'head', 'head_ref', 'head_branch') ?? '');
      const base = String(mcpArg(args, 'base', 'base_ref', 'base_branch') ?? '');
      if (!title || !head || !base) return { result: mcpToolResult({ error: 'title, head and base are required' }, true) };
      const pr = createPullGql(repo as Repo, head, base, title, String(mcpArg(args, 'body', 'description') ?? ''));
      if (!pr) return { result: mcpToolResult({ error: 'head or base branch does not exist' }, true) };
      return { result: mcpToolResult(pullJson(repo as Repo, pr)) };
    }
    case 'merge_pull_request': {
      const miss = needRepo(); if (miss) return miss;
      const num = Number(mcpArg(args, 'pull_number', 'pull_request_number', 'pr_number', 'number'));
      const pr = (repo as Repo).pulls.get(num);
      if (!pr) return { result: mcpToolResult({ error: `pull request #${num} not found` }, true) };
      if (pr.merged || pr.state === 'closed') return { result: mcpToolResult({ error: 'pull request is already merged or closed' }, true) };
      const r = doMerge(repo as Repo, pr);
      if ('conflict' in r) return { result: mcpToolResult({ error: 'merge conflict' }, true) };
      return { result: mcpToolResult({ sha: r.sha, merged: true, number: pr.number }) };
    }
  }
  return { error: { code: -32601, message: `Unknown tool: ${name}` } };
}
function handleMcp(bodyRaw: Buffer, res: http.ServerResponse): void {
  const send = (status: number, obj: unknown, extra: Record<string, string> = {}): void => {
    res.writeHead(status, { 'content-type': 'application/json', ...extra });
    res.end(JSON.stringify(obj));
  };
  let body: unknown;
  try { body = JSON.parse(bodyRaw.toString('utf8')); } catch {
    send(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (Array.isArray(body) || typeof body !== 'object' || body === null) {
    send(400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const req = body as Record<string, unknown>;
  const id = req.id;
  if (id === undefined) {
    // Notification: acknowledge, no JSON-RPC response body.
    res.writeHead(202, { 'content-type': 'application/json' });
    res.end('');
    return;
  }
  const method = String(req.method ?? '');
  const params = (req.params ?? {}) as Record<string, unknown>;
  if (method === 'server/discover') {
    send(200, { jsonrpc: '2.0', id, result: { supportedVersions: MCP_VERSIONS, capabilities: { tools: {} }, serverInfo: SERVER_INFO, _meta: { 'io.modelcontextprotocol/serverInfo': SERVER_INFO } } }, { 'mcp-session-id': 'forge-session-1' });
    return;
  }
  if (method === 'initialize') {
    const asked = String(params.protocolVersion ?? '');
    const negotiated = MCP_VERSIONS.includes(asked) ? asked : '2025-11-25';
    send(200, { jsonrpc: '2.0', id, result: { protocolVersion: negotiated, capabilities: { tools: {} }, serverInfo: SERVER_INFO } }, { 'mcp-session-id': 'forge-session-1' });
    return;
  }
  if (method === 'ping') { send(200, { jsonrpc: '2.0', id, result: {} }); return; }
  if (method === 'tools/list') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result: { tools: JSON.parse(MCP_TOOLS_JSON) } }));
    return;
  }
  if (method === 'tools/call') {
    const name = String(params.name ?? '');
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const out = mcpCall(name, args);
    if (out.error) { send(200, { jsonrpc: '2.0', id, error: out.error }); return; }
    send(200, { jsonrpc: '2.0', id, result: out.result });
    return;
  }
  send(200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
}

// ---------------------------------------------------------------------------
// HTTP server + lifecycle
// ---------------------------------------------------------------------------
function authed(req: http.IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  if (!h.startsWith('Bearer ')) return false;
  const tok = h.slice('Bearer '.length);
  if (TOKEN === '') return tok.length > 0;
  return tok === TOKEN;
}
async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
}
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://x');
    const path = url.pathname;
    const method = req.method ?? 'GET';
    if (path === '/healthz' && method === 'GET') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
    if (gitMatch) {
      if (!authed(req)) { errJson(res, 401, 'Unauthorized'); return; }
      const owner = decodeURIComponent(gitMatch[1] as string);
      const name = decodeURIComponent(gitMatch[2] as string);
      const suffix = gitMatch[3] ?? '';
      const repo = getRepo(owner, name);
      if (!repo) { errJson(res, 404, 'Not Found'); return; }
      const service = url.searchParams.get('service') ?? '';
      if (method === 'GET' && suffix === '/info/refs' && (service === 'git-upload-pack' || service === 'git-receive-pack')) {
        const isV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '').includes('version=2');
        const body = isV2 ? v2Advertisement() : v0Advertisement(repo, service);
        res.writeHead(200, { 'content-type': `application/x-${service}-advertisement` });
        res.end(body);
        return;
      }
      if (method === 'POST' && suffix === '/git-upload-pack') {
        const raw = await readBody(req);
        const isV2 = (req.headers['git-protocol'] ?? '').includes('version=2');
        const lines = gitTextLines(raw);
        const first = lines[0] ?? '';
        if (!first.startsWith('command=')) {
          res.writeHead(400, { 'content-type': 'text/plain' });
          res.end('bad request: expected a v2 command');
          return;
        }
        const command = first.slice('command='.length).trim();
        if (command === 'ls-refs') {
          const args = { peel: false, symrefs: false, unborn: false, prefixes: [] as string[] };
          for (const l of lines.slice(1)) {
            const t = l.trim();
            if (t === 'peel') args.peel = true;
            else if (t === 'symrefs') args.symrefs = true;
            else if (t === 'unborn') args.unborn = true;
            else if (t.startsWith('ref-prefix ')) args.prefixes.push(t.slice('ref-prefix '.length).trim());
          }
          res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result' });
          res.end(lsRefsResponse(repo, args));
          return;
        }
        if (command === 'fetch') {
          const fetchArgs = parseFetchArgs(lines.slice(1));
          const out = isV2 ? fetchResponseV2(repo, fetchArgs) : fetchResponseV0(repo, fetchArgs);
          res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result' });
          res.end(out);
          return;
        }
        res.writeHead(400, { 'content-type': 'text/plain' });
        res.end(`unknown command ${command}`);
        return;
      }
      if (method === 'POST' && suffix === '/git-receive-pack') {
        const raw = await readBody(req);
        const out = handleReceivePack(repo, raw);
        res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result' });
        res.end(out);
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    if (path.startsWith('/api/v3')) {
      if (!authed(req)) { errJson(res, 401, 'Unauthorized'); return; }
      const segs = path.slice('/api/v3'.length).split('/').filter((s) => s !== '');
      const raw = await readBody(req);
      let parsed: unknown = undefined;
      if (raw.length > 0) {
        try { parsed = JSON.parse(raw.toString('utf8')); } catch { errJson(res, 400, 'Malformed JSON body'); return; }
      }
      handleRest({ method, segs, query: url.searchParams, host: req.headers.host ?? 'localhost', body: parsed, bodyRaw: raw, authed: true }, res);
      return;
    }
    if (path === '/api/graphql' && method === 'POST') {
      if (!authed(req)) { errJson(res, 401, 'Unauthorized'); return; }
      const raw = await readBody(req);
      let parsed: unknown;
      try { parsed = JSON.parse(raw.toString('utf8')); } catch { jsonBody(res, 400, { errors: [{ message: 'Malformed JSON body' }] }); return; }
      if (Array.isArray(parsed)) {
        const out = parsed.map((op) => {
          const o = (op ?? {}) as Record<string, unknown>;
          return executeGql(String(o.query ?? ''), (o.variables ?? {}) as Record<string, GqlValue>);
        });
        jsonBody(res, 200, out);
        return;
      }
      const o = (parsed ?? {}) as Record<string, unknown>;
      jsonBody(res, 200, executeGql(String(o.query ?? ''), (o.variables ?? {}) as Record<string, GqlValue>));
      return;
    }
    if (path === '/mcp') {
      if (method === 'DELETE') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(''); return; }
      if (method !== 'POST') { errJson(res, 405, 'Method Not Allowed'); return; }
      if (!authed(req)) { errJson(res, 401, 'Unauthorized'); return; }
      const raw = await readBody(req);
      handleMcp(raw, res);
      return;
    }
    errJson(res, 404, 'Not Found');
  } catch (e) {
    try {
      errJson(res, 500, e instanceof Error ? e.message : 'internal error');
    } catch { /* socket gone */ }
  }
});

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
async function main(): Promise<void> {
  await new Promise<void>((resolve) => server.listen(0, '0.0.0.0', () => resolve()));
  const port = (server.address() as { port: number }).port;
  if (!ENV_URL) return; // local run: serve forever
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const r = await fetch(`${ENV_URL}/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ port }) });
      if (r.ok || r.status === 409) break;
    } catch { /* env not up yet */ }
    await sleep(200);
  }
  for (;;) {
    await sleep(500);
    try {
      const r = await fetch(`${ENV_URL}/done`);
      const j = (await r.json()) as { done?: boolean };
      if (j?.done === true) break;
    } catch { /* keep polling */ }
  }
  process.exit(0);
}
main().catch(() => process.exit(1));
