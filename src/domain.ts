/**
 * Redoubt — 端侧加密保险箱 · 领域逻辑层
 *
 * 设计原则：
 *  - 零依赖、纯 TypeScript，既能在 Node（本机测试）跑，也能在 React Native（Expo）跑。
 *  - 加解密使用本仓库自带的纯 JS 原语（purecrypto.ts）：Hermes 没有 WebCrypto.subtle，
 *    Expo SDK 54 也不提供，直接用 subtle 会导致真机上「建箱子」必然失败（NO_CRYPTO）。
 *  - 零网络：本文件不含任何 fetch / XHR / WebSocket。数据明文只在内存里短暂存在。
 *  - 加密格式稳定：任何改动都要升 FORMAT_VERSION 并写迁移，避免老数据打不开。
 *
 * 威胁模型（诚实边界，见 需求/PRD.md）：
 *  - 防：设备丢失/被偷后，文件或 iCloud 备份里的密文泄露（无密钥不可读）。
 *  - 防：App 沙箱被静态 dump（拿不到主密钥，主密钥在 Keychain/Secure Enclave）。
 *  - 不防：设备已解锁且被装上恶意键盘记录/运行时 hook、被胁迫解锁、司法强制。
 */

import { aesGcmDecrypt, aesGcmEncrypt, pbkdf2Sha256 } from './purecrypto.ts';


// ============================================================
// 常量与类型
// ============================================================

export const FORMAT_VERSION = 1;
export const PBKDF2_ITERATIONS = 310_000; // OWASP 2023 建议 ≥600k for SHA256；310k 兼顾手机端启动延迟，见 PRD 权衡
export const SALT_BYTES = 16;
export const IV_BYTES = 12; // AES-GCM 标准 96-bit nonce
export const KEY_BITS = 256;
export const MAX_BACKUP_BYTES = 20 * 1024 * 1024; // 备份文件上限 20MB，防超大导入卡死/OOM

export type VaultKind = 'login' | 'note' | 'card' | 'file' | 'recovery' | 'identity';

export interface VaultItem {
  id: string;
  kind: VaultKind;
  title: string;
  fields: Record<string, string>; // 结构化字段，如 username/password/url 或 cardNumber/pin
  note?: string;
  createdAt: string; // ISO
  updatedAt: string; // ISO
}

export interface SealboxMeta {
  formatVersion: number;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  saltB64: string;
  createdAt: string;
  updatedAt: string;
  itemCount: number;
}

export interface EncryptedBlob {
  v: number;
  ivB64: string;
  dataB64: string; // AES-256-GCM 密文（tag 拼接在末尾，WebCrypto 默认行为）
}

export interface BackupFile {
  format: 'sealbox-backup';
  version: number;
  exportedAt: string;
  boxName: string;
  meta: SealboxMeta;
  blob: EncryptedBlob;
}

export type DomainErrorKind =
  | 'BAD_PASSWORD'
  | 'BAD_FORMAT'
  | 'UNSUPPORTED_VERSION'
  | 'CHECKSUM_MISMATCH'
  | 'EMPTY_BOX'
  | 'ITEM_NOT_FOUND'
  | 'TOO_LARGE'
  | 'NO_CRYPTO'
  | 'BAD_OPTIONS';

export class DomainError extends Error {
  kind: DomainErrorKind;
  constructor(kind: DomainErrorKind, message: string) {
    super(message);
    this.name = 'DomainError';
    this.kind = kind;
  }
}

// ============================================================
// Base64 编解码（RN 与 Node 通用，不依赖 Buffer）
// ============================================================

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function bytesToB64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const c = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += B64[a >> 2];
    out += B64[((a & 3) << 4) | ((b ?? 0) >> 4)];
    out += b === undefined ? '=' : B64[((b & 15) << 2) | ((c ?? 0) >> 6)];
    out += c === undefined ? '=' : B64[c & 63];
  }
  return out;
}

export function b64ToBytes(s: string): Uint8Array {
  const clean = s.replace(/=+$/, '').replace(/\s/g, '');
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of clean) {
    const idx = B64.indexOf(ch);
    if (idx < 0) throw new DomainError('BAD_FORMAT', `非法 base64 字符：${ch}`);
    acc = (acc << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const toBytes = (s: string): Uint8Array => enc.encode(s);
const fromBytes = (b: Uint8Array): string => dec.decode(b);

// ============================================================
// 加密原语：纯 JS 实现（Hermes 没有 WebCrypto.subtle，见 purecrypto.ts）
// ============================================================

/** 可注入的安全随机源（RN 端由 App.tsx 用 expo-crypto 注入）。 */
let injectedRandom: ((n: number) => Uint8Array) | null = null;

export function setRandomSource(fn: (n: number) => Uint8Array): void {
  injectedRandom = fn;
}

/** 安全随机字节：优先 WebCrypto，其次 App 注入的 expo-crypto，最后报错（绝不退化成 Math.random）。 */
export function randomBytes(n: number): Uint8Array {
  const c = (globalThis as any).crypto;
  if (c && typeof c.getRandomValues === 'function') {
    return c.getRandomValues(new Uint8Array(n)) as Uint8Array;
  }
  if (injectedRandom) return injectedRandom(n);
  throw new DomainError('NO_CRYPTO', '当前运行时没有可用的安全随机数来源');
}

// ============================================================
// 密钥派生与加解密
// ============================================================

/** 派生出的对称密钥（纯 JS 实现，密钥字节留在内存，不进 WebCrypto 不可导出句柄）。 */
export interface VaultKey {
  readonly raw: Uint8Array;
}

/** 从主密码 + 盐派生 AES-256-GCM 密钥。盐必须每个保险箱随机且唯一。 */
export async function deriveKey(password: string, salt: Uint8Array, iterations = PBKDF2_ITERATIONS): Promise<VaultKey> {
  if (!password || password.length < 1) throw new DomainError('BAD_PASSWORD', '密码不能为空');
  if (salt.length < 8) throw new DomainError('BAD_FORMAT', '盐长度不足');
  const raw = pbkdf2Sha256(toBytes(password), salt, iterations, KEY_BITS / 8);
  return { raw };
}

/** AES-256-GCM 加密，返回 iv + 密文（认证标签拼在密文尾部，与 WebCrypto 输出一致）。 */
export async function encrypt(plaintext: string, key: VaultKey, iv = randomBytes(IV_BYTES)): Promise<EncryptedBlob> {
  const data = aesGcmEncrypt(key.raw, iv, toBytes(plaintext));
  return { v: FORMAT_VERSION, ivB64: bytesToB64(iv), dataB64: bytesToB64(data) };
}

/**
 * AES-256-GCM 解密。密码错误 / 密文被篡改都会因认证失败而抛错 → 统一映射为 BAD_PASSWORD，
 * 避免向调用方泄露“是密码错还是数据坏”（有助于抗 Oracle 攻击）。
 */
export async function decrypt(blob: EncryptedBlob, key: VaultKey): Promise<string> {
  try {
    const iv = b64ToBytes(blob.ivB64);
    const data = b64ToBytes(blob.dataB64);
    const plain = aesGcmDecrypt(key.raw, iv, data);
    return fromBytes(plain);
  } catch {
    throw new DomainError('BAD_PASSWORD', '密码错误，或数据已损坏');
  }
}

// ============================================================
// 保险箱序列化格式
// ============================================================

interface BoxPlain {
  meta: SealboxMeta;
  items: VaultItem[];
}

function assertVersion(v: number): void {
  if (v > FORMAT_VERSION) throw new DomainError('UNSUPPORTED_VERSION', `数据版本 ${v} 高于支持版本 ${FORMAT_VERSION}，请升级 App`);
  if (v < 1) throw new DomainError('BAD_FORMAT', `非法数据版本 ${v}`);
}

/** 把明文保险箱 + 主密码封成一个加密 blob。 */
export async function sealBox(items: VaultItem[], boxName: string, password: string, now = new Date()): Promise<{ blob: EncryptedBlob; meta: SealboxMeta; salt: Uint8Array }> {
  const salt = randomBytes(SALT_BYTES);
  const meta: SealboxMeta = {
    formatVersion: FORMAT_VERSION,
    kdf: 'PBKDF2-SHA256',
    iterations: PBKDF2_ITERATIONS,
    saltB64: bytesToB64(salt),
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    itemCount: items.length,
  };
  const plain: BoxPlain = { meta, items };
  const key = await deriveKey(password, salt, meta.iterations);
  const blob = await encrypt(JSON.stringify(plain), key);
  return { blob, meta, salt };
}

/** 用主密码打开一个加密 blob，返回明文条目。密码错或数据被改都会失败。 */
export async function openBox(blob: EncryptedBlob, meta: SealboxMeta, password: string): Promise<VaultItem[]> {
  assertVersion(blob.v);
  assertVersion(meta.formatVersion);
  const salt = b64ToBytes(meta.saltB64);
  const key = await deriveKey(password, salt, meta.iterations);
  const json = await decrypt(blob, key);
  let plain: BoxPlain;
  try {
    plain = JSON.parse(json) as BoxPlain;
  } catch {
    throw new DomainError('BAD_FORMAT', '解密成功但内容不是合法 JSON');
  }
  if (!plain || !Array.isArray(plain.items)) throw new DomainError('BAD_FORMAT', '保险箱内容结构损坏');
  return plain.items;
}

// ============================================================
// 备份导出 / 导入（仍加密，明文永不出设备）
// ============================================================

/**
 * 生成"加密备份文件"：blob 本身已加密，导出物不含任何明文；
 * 换设备时靠另一个 passphrase 二次封装，或直接用主密码（见 PRD 说明）。
 */
export function makeBackup(boxName: string, meta: SealboxMeta, blob: EncryptedBlob, now = new Date()): BackupFile {
  return {
    format: 'sealbox-backup',
    version: FORMAT_VERSION,
    exportedAt: now.toISOString(),
    boxName,
    meta,
    blob,
  };
}

/** 解析并校验备份文件；任何结构/版本问题都在导入前拦下。 */
export function parseBackup(text: string): BackupFile {
  if (text.length > MAX_BACKUP_BYTES) throw new DomainError('TOO_LARGE', '备份文件超过 20MB 上限');
  let obj: any;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new DomainError('BAD_FORMAT', '备份不是合法 JSON');
  }
  if (!obj || obj.format !== 'sealbox-backup') throw new DomainError('BAD_FORMAT', '不是 Redoubt 备份文件');
  assertVersion(obj.version);
  const b = obj as BackupFile;
  if (!b.blob || typeof b.blob.ivB64 !== 'string' || typeof b.blob.dataB64 !== 'string') {
    throw new DomainError('BAD_FORMAT', '备份缺少有效密文');
  }
  if (!b.meta || typeof b.meta.saltB64 !== 'string' || typeof b.meta.iterations !== 'number') {
    throw new DomainError('BAD_FORMAT', '备份缺少密钥派生参数');
  }
  if (b.meta.iterations < 100_000) throw new DomainError('BAD_FORMAT', '备份的密钥派生强度不足，拒绝导入');
  return b;
}

// ============================================================
// 条目辅助（纯逻辑，便于本机测试）
// ============================================================

export function newItem(kind: VaultKind, title: string, now = new Date()): VaultItem {
  const ts = now.toISOString();
  return { id: `${Date.now()}-${randomBytes(6).reduce((a, b) => a * 256 + b, 0).toString(36)}`, kind, title, fields: {}, createdAt: ts, updatedAt: ts };
}

export function upsertItem(items: VaultItem[], item: VaultItem): VaultItem[] {
  const i = items.findIndex((x) => x.id === item.id);
  if (i < 0) return [...items, item];
  const next = items.slice();
  next[i] = { ...item, updatedAt: new Date().toISOString() };
  return next;
}

export function removeItem(items: VaultItem[], id: string): VaultItem[] {
  return items.filter((x) => x.id !== id);
}

/** 本地全文搜索：标题 + 字段名 + 字段值 + 备注，大小写不敏感。全部在内存做，零网络。 */
export function searchItems(items: VaultItem[], query: string): VaultItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((it) => {
    const hay = [it.title, it.note ?? '', ...Object.keys(it.fields), ...Object.values(it.fields)].join('\n').toLowerCase();
    return hay.includes(q);
  });
}

export function groupByKind(items: VaultItem[]): Record<VaultKind, number> {
  const out: Record<VaultKind, number> = { login: 0, note: 0, card: 0, file: 0, recovery: 0, identity: 0 };
  for (const it of items) out[it.kind] = (out[it.kind] ?? 0) + 1;
  return out;
}

/** 导出为 CSV（字段转义 + 公式注入防护）。仅用户主动触发，结果交给系统分享面板。 */
export function itemsToCsv(items: VaultItem[]): string {
  const cell = (v: string): string => {
    const safe = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v; // 防 CSV 公式注入
    return `"${safe.replace(/"/g, '""')}"`;
  };
  const rows = [['id', 'kind', 'title', 'fields', 'note', 'updatedAt'].map(cell).join(',')];
  for (const it of items) {
    const fields = Object.entries(it.fields).map(([k, v]) => `${k}:${v}`).join(' | ');
    rows.push([it.id, it.kind, it.title, fields, it.note ?? '', it.updatedAt].map(cell).join(','));
  }
  return '\uFEFF' + rows.join('\r\n'); // BOM 让 Excel 正确识别 UTF-8
}

/** 密码强度评估（本地、无网络、无泄露），仅提示，不阻断。标签为英文，与 en-US UI 一致。 */
export function passwordScore(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string } {
  if (!pw) return { score: 0, label: 'Empty' };
  let n = 0;
  if (pw.length >= 12) n++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) n++;
  if (/\d/.test(pw)) n++;
  if (/[^a-zA-Z0-9]/.test(pw)) n++;
  const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
  return { score: Math.min(4, n) as 0 | 1 | 2 | 3 | 4, label: labels[Math.min(4, n)] };
}

// ============================================================
// 安全策略与输入工具（纯逻辑，本机可真测；不含任何原生依赖）
// ============================================================

/** 主密码最小长度。创建保险箱 / 导出备份共用，避免散落的魔法数字。 */
export const MIN_PASSPHRASE_LENGTH = 12;

/** 解锁后最长保持时长（毫秒）。到点无条件锁定；切后台是「立即锁定」，见 App.tsx。 */
export const IDLE_LOCK_MS = 5 * 60 * 1000;

export function isPassphraseAcceptable(pw: string): boolean {
  return typeof pw === 'string' && pw.length >= MIN_PASSPHRASE_LENGTH;
}

/** 需要遮掩的字段名（密码 / PIN / 助记词 / 密钥 / 令牌 / 验证码等）。UI 用它决定 secureTextEntry。 */
export function isSensitiveField(name: string): boolean {
  return /pass|pin|secret|key|seed|phrase|mnemonic|token|cvv|otp|code/i.test(name);
}

// ---------- 强密码生成器 ----------

export interface PasswordOptions {
  length?: number;          // 8–128，默认 20
  uppercase?: boolean;      // 默认 true
  lowercase?: boolean;      // 默认 true
  digits?: boolean;         // 默认 true
  symbols?: boolean;        // 默认 true
  excludeAmbiguous?: boolean; // 默认 true，排除 0/O/1/l/I/| 等易混淆字符
}

const PW_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const PW_LOWER = 'abcdefghijklmnopqrstuvwxyz';
const PW_DIGITS = '0123456789';
const PW_SYMBOLS = '!@#$%^&*_-+=?'; // 不含引号/反斜杠，便于在各系统输入与复制
const AMBIGUOUS = new Set('O0Il1|');

/** 均匀随机整数 [0, n)：拒绝采样消除取模偏差（直接用 % 会让小索引概率偏高）。n ≤ 256。 */
function randBelow(n: number): number {
  if (n <= 0 || n > 256) throw new DomainError('BAD_OPTIONS', '随机范围非法');
  const limit = Math.floor(256 / n) * n;
  let b = randomBytes(1)[0];
  while (b >= limit) b = randomBytes(1)[0];
  return b % n;
}

/**
 * 生成强密码：只用 WebCrypto CSPRNG（绝不 Math.random），保证每个启用的字符类至少出现一次，
 * 再 Fisher–Yates 洗牌消除「前几位固定属于某类」的可预测模式。不联网、不落盘、不记录。
 */
export function generatePassword(opts: PasswordOptions = {}): string {
  const length = opts.length ?? 20;
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new DomainError('BAD_OPTIONS', '密码长度须为 8–128 的整数');
  }
  const drop = opts.excludeAmbiguous ?? true;
  const clean = (s: string): string => drop ? [...s].filter((c) => !AMBIGUOUS.has(c)).join('') : s;
  const groups: string[] = [];
  if (opts.uppercase !== false) groups.push(clean(PW_UPPER));
  if (opts.lowercase !== false) groups.push(clean(PW_LOWER));
  if (opts.digits !== false) groups.push(clean(PW_DIGITS));
  if (opts.symbols !== false) groups.push(clean(PW_SYMBOLS));
  const usable = groups.filter((g) => g.length > 0);
  if (usable.length === 0) throw new DomainError('BAD_OPTIONS', '至少启用一种字符类型');
  if (length < usable.length) throw new DomainError('BAD_OPTIONS', '长度不足以覆盖所有启用的字符类型');

  const all = usable.join('');
  const out: string[] = [];
  for (const g of usable) out.push(g[randBelow(g.length)]); // 每类先保底一个
  while (out.length < length) out.push(all[randBelow(all.length)]);
  for (let i = out.length - 1; i > 0; i--) {
    const j = randBelow(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join('');
}

// ---------- 自动锁定策略 ----------

export type AppLifecycleState = 'active' | 'background' | 'inactive';

export interface LockDecisionInput {
  state: AppLifecycleState;
  unlocked: boolean;
  nowMs: number;
  lastActiveMs: number;   // 本次解锁时刻；后续版本可刷新为最后一次交互时刻
  idleTimeoutMs?: number;
}

/**
 * 是否应立即锁定。纯函数，UI 层只负责传入 AppState 与时钟。
 *  - 未解锁 → 不再锁（避免重复清状态）
 *  - 切后台 / 失活 → 立即锁（隐私保险箱的 P0 要求）
 *  - 前台停留超过阈值 → 锁
 */
export function shouldLock(i: LockDecisionInput): boolean {
  if (!i.unlocked) return false;
  if (i.state !== 'active') return true;
  return i.nowMs - i.lastActiveMs >= (i.idleTimeoutMs ?? IDLE_LOCK_MS);
}

// ============================================================
// 持久化层纯逻辑（v0.3：把大密文移出 Keychain）
//
// 背景（P0 缺陷）：expo-secure-store 官方文档明确「大 payload 会被底层平台
// 拒绝，历史上部分 iOS 版本拒绝超过约 2048 字节的值」。v0.2 把所有保险箱
// （含照片附件的 base64 密文）塞进单个 Keychain 项，用户存一张照片即可能写入
// 失败 → 静默丢数据。v0.3 起：Keychain 只保留生物识别门控的主密码（小），
// 箱密文写独立文件，索引写独立文件。
//
// 下列函数零依赖、可在 Windows 本机 Node 真跑单测；平台层只负责「读写字符串」。
// 提交顺序由平台层保证：先写箱文件（大、可失败），再写索引（小、提交点）。
// ============================================================

export const VAULT_INDEX_FILE = 'redoubt-index.json';
export const VAULT_FILE_PREFIX = 'redoubt-v-';
export const VAULT_FILE_SUFFIX = '.json';
export const MAX_BOX_FILE_BYTES = MAX_BACKUP_BYTES; // 单箱密文 ≤ 20MB，与备份上限一致

/**
 * v0.4 原子提交：每个箱轮流写 a / b 两个文件槽，索引记录当前生效的槽。
 * slot 缺省 = v0.3 旧格式（单文件路径 vaultFileName），首次保存时自动切换到双槽，
 * 因此老用户升级后原有箱仍可读，不会因文件名变化而「保险箱不见」。
 */
export type VaultSlot = 'a' | 'b';
export interface VaultIndexEntry { name: string; meta: SealboxMeta; slot?: VaultSlot }
export type VaultIndex = Record<string, VaultIndexEntry>;

/** UTF-8 字节数（RN Hermes 与 Node 均有 TextEncoder）。 */
export function utf8Bytes(s: string): number {
  return new TextEncoder().encode(s).length;
}

/** 只接受安全字符，杜绝路径穿越；id 由 randomUUID 生成，正常情况下恒成立。 */
export function safeVaultId(id: string): string {
  const s = id.replace(/[^A-Za-z0-9_-]/g, '');
  if (!s || s !== id) throw new DomainError('BAD_FORMAT', '非法保险箱 ID');
  return s;
}

export function vaultFileName(id: string): string {
  return `${VAULT_FILE_PREFIX}${safeVaultId(id)}${VAULT_FILE_SUFFIX}`;
}

/** A/B 双槽文件名。写入永远落在「当前生效槽的另一槽」，旧槽数据在提交前保持完好。 */
export function vaultSlotFileName(id: string, slot: VaultSlot): string {
  return `${VAULT_FILE_PREFIX}${safeVaultId(id)}-${slot}${VAULT_FILE_SUFFIX}`;
}

export function nextSlot(current?: VaultSlot): VaultSlot {
  return current === 'a' ? 'b' : 'a';
}

/** 按索引条目解析实际文件路径；无 slot 的旧条目回落到 v0.3 单文件名。 */
export function vaultFilePathFor(id: string, entry: VaultIndexEntry): string {
  return entry.slot ? vaultSlotFileName(id, entry.slot) : vaultFileName(id);
}

/** 列出某箱可能占用的全部文件（删除/清理时用，含旧格式）。 */
export function allVaultFileNames(id: string): string[] {
  return [vaultFileName(id), vaultSlotFileName(id, 'a'), vaultSlotFileName(id, 'b')];
}

export function isVaultFileName(name: string): boolean {
  return name.startsWith(VAULT_FILE_PREFIX) && name.endsWith(VAULT_FILE_SUFFIX) &&
    name.length > VAULT_FILE_PREFIX.length + VAULT_FILE_SUFFIX.length;
}

/** 显式上限，超限抛可操作的 DomainError，绝不静默失败。 */
export function assertWithinStorageLimit(text: string, label: string, max = MAX_BOX_FILE_BYTES): void {
  const n = utf8Bytes(text);
  if (n > max) throw new DomainError('TOO_LARGE', `${label}过大（${n} 字节，上限 ${max}）`);
}

export function encodeVaultIndex(index: VaultIndex): string {
  const text = JSON.stringify(index);
  assertWithinStorageLimit(text, '保险箱索引');
  return text;
}

/** 解析失败一律抛错，绝不返回空对象（返回空 = 用户以为保险箱丢了）。 */
export function decodeVaultIndex(text: string): VaultIndex {
  let obj: unknown;
  try { obj = JSON.parse(text); }
  catch { throw new DomainError('BAD_FORMAT', '保险箱索引损坏'); }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new DomainError('BAD_FORMAT', '保险箱索引格式错误');
  }
  for (const [id, entry] of Object.entries(obj as Record<string, unknown>)) {
    safeVaultId(id);
    const e = entry as VaultIndexEntry | null;
    if (!e || typeof e.name !== 'string' || !e.meta ||
        typeof e.meta.iterations !== 'number' || typeof e.meta.saltB64 !== 'string') {
      throw new DomainError('BAD_FORMAT', '保险箱索引条目损坏');
    }
    if (e.slot !== undefined && e.slot !== 'a' && e.slot !== 'b') {
      throw new DomainError('BAD_FORMAT', '保险箱索引槽位标记损坏');
    }
  }
  return obj as VaultIndex;
}

export function encodeVaultFile(blob: EncryptedBlob): string {
  const text = JSON.stringify({ blob });
  assertWithinStorageLimit(text, '保险箱内容');
  return text;
}

export function decodeVaultFile(text: string): EncryptedBlob {
  let obj: { blob?: EncryptedBlob };
  try { obj = JSON.parse(text); }
  catch { throw new DomainError('BAD_FORMAT', '保险箱文件损坏'); }
  const b = obj?.blob;
  if (!b || typeof b.v !== 'number' || typeof b.ivB64 !== 'string' || typeof b.dataB64 !== 'string') {
    throw new DomainError('BAD_FORMAT', '保险箱文件密文缺失');
  }
  return b;
}

/**
 * v0.4 索引容错：索引是覆盖式写入的小文件，一旦在写入中途被中断而截断，
 * v0.3 会让「所有保险箱」一起打不开。平台层在每次提交前保留一份可解析的 .bak，
 * 这里在解析失败时回退；两者都坏则明确抛错，绝不返回空集合（空集合 = 用户以为数据没了）。
 */
export function recoverVaultIndex(primary: string | null, backup: string | null): VaultIndex {
  try {
    if (primary !== null) return decodeVaultIndex(primary);
  } catch { /* 主索引损坏，尝试备份 */ }
  try {
    if (backup !== null) return decodeVaultIndex(backup);
  } catch { /* 备份也损坏 */ }
  throw new DomainError('BAD_FORMAT', '保险箱索引损坏且无可用备份，已停止读取以防止误判为数据丢失');
}

// ============================================================
// v0.4 输入防护（纯逻辑，本机可测；平台层在「读文件之前」调用）
// ============================================================

/** 原始字节 → base64 字符数（4·ceil(n/3)）。 */
export function base64LengthOf(rawBytes: number): number {
  if (!Number.isFinite(rawBytes) || rawBytes < 0) return 0;
  return 4 * Math.ceil(rawBytes / 3);
}

export const MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024;

/**
 * 选文件后、读入内存前判大小。膨胀链：原始字节 → base64 → 条目 JSON → 加密后再次 base64。
 * 任一环节超过单箱上限就提前拒绝，避免先把几十 MB 读进内存才报错（真机 OOM 崩溃）。
 */
export function assertAttachmentSize(rawBytes: number, label: string): void {
  if (!Number.isFinite(rawBytes) || rawBytes < 0) {
    throw new DomainError('BAD_FORMAT', `${label}大小不可读`);
  }
  if (rawBytes > MAX_ATTACHMENT_BYTES) {
    throw new DomainError('TOO_LARGE', `${label}过大（${rawBytes} 字节，附件上限 ${MAX_ATTACHMENT_BYTES}）`);
  }
  if (base64LengthOf(base64LengthOf(rawBytes)) > MAX_BOX_FILE_BYTES) {
    throw new DomainError('TOO_LARGE', `${label}加密后将超过单箱容量上限`);
  }
}

/** 读备份文件前按字节数拦截（getInfoAsync 的 size），同样防止先读全文再判大小。 */
export function assertFileSizeWithinLimit(bytes: number, label: string, max = MAX_BOX_FILE_BYTES): void {
  if (!Number.isFinite(bytes) || bytes < 0) throw new DomainError('BAD_FORMAT', `${label}大小不可读`);
  if (bytes > max) throw new DomainError('TOO_LARGE', `${label}过大（${bytes} 字节，上限 ${max}）`);
}

/**
 * 字段名唯一化：v0.3 直接用附件文件名作字段 key，用户连续添加两张都叫 photo.jpg 的
 * 照片时，第二张会静默覆盖第一张。改为自动追加 " (2)"、" (3)"。
 */
export function uniqueFieldKey(fields: Record<string, unknown>, name: string): string {
  const base = name.trim() || 'attachment';
  if (!Object.prototype.hasOwnProperty.call(fields, base)) return base;
  for (let i = 2; i < 1000; i++) {
    const k = `${base} (${i})`;
    if (!Object.prototype.hasOwnProperty.call(fields, k)) return k;
  }
  throw new DomainError('TOO_LARGE', '同名字段过多');
}
