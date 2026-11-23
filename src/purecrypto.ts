/**
 * Redoubt — 纯 JS 加密原语（Hermes / React Native 没有 WebCrypto.subtle 时使用）
 *
 * 为什么需要这个文件：
 *   - React Native 的 Hermes 运行时没有 globalThis.crypto.subtle，Expo SDK 54 也不提供；
 *   - 之前 domain.ts 直接调用 subtle，导致真机/模拟器上「建箱子」必然报 NO_CRYPTO；
 *   - 这里用纯 JS 实现 SHA-256 / HMAC-SHA256 / PBKDF2 / AES-256-GCM，
 *     输出与 WebCrypto 逐字节一致（Node 侧已做交叉验证），不引入任何原生依赖。
 *
 * 性能取舍（为什么不是最朴素的写法）：
 *   - 附件会被 base64 内联进保险箱 JSON，单箱上限 20MB，所以 GCM 吞吐必须够用；
 *   - PBKDF2 迭代 310k 次，HMAC 用「预计算 ipad/opad 中间态」压到每轮 2 次压缩；
 *   - AES 用 T 表（SubBytes + MixColumns 合并）、GHASH 用半字节表。
 */

// ============================================================
// SHA-256（无分配压缩函数；HMAC/PBKDF2 复用同一个核心）
// ============================================================

const K256 = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const IV256 = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/** 复用的消息扩展缓冲（单线程同步执行，不存在重入）。 */
const W256 = new Int32Array(64);

/** 把一个 64 字节块压缩进 h（就地更新 8 个状态字）。 */
function compress256(h: Int32Array, block: Uint8Array, off: number): void {
  const w = W256;
  for (let i = 0; i < 16; i++) {
    const p = off + i * 4;
    w[i] = (block[p] << 24) | (block[p + 1] << 16) | (block[p + 2] << 8) | block[p + 3];
  }
  for (let i = 16; i < 64; i++) {
    const x = w[i - 15];
    const y = w[i - 2];
    const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }
  let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (hh + S1 + ch + K256[i] + w[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    hh = g; g = f; f = e; e = (d + t1) | 0;
    d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
  h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
}

function digestBytes(h: Int32Array, out: Uint8Array, outOff = 0): void {
  for (let i = 0; i < 8; i++) {
    const v = h[i];
    out[outOff + i * 4] = v >>> 24;
    out[outOff + i * 4 + 1] = v >>> 16;
    out[outOff + i * 4 + 2] = v >>> 8;
    out[outOff + i * 4 + 3] = v;
  }
}

function writeBitLen(block: Uint8Array, byteLen: number): void {
  let bitLen = byteLen * 8;
  for (let i = 63; i >= 56; i--) {
    block[i] = bitLen & 0xff;
    bitLen = Math.floor(bitLen / 256);
  }
}

/** SHA-256 摘要，返回 32 字节。 */
export function sha256(data: Uint8Array): Uint8Array {
  const h = new Int32Array(IV256);
  let off = 0;
  while (data.length - off >= 64) {
    compress256(h, data, off);
    off += 64;
  }
  const rem = data.length - off;
  const tail = new Uint8Array(64);
  tail.set(data.subarray(off));
  tail[rem] = 0x80;
  if (rem >= 56) {
    compress256(h, tail, 0);
    tail.fill(0);
  }
  writeBitLen(tail, data.length);
  compress256(h, tail, 0);
  const out = new Uint8Array(32);
  digestBytes(h, out);
  return out;
}

/** HMAC 预计算中间态：ipad / opad 两个块各压缩一次，之后每条消息压到 2 次压缩。 */
interface HmacCtx {
  inner: Int32Array;
  outer: Int32Array;
}

function hmacInit(key: Uint8Array): HmacCtx {
  const k = new Uint8Array(64);
  if (key.length > 64) k.set(sha256(key));
  else k.set(key);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const inner = new Int32Array(IV256);
  const outer = new Int32Array(IV256);
  compress256(inner, ipad, 0);
  compress256(outer, opad, 0);
  return { inner, outer };
}

/** 处理长度 ≤55 字节的消息（PBKDF2 里恒为 32 字节），只压 2 个块。 */
function hmacRun(ctx: HmacCtx, msg: Uint8Array, msgLen: number): Uint8Array {
  const h = new Int32Array(ctx.inner);
  const blk = new Uint8Array(64);
  for (let i = 0; i < msgLen; i++) blk[i] = msg[i];
  blk[msgLen] = 0x80;
  // 注意：预计算中间态时，SHA-256 的长度字段必须按 ipad(64B)+msg 的总长计，
  // 否则算出来的不是 HMAC（这是最容易踩错的坑）。
  writeBitLen(blk, 64 + msgLen);
  compress256(h, blk, 0);
  const innerHash = new Uint8Array(32);
  digestBytes(h, innerHash);

  const h2 = new Int32Array(ctx.outer);
  const blk2 = new Uint8Array(64);
  blk2.set(innerHash);
  blk2[32] = 0x80;
  writeBitLen(blk2, 64 + 32);
  compress256(h2, blk2, 0);
  const out = new Uint8Array(32);
  digestBytes(h2, out);
  return out;
}

/** HMAC-SHA256，返回 32 字节。 */
export function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  if (msg.length <= 55) return hmacRun(hmacInit(key), msg, msg.length);
  // 长消息走通用路径（本产品的消息恒短，这里只为正确性兜底）
  const k = new Uint8Array(64);
  if (key.length > 64) k.set(sha256(key));
  else k.set(key);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const inner = new Uint8Array(64 + msg.length);
  inner.set(ipad);
  inner.set(msg, 64);
  const innerHash = sha256(inner);
  const outer = new Uint8Array(96);
  outer.set(opad);
  outer.set(innerHash, 64);
  return sha256(outer);
}

/** PBKDF2-HMAC-SHA256。 */
export function pbkdf2Sha256(password: Uint8Array, salt: Uint8Array, iterations: number, dkLen: number): Uint8Array {
  const out = new Uint8Array(dkLen);
  const ctx = hmacInit(password);
  const msg = new Uint8Array(32);
  let offset = 0;
  for (let blockIndex = 1; offset < dkLen; blockIndex++) {
    const saltBlock = new Uint8Array(salt.length + 4);
    saltBlock.set(salt);
    saltBlock[salt.length] = blockIndex >>> 24;
    saltBlock[salt.length + 1] = (blockIndex >>> 16) & 0xff;
    saltBlock[salt.length + 2] = (blockIndex >>> 8) & 0xff;
    saltBlock[salt.length + 3] = blockIndex & 0xff;
    let u = hmacRun(ctx, saltBlock, saltBlock.length <= 55 ? saltBlock.length : 0);
    if (saltBlock.length > 55) u = hmacSha256(password, saltBlock);
    const t = new Uint8Array(u);
    for (let i = 1; i < iterations; i++) {
      msg.set(u);
      u = hmacRun(ctx, msg, 32);
      for (let j = 0; j < 32; j++) t[j] ^= u[j];
    }
    const need = Math.min(32, dkLen - offset);
    out.set(t.subarray(0, need), offset);
    offset += need;
  }
  return out;
}

// ============================================================
// AES-256 基础件（S 盒运行时生成，T 表由此展开）
// ============================================================

/** GF(2^8) 乘法。 */
function gmul8(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

/** 运行时生成 S 盒（GF(2^8) 求逆 + 仿射变换），避免手抄 256 字节表出错。 */
function buildSBox(): Uint8Array {
  const sbox = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    let inv = 0;
    if (i !== 0) {
      let base = i;
      let exp = 254;
      inv = 1;
      while (exp > 0) {
        if (exp & 1) inv = gmul8(inv, base);
        base = gmul8(base, base);
        exp >>= 1;
      }
    }
    const x = inv;
    const s =
      x ^
      ((x << 1) | (x >>> 7)) ^
      ((x << 2) | (x >>> 6)) ^
      ((x << 3) | (x >>> 5)) ^
      ((x << 4) | (x >>> 4)) ^
      0x63;
    sbox[i] = s & 0xff;
  }
  return sbox;
}

const SBOX = buildSBox();

function xtime(x: number): number {
  return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0)) & 0xff;
}

/** T 表：把 SubBytes + MixColumns 合并成 4 次查表异或。 */
const T0 = new Uint32Array(256);
const T1 = new Uint32Array(256);
const T2 = new Uint32Array(256);
const T3 = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  const s = SBOX[i];
  const s2 = xtime(s);
  const s3 = s2 ^ s;
  T0[i] = ((s2 << 24) | (s << 16) | (s << 8) | s3) >>> 0; // 位置0 贡献：2s,s,s,3s
  T1[i] = ((s3 << 24) | (s2 << 16) | (s << 8) | s) >>> 0; // 位置1：3s,2s,s,s
  T2[i] = ((s << 24) | (s3 << 16) | (s2 << 8) | s) >>> 0; // 位置2：s,3s,2s,s
  T3[i] = ((s << 24) | (s << 16) | (s3 << 8) | s2) >>> 0; // 位置3：s,s,3s,2s
}

/** AES-256 密钥扩展：60 个 32-bit 轮密钥字。 */
function expandKey(key: Uint8Array): Uint32Array {
  if (key.length !== 32) throw new Error('AES-256 需要 32 字节密钥');
  const Nk = 8;
  const w = new Uint32Array(60);
  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
  const subBytesWord = (x: number) =>
    ((SBOX[(x >>> 24) & 0xff] << 24) |
      (SBOX[(x >>> 16) & 0xff] << 16) |
      (SBOX[(x >>> 8) & 0xff] << 8) |
      SBOX[x & 0xff]) >>> 0;
  for (let i = 0; i < Nk; i++) {
    w[i] = ((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) >>> 0;
  }
  for (let i = Nk; i < 60; i++) {
    let t = w[i - 1];
    if (i % Nk === 0) {
      t = ((t << 8) | (t >>> 24)) >>> 0; // RotWord
      t = subBytesWord(t);
      t = (t ^ (RCON[i / Nk - 1] << 24)) >>> 0;
    } else if (i % Nk === 4) {
      t = subBytesWord(t);
    }
    w[i] = (w[i - Nk] ^ t) >>> 0;
  }
  return w;
}

function readWord(b: Uint8Array, off: number): number {
  return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}

function writeWord(v: number, b: Uint8Array, off: number): void {
  b[off] = v >>> 24; b[off + 1] = v >>> 16; b[off + 2] = v >>> 8; b[off + 3] = v;
}

/** 快速单块加密（T 表版）。 */
function encryptBlock(w: Uint32Array, input: Uint8Array, inOff: number, out: Uint8Array, outOff: number): void {
  let s0 = (readWord(input, inOff) ^ w[0]) >>> 0;
  let s1 = (readWord(input, inOff + 4) ^ w[1]) >>> 0;
  let s2 = (readWord(input, inOff + 8) ^ w[2]) >>> 0;
  let s3 = (readWord(input, inOff + 12) ^ w[3]) >>> 0;

  let rk = 0;
  for (let round = 0; round < 13; round++) {
    rk += 4;
    const n0 =
      (T0[s0 >>> 24] ^ T1[(s1 >>> 16) & 0xff] ^ T2[(s2 >>> 8) & 0xff] ^ T3[s3 & 0xff] ^ w[rk]) >>> 0;
    const n1 =
      (T0[s1 >>> 24] ^ T1[(s2 >>> 16) & 0xff] ^ T2[(s3 >>> 8) & 0xff] ^ T3[s0 & 0xff] ^ w[rk + 1]) >>> 0;
    const n2 =
      (T0[s2 >>> 24] ^ T1[(s3 >>> 16) & 0xff] ^ T2[(s0 >>> 8) & 0xff] ^ T3[s1 & 0xff] ^ w[rk + 2]) >>> 0;
    const n3 =
      (T0[s3 >>> 24] ^ T1[(s0 >>> 16) & 0xff] ^ T2[(s1 >>> 8) & 0xff] ^ T3[s2 & 0xff] ^ w[rk + 3]) >>> 0;
    s0 = n0; s1 = n1; s2 = n2; s3 = n3;
  }
  rk += 4;
  const f0 =
    ((SBOX[s0 >>> 24] << 24) |
      (SBOX[(s1 >>> 16) & 0xff] << 16) |
      (SBOX[(s2 >>> 8) & 0xff] << 8) |
      SBOX[s3 & 0xff]) >>> 0;
  const f1 =
    ((SBOX[s1 >>> 24] << 24) |
      (SBOX[(s2 >>> 16) & 0xff] << 16) |
      (SBOX[(s3 >>> 8) & 0xff] << 8) |
      SBOX[s0 & 0xff]) >>> 0;
  const f2 =
    ((SBOX[s2 >>> 24] << 24) |
      (SBOX[(s3 >>> 16) & 0xff] << 16) |
      (SBOX[(s0 >>> 8) & 0xff] << 8) |
      SBOX[s1 & 0xff]) >>> 0;
  const f3 =
    ((SBOX[s3 >>> 24] << 24) |
      (SBOX[(s0 >>> 16) & 0xff] << 16) |
      (SBOX[(s1 >>> 8) & 0xff] << 8) |
      SBOX[s2 & 0xff]) >>> 0;
  writeWord((f0 ^ w[rk]) >>> 0, out, outOff);
  writeWord((f1 ^ w[rk + 1]) >>> 0, out, outOff + 4);
  writeWord((f2 ^ w[rk + 2]) >>> 0, out, outOff + 8);
  writeWord((f3 ^ w[rk + 3]) >>> 0, out, outOff + 12);
}

// ============================================================
// GCM（GHASH 用 GF(2^128) 半字节表实现）
// ============================================================

const R128 = 0xe1000000000000000000000000000000n;
const MASK128 = (1n << 128n) - 1n;

/** 参考实现（逐位），仅用于自检对照。 */
function gfMulRef(x: bigint, y: bigint): bigint {
  let z = 0n;
  let v = y;
  for (let i = 0; i < 128; i++) {
    if ((x >> BigInt(127 - i)) & 1n) z ^= v;
    if (v & 1n) v = (v >> 1n) ^ R128;
    else v >>= 1n;
  }
  return z;
}

function blockToWords(b: Uint8Array, off: number, out: Uint32Array): void {
  for (let i = 0; i < 4; i++) {
    const p = off + i * 4;
    out[i] = ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
  }
}

const MUL_V = new Uint32Array(4);
const MUL_Z = new Uint32Array(4);

/** z = z · y（GF(2^128)，32-bit 字位串实现，不用 BigInt）。 */
function mulWords(z: Uint32Array, y: Uint32Array): void {
  MUL_V.set(y);
  MUL_Z[0] = 0; MUL_Z[1] = 0; MUL_Z[2] = 0; MUL_Z[3] = 0;
  for (let i = 0; i < 128; i++) {
    if ((z[i >> 5] >>> (31 - (i & 31))) & 1) {
      MUL_Z[0] ^= MUL_V[0];
      MUL_Z[1] ^= MUL_V[1];
      MUL_Z[2] ^= MUL_V[2];
      MUL_Z[3] ^= MUL_V[3];
    }
    const lsb = MUL_V[3] & 1;
    MUL_V[3] = (MUL_V[3] >>> 1) | ((MUL_V[2] & 1) << 31);
    MUL_V[2] = (MUL_V[2] >>> 1) | ((MUL_V[1] & 1) << 31);
    MUL_V[1] = (MUL_V[1] >>> 1) | ((MUL_V[0] & 1) << 31);
    MUL_V[0] = MUL_V[0] >>> 1;
    if (lsb) MUL_V[0] ^= 0xe1000000;
  }
  z[0] = MUL_Z[0]; z[1] = MUL_Z[1]; z[2] = MUL_Z[2]; z[3] = MUL_Z[3];
}

const GH_LEN = new Uint8Array(16);

/** 乘 x（左移一位并归约），就地修改 4 字向量。 */
function mulXw(v: Uint32Array): void {
  const lsb = v[3] & 1;
  v[3] = (v[3] >>> 1) | ((v[2] & 1) << 31);
  v[2] = (v[2] >>> 1) | ((v[1] & 1) << 31);
  v[1] = (v[1] >>> 1) | ((v[0] & 1) << 31);
  v[0] = v[0] >>> 1;
  if (lsb) v[0] ^= 0xe1000000;
}

/** 逐字节表：RED8 处理右移 8 位的归约，NBYTE 处理 b·H。 */
interface GcmTables {
  red8: Uint32Array;
  nbyte: Uint32Array;
}

function buildGcmTables(hw: Uint32Array): GcmTables {
  // powers[k] = x^k · H
  const powers = new Uint32Array(8 * 4);
  powers.set(hw, 0);
  for (let k = 1; k < 8; k++) {
    powers.set(powers.subarray((k - 1) * 4, k * 4), k * 4);
    const v = powers.subarray(k * 4, k * 4 + 4);
    mulXw(v);
  }
  const nbyte = new Uint32Array(256 * 4);
  // 该表示下字节按 MSB 先行消耗，故 bit k 对应 x^(7-k)·H
  for (let b = 1; b < 256; b++) {
    const off = b * 4;
    for (let k = 0; k < 8; k++) {
      if ((b >> k) & 1) {
        const src = (7 - k) * 4;
        nbyte[off] ^= powers[src];
        nbyte[off + 1] ^= powers[src + 1];
        nbyte[off + 2] ^= powers[src + 2];
        nbyte[off + 3] ^= powers[src + 3];
      }
    }
  }
  const red8 = new Uint32Array(256 * 4);
  for (let t = 1; t < 256; t++) {
    const v = new Uint32Array(4);
    v[3] = t;
    for (let k = 0; k < 8; k++) mulXw(v);
    red8.set(v, t * 4);
  }
  return { red8, nbyte };
}

/** z = z · H（按字节 Horner：从最低字节向最高字节，16 步完成一次 128-bit 乘法）。 */
function mulByH(y: Uint32Array, t: GcmTables): Uint32Array {
  const z = new Uint32Array(4);
  for (let i = 15; i >= 0; i--) {
    const low = z[3] & 0xff;
    z[3] = ((z[3] >>> 8) | (z[2] << 24)) >>> 0;
    z[2] = ((z[2] >>> 8) | (z[1] << 24)) >>> 0;
    z[1] = ((z[1] >>> 8) | (z[0] << 24)) >>> 0;
    z[0] = z[0] >>> 8;
    const rp = low * 4;
    z[0] ^= t.red8[rp]; z[1] ^= t.red8[rp + 1]; z[2] ^= t.red8[rp + 2]; z[3] ^= t.red8[rp + 3];
    const b = (y[i >> 2] >>> (24 - 8 * (i & 3))) & 0xff;
    const np = b * 4;
    z[0] ^= t.nbyte[np]; z[1] ^= t.nbyte[np + 1]; z[2] ^= t.nbyte[np + 2]; z[3] ^= t.nbyte[np + 3];
  }
  return z;
}

/** GHASH（本产品不使用 AAD），返回 4 个 32-bit 字。 */
function ghash(t: GcmTables, ct: Uint8Array): Uint32Array {
  let y: Uint32Array = new Uint32Array(4);
  const blk = new Uint32Array(4);
  for (let off = 0; off < ct.length; off += 16) {
    for (let i = 0; i < 4; i++) {
      const p = off + i * 4;
      blk[i] = ((ct[p] << 24) | ((ct[p + 1] ?? 0) << 16) | ((ct[p + 2] ?? 0) << 8) | (ct[p + 3] ?? 0)) >>> 0;
    }
    y[0] ^= blk[0]; y[1] ^= blk[1]; y[2] ^= blk[2]; y[3] ^= blk[3];
    y = mulByH(y, t);
  }
  GH_LEN.fill(0);
  let bits = ct.length * 8;
  for (let i = 15; i >= 8; i--) {
    GH_LEN[i] = bits & 0xff;
    bits = Math.floor(bits / 256);
  }
  blk[0] = ((GH_LEN[0] << 24) | (GH_LEN[1] << 16) | (GH_LEN[2] << 8) | GH_LEN[3]) >>> 0;
  blk[1] = ((GH_LEN[4] << 24) | (GH_LEN[5] << 16) | (GH_LEN[6] << 8) | GH_LEN[7]) >>> 0;
  blk[2] = ((GH_LEN[8] << 24) | (GH_LEN[9] << 16) | (GH_LEN[10] << 8) | GH_LEN[11]) >>> 0;
  blk[3] = ((GH_LEN[12] << 24) | (GH_LEN[13] << 16) | (GH_LEN[14] << 8) | GH_LEN[15]) >>> 0;
  y[0] ^= blk[0]; y[1] ^= blk[1]; y[2] ^= blk[2]; y[3] ^= blk[3];
  return mulByH(y, t);
}

/** tag = GHASH(...) ^ E(K, J0)。 */
function tagFromWords(y: Uint32Array, ek0: Uint8Array, out: Uint8Array, outOff = 0): void {
  for (let i = 0; i < 4; i++) {
    const p = i * 4;
    const v = (y[i] ^ ((ek0[p] << 24) | (ek0[p + 1] << 16) | (ek0[p + 2] << 8) | ek0[p + 3])) >>> 0;
    out[outOff + p] = v >>> 24;
    out[outOff + p + 1] = v >>> 16;
    out[outOff + p + 2] = v >>> 8;
    out[outOff + p + 3] = v;
  }
}

function inc32(counter: Uint8Array): void {
  const c = (((counter[12] << 24) | (counter[13] << 16) | (counter[14] << 8) | counter[15]) + 1) >>> 0;
  counter[12] = (c >>> 24) & 0xff;
  counter[13] = (c >>> 16) & 0xff;
  counter[14] = (c >>> 8) & 0xff;
  counter[15] = c & 0xff;
}

function initGcm(key: Uint8Array, iv: Uint8Array) {
  if (iv.length !== 12) throw new Error('GCM 需要 12 字节 IV');
  const w = expandKey(key);
  const zero = new Uint8Array(16);
  const hb = new Uint8Array(16);
  encryptBlock(w, zero, 0, hb, 0);
  const hw = new Uint32Array(4);
  blockToWords(hb, 0, hw);
  const tables = buildGcmTables(hw);
  const j0 = new Uint8Array(16);
  j0.set(iv);
  j0[15] = 1;
  const ek0 = new Uint8Array(16);
  encryptBlock(w, j0, 0, ek0, 0);
  return { w, tables, j0, ek0 };
}

/** AES-256-GCM 加密，返回 密文||tag(16B)，与 WebCrypto 输出一致。 */
export function aesGcmEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const g = initGcm(key, iv);
  const ct = new Uint8Array(plaintext.length);
  const counter = new Uint8Array(g.j0);
  const ks = new Uint8Array(16);
  for (let off = 0; off < plaintext.length; off += 16) {
    inc32(counter);
    encryptBlock(g.w, counter, 0, ks, 0);
    const take = Math.min(16, plaintext.length - off);
    for (let i = 0; i < take; i++) ct[off + i] = plaintext[off + i] ^ ks[i];
  }
  const tag = new Uint8Array(16);
  tagFromWords(ghash(g.tables, ct), g.ek0, tag, 0);
  const out = new Uint8Array(ct.length + 16);
  out.set(ct);
  out.set(tag, ct.length);
  return out;
}

/** AES-256-GCM 解密；认证失败抛错。输入为 密文||tag。 */
export function aesGcmDecrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  if (data.length < 16) throw new Error('密文长度不足');
  const g = initGcm(key, iv);
  const ct = data.subarray(0, data.length - 16);
  const tag = data.subarray(data.length - 16);
  const expect = new Uint8Array(16);
  tagFromWords(ghash(g.tables, ct), g.ek0, expect, 0);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= expect[i] ^ tag[i];
  if (diff !== 0) throw new Error('GCM 认证失败');

  const pt = new Uint8Array(ct.length);
  const counter = new Uint8Array(g.j0);
  const ks = new Uint8Array(16);
  for (let off = 0; off < ct.length; off += 16) {
    inc32(counter);
    encryptBlock(g.w, counter, 0, ks, 0);
    const take = Math.min(16, ct.length - off);
    for (let i = 0; i < take; i++) pt[off + i] = ct[off + i] ^ ks[i];
  }
  return pt;
}

// ============================================================
// 仅供本机交叉验证使用（不参与 App 运行）
// ============================================================

/** 单块 AES-256 加密，便于和 Node crypto 对照。 */
export function __aes256Block(key: Uint8Array, block: Uint8Array): Uint8Array {
  const w = expandKey(key);
  const out = new Uint8Array(16);
  encryptBlock(w, block, 0, out, 0);
  return out;
}

/** S 盒。 */
export function __sbox(): Uint8Array {
  return SBOX;
}

/** 参考版 GHASH 乘法（逐位 BigInt）。 */
export function __gfMulRefBits(x: bigint, y: bigint): bigint {
  return gfMulRef(x, y);
}

/** 字版 GHASH 乘法：返回 x·h（均为 4 字，大端）。 */
export function __gfMulWords(x: Uint32Array, h: Uint32Array): Uint32Array {
  const z = new Uint32Array(x);
  mulWords(z, h);
  return z;
}

/** 字节表版 GHASH 乘法（自检用）。 */
export function __gfMulByte(x: Uint32Array, h: Uint32Array): Uint32Array {
  return mulByH(new Uint32Array(x), buildGcmTables(h));
}
