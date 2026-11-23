/**
 * 平台适配层：本地持久化 + 主密钥保管。
 *
 * 关键设计（对应 Vaultaire/Vaultis 已验证的零后端架构）：
 *  - 落盘的永远是「密文 blob + meta」，明文条目只在解锁后的内存里存在。
 *  - 主密码不落盘；只存派生用的随机盐（在 meta 里）。密码是否正确由 AES-GCM 的认证标签判断：
 *    密码错或密文被改都会导致解密抛 BAD_PASSWORD，无需额外自检标记。
 *  - 生物识别解锁：把「主密码」存进 Keychain（expo-secure-store），设为仅本设备、且读取须过 Face ID。
 *    读回主密码后仍走与手动解锁完全相同的 deriveKey → openBox 链路，不引入第二条解密路径。
 *
 * v0.3 存储架构（修复 P0）：
 *  - v0.1/v0.2 把「所有箱 + 附件密文」塞进单个 Keychain 项。expo-secure-store 官方文档明确
 *    大 payload 会被底层平台拒绝（历史上部分 iOS 版本拒绝 >~2048 字节），存一张照片即可能
 *    写入失败并静默丢数据。
 *  - v0.3 起：Keychain 只放小型主密码/生物标记；每个箱的密文写独立文件；索引写独立文件。
 *
 * v0.4 原子提交（本轮审计后修复的第二个 P0）：
 *  - v0.3 的 saveBox 是「覆盖式写入当前箱文件」。写入大密文中途崩溃/被系统杀掉时，
 *    旧密文已被截断，而索引仍指向它 → 该箱数据永久丢失。writeIndex 覆盖式写索引同理，
 *    一旦截断会让「所有保险箱」一起打不开。
 *  - 现在每个箱有两个文件槽 a/b：保存永远写入「当前生效槽的另一槽」，读回校验通过后才
 *    把索引切到新槽。任何时刻崩溃，索引都指向一份完好、完整、未被触碰的旧密文。
 *  - 索引提交前先把「当前可解析的索引」复制为 .bak；主索引损坏时 recoverVaultIndex 回退。
 *  - 无 slot 字段的 v0.3 旧索引条目会自动回落到旧单文件名，老用户升级后原有箱仍可读，
 *    第一次保存时才平滑切到双槽，无需数据迁移。
 *
 * iCloud 备份取舍（2026-11-12 查 Apple 官方 Optimizing Your App's Data for iCloud Backup 后定案）：
 *  - 官方明确「用户导入、且换机后难以重建的文件，不要排除备份」。本 App 零云、无账号，
 *    系统设备备份是用户唯一的跨设备恢复途径；解密只依赖 口令 + salt + blob，不依赖 Keychain，
 *    因此备份恢复到新设备后输密码仍能打开。**主动设置 isExcludedFromBackup 是错误的，不做。**
 *  - 同理索引不额外加密：若用仅本设备的 Keychain 密钥加密，恢复后密钥不在，数据将永久解不开。
 *  - 可再生的「导出备份临时文件」放 cacheDirectory 并即用即删，不占 Documents、不进备份。
 *
 * 本文件依赖 Expo 原生模块，无法在 Windows 本机 Node 真跑；其纯逻辑对应物在 domain.ts，
 * 由 测试/domain.test.ts 本机单测覆盖（含双槽轮换、索引回退、大小前置判定）。
 */
import * as SecureStore from 'expo-secure-store';
import * as LocalAuthentication from 'expo-local-authentication';
import * as FileSystem from 'expo-file-system/legacy';
import {
  type EncryptedBlob, type SealboxMeta, type VaultItem, type BackupFile, type VaultIndex,
  parseBackup, DomainError, VAULT_INDEX_FILE, safeVaultId,
  vaultSlotFileName, nextSlot, vaultFilePathFor, allVaultFileNames,
  recoverVaultIndex, decodeVaultIndex, encodeVaultIndex, encodeVaultFile, decodeVaultFile,
  assertWithinStorageLimit, assertFileSizeWithinLimit,
} from '../domain';

const LEGACY_BLOBS_KEY = 'sealbox.blobs.v1';  // v0.1/v0.2 旧格式，仅用于一次性迁移
const KEYCHAIN_PREFIX = 'sealbox.pw.';        // 每个箱一份主密码（生物识别门控，存于 Keychain）
const BIO_FLAG_PREFIX = 'sealbox.bio.';       // 独立标记：判断是否已开启 Face ID，不触碰门控项
const INDEX_BAK_SUFFIX = '.bak';
const EXPORT_PREFIX = 'redoubt-export-';
const EXPORT_SUFFIX = '.redoubt.json';

interface StoredBox { name: string; meta: SealboxMeta; blob: EncryptedBlob }

const UTF8 = { encoding: FileSystem.EncodingType.UTF8 };

function docDir(): string {
  const d = FileSystem.documentDirectory;
  if (!d) throw new DomainError('BAD_FORMAT', '文件系统不可用');
  return d;
}
function cacheDir(): string {
  const d = FileSystem.cacheDirectory;
  if (!d) throw new DomainError('BAD_FORMAT', '临时目录不可用');
  return d;
}
const indexPath = (): string => docDir() + VAULT_INDEX_FILE;
const indexBakPath = (): string => indexPath() + INDEX_BAK_SUFFIX;

async function readTextOrNull(p: string): Promise<string | null> {
  const info = await FileSystem.getInfoAsync(p);
  if (!info.exists) return null;
  return FileSystem.readAsStringAsync(p, UTF8);
}

async function readIndex(): Promise<VaultIndex> {
  const info = await FileSystem.getInfoAsync(indexPath());
  if (!info.exists) {
    // 主索引丢失但 .bak 还在（覆盖写中途被杀）→ 仍可恢复，绝不返回空集合
    const bak = await readTextOrNull(indexBakPath());
    if (bak !== null) return recoverVaultIndex(null, bak);
    return migrateLegacyIfAny();
  }
  return recoverVaultIndex(
    await readTextOrNull(indexPath()),
    await readTextOrNull(indexBakPath()),
  );
}

/**
 * 索引是提交点：先把当前「可解析」的索引复制成 .bak，再覆盖主索引并读回逐字节校验。
 * 只备份可解析版本，避免把损坏内容写进 .bak，把唯一一份好的备份也弄坏。
 */
async function writeIndex(index: VaultIndex): Promise<void> {
  const text = encodeVaultIndex(index);
  const p = indexPath();
  const current = await readTextOrNull(p);
  if (current !== null) {
    try {
      decodeVaultIndex(current);
      await FileSystem.writeAsStringAsync(indexBakPath(), current, UTF8);
    } catch { /* 当前已损坏 → 保留上一份完好的 .bak，不覆盖 */ }
  }
  await FileSystem.writeAsStringAsync(p, text, UTF8);
  const back = await FileSystem.readAsStringAsync(p, UTF8);
  if (back !== text) throw new DomainError('BAD_FORMAT', '保险箱索引写入校验失败');
}

/** 一次性迁移 v0.1/v0.2 的「所有箱塞在单个 Keychain 项」格式；无旧数据则为空索引。 */
async function migrateLegacyIfAny(): Promise<VaultIndex> {
  const raw = await SecureStore.getItemAsync(LEGACY_BLOBS_KEY);
  if (!raw) return {};
  let old: Record<string, StoredBox>;
  try { old = JSON.parse(raw) as Record<string, StoredBox>; }
  catch { throw new DomainError('BAD_FORMAT', '旧版保险箱数据损坏，无法自动迁移'); }
  const index: VaultIndex = {};
  for (const [id, b] of Object.entries(old)) {
    safeVaultId(id);
    const text = encodeVaultFile(b.blob);
    const target = docDir() + vaultSlotFileName(id, 'a');
    await FileSystem.writeAsStringAsync(target, text, UTF8);
    if ((await FileSystem.readAsStringAsync(target, UTF8)) !== text) {
      throw new DomainError('BAD_FORMAT', '旧版保险箱迁移写入校验失败');
    }
    index[id] = { name: b.name, meta: b.meta, slot: 'a' };
  }
  await writeIndex(index);
  await SecureStore.deleteItemAsync(LEGACY_BLOBS_KEY).catch(() => {});
  return index;
}

/**
 * 保存一个保险箱（只写密文）。
 * 顺序：读索引 → 选「另一槽」写入并读回校验 → 提交索引指向新槽。
 * 写入期间旧槽文件完全不动；即使进程被杀，索引仍指向完好的旧版本。
 */
export async function saveBox(id: string, name: string, meta: SealboxMeta, blob: EncryptedBlob): Promise<void> {
  safeVaultId(id);
  const index = await readIndex();
  const slot = nextSlot(index[id]?.slot);
  const target = docDir() + vaultSlotFileName(id, slot);
  const text = encodeVaultFile(blob);
  await FileSystem.writeAsStringAsync(target, text, UTF8);
  if ((await FileSystem.readAsStringAsync(target, UTF8)) !== text) {
    throw new DomainError('BAD_FORMAT', '保险箱密文写入校验失败');
  }
  index[id] = { name, meta, slot };
  await writeIndex(index);
}

export async function listBoxes(): Promise<Array<{ id: string; name: string; meta: SealboxMeta }>> {
  const index = await readIndex();
  return Object.entries(index).map(([id, e]) => ({ id, name: e.name, meta: e.meta }));
}

/** 先从索引移除（提交点），再清理 a/b/旧格式三个文件与 Keychain；残留文件无害。 */
export async function deleteBox(id: string): Promise<void> {
  const index = await readIndex();
  delete index[id];
  await writeIndex(index);
  for (const f of allVaultFileNames(id)) {
    await FileSystem.deleteAsync(docDir() + f, { idempotent: true }).catch(() => {});
  }
  await SecureStore.deleteItemAsync(KEYCHAIN_PREFIX + id).catch(() => {});
  await SecureStore.deleteItemAsync(BIO_FLAG_PREFIX + id).catch(() => {});
}

export async function getBox(id: string): Promise<StoredBox | null> {
  const index = await readIndex();
  const entry = index[id];
  if (!entry) return null;
  const p = docDir() + vaultFilePathFor(id, entry);
  const info = await FileSystem.getInfoAsync(p);
  // 索引在但密文不在 = 数据损坏，必须明确报错，不能当成「箱不存在」
  if (!info.exists) throw new DomainError('BAD_FORMAT', '保险箱密文文件缺失');
  const blob = decodeVaultFile(await FileSystem.readAsStringAsync(p, UTF8));
  return { name: entry.name, meta: entry.meta, blob };
}

/** 用密码打开：读密文 → 交给 domain.openBox 解密。 */
export async function openWithPassword(id: string, password: string): Promise<VaultItem[]> {
  const { openBox } = await import('../domain');
  const box = await getBox(id);
  if (!box) throw new DomainError('EMPTY_BOX', '保险箱不存在');
  return openBox(box.blob, box.meta, password);
}

// ---------- 生物识别解锁 ----------

export async function isBiometricAvailable(): Promise<boolean> {
  const has = await LocalAuthentication.hasHardwareAsync();
  const enrolled = await LocalAuthentication.isEnrolledAsync();
  return has && enrolled;
}

/**
 * 首次用密码成功解锁后，把主密码存进 Keychain 并开启生物识别门控。
 * 另写一个不带门控的小标记，供 biometricEnabled() 查询 —— 避免读取门控项时误弹 Face ID。
 */
export async function enableBiometric(id: string, passphrase: string): Promise<void> {
  await SecureStore.setItemAsync(KEYCHAIN_PREFIX + id, passphrase, {
    keychainAccessible: SecureStore.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
    requireAuthentication: true, // 读取时必须再过一次系统生物识别
  });
  await SecureStore.setItemAsync(BIO_FLAG_PREFIX + id, '1', {
    keychainAccessible: SecureStore.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY,
  });
}

export async function biometricEnabled(id: string): Promise<boolean> {
  return (await SecureStore.getItemAsync(BIO_FLAG_PREFIX + id)) !== null;
}

/** 触发系统 Face ID/Touch ID，成功后返回缓存的主密码。 */
export async function unlockWithBiometric(id: string): Promise<string | null> {
  try {
    const pw = await SecureStore.getItemAsync(KEYCHAIN_PREFIX + id); // 系统弹 Face ID
    if (pw === null) await disableBiometric(id); // 生物识别设置变更后门控项失效 → 清理标记
    return pw;
  } catch {
    return null; // 用户取消或生物识别失败
  }
}

/** 关闭某个保险箱的 Face ID 解锁（在设置里可用）。 */
export async function disableBiometric(id: string): Promise<void> {
  await SecureStore.deleteItemAsync(KEYCHAIN_PREFIX + id).catch(() => {});
  await SecureStore.deleteItemAsync(BIO_FLAG_PREFIX + id).catch(() => {});
}

// ---------- 加密备份：导出仍加密，导入仍加密 ----------

/**
 * 导出文件是「可再生的临时文件」，按 Apple Data Storage Guidelines 应放 Caches
 * 而非 Documents（Documents 会被 iCloud 备份）。v0.3 写在 Documents，且分享抛异常时
 * deleteFile 不执行，会在用户设备与备份里永久堆积加密备份副本。
 */
async function cleanupStaleExports(dir: string): Promise<void> {
  const names = await FileSystem.readDirectoryAsync(dir);
  for (const n of names) {
    if (n.startsWith(EXPORT_PREFIX) && n.endsWith(EXPORT_SUFFIX)) {
      await FileSystem.deleteAsync(dir + n, { idempotent: true }).catch(() => {});
    }
  }
}

export async function exportBackupFile(backup: BackupFile): Promise<string> {
  const payload = JSON.stringify(backup);
  assertWithinStorageLimit(payload, '备份文件');
  const dir = cacheDir();
  await cleanupStaleExports(dir).catch(() => {}); // 清掉上次分享异常遗留的临时文件
  const uri = `${dir}${EXPORT_PREFIX}${Date.now()}${EXPORT_SUFFIX}`;
  await FileSystem.writeAsStringAsync(uri, payload, UTF8);
  return uri;
}

/** 先按磁盘字节数拦截，再读入内存：v0.3 先读全文才判大小，选到超大文件会直接 OOM 崩溃。 */
export async function importBackupFile(uri: string): Promise<BackupFile> {
  const info = await FileSystem.getInfoAsync(uri);
  if (!info.exists) throw new DomainError('BAD_FORMAT', '备份文件不存在');
  assertFileSizeWithinLimit(info.size ?? 0, '备份文件');
  const text = await FileSystem.readAsStringAsync(uri, UTF8);
  return parseBackup(text); // 内部按文本长度二次校验，双保险
}

export async function deleteFile(uri: string): Promise<void> {
  await FileSystem.deleteAsync(uri, { idempotent: true });
}
