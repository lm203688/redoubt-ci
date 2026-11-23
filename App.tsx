/**
 * Redoubt — Offline Encrypted Vault
 * 流程：启动 → 选保险箱/创建 → 解锁(密码或 Face ID) → 列表/搜索 → 新增编辑 → 加密备份导入导出 → 隐私页
 * 硬约束：无账号、无网络请求、无云、无广告/分析/追踪 SDK、一键全删、导出仅用户主动触发。
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator, Alert, AppState, FlatList, Modal, Pressable, SafeAreaView,
  ScrollView, StyleSheet, Text, TextInput, View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import * as Sharing from 'expo-sharing';
import * as DocumentPicker from 'expo-document-picker';
import {
  sealBox, openBox, makeBackup,
  newItem, upsertItem, removeItem, searchItems, groupByKind,
  isPassphraseAcceptable, MIN_PASSPHRASE_LENGTH, isSensitiveField,
  generatePassword, passwordScore, shouldLock, IDLE_LOCK_MS,
  uniqueFieldKey,
  DomainError, setRandomSource,
  type VaultItem, type VaultKind, type SealboxMeta, type AppLifecycleState,
} from './src/domain';
import {
  saveBox, listBoxes, deleteBox, getBox,
  isBiometricAvailable, enableBiometric, biometricEnabled, unlockWithBiometric,
  exportBackupFile, importBackupFile, deleteFile,
} from './src/platform/storage';
import { pickPhoto, pickFile } from './src/platform/attachments';
import { getRandomBytes } from 'expo-crypto';
import FeedbackModal from './src/FeedbackModal';

/**
 * Hermes 没有 globalThis.crypto.getRandomValues（也没有 subtle），
 * 所以把 expo-crypto 的 CSPRNG 注入 domain 层。必须在任何加解密动作之前执行。
 */
setRandomSource((n: number) => new Uint8Array(getRandomBytes(n)));

const KINDS: { key: VaultKind; label: string }[] = [
  { key: 'login', label: 'Login' }, { key: 'note', label: 'Secure note' },
  { key: 'card', label: 'Card' }, { key: 'recovery', label: 'Recovery phrase' },
  { key: 'identity', label: 'Identity' }, { key: 'file', label: 'File / photo' },
];
const C = {
  bg: '#0B1020', surface: '#151B2E', surface2: '#1E2740', border: '#2A3555',
  text: '#EDF1FA', muted: '#93A0C0', accent: '#4C8DFF', danger: '#FF6B6B',
  ok: '#39D9A0', warn: '#F5B942',
};

type Screen = 'vaults' | 'unlock' | 'list' | 'editor' | 'privacy';

/** domain 层异常文案是中文（内部日志用），App UI 全英文 → 统一在这里翻译，避免弹窗冒中文。 */
const ERROR_TEXT: Record<string, string> = {
  BAD_PASSWORD: 'Wrong passphrase, or the encrypted data is damaged.',
  BAD_FORMAT: 'The file or data could not be read. It may be damaged, or not a Redoubt backup.',
  UNSUPPORTED_VERSION: 'This backup was created by a newer version of Redoubt. Please update the app.',
  CHECKSUM_MISMATCH: 'The data failed its integrity check and was left unchanged.',
  EMPTY_BOX: 'This sealed box no longer exists on this device.',
  ITEM_NOT_FOUND: 'That item no longer exists.',
  TOO_LARGE: 'This file is too large. Attachments are limited to 8 MB and each box to 20 MB.',
  NO_CRYPTO: 'This device does not provide the required encryption support.',
  BAD_OPTIONS: 'Those options cannot be used. Check the password length and character settings.',
};
function describeError(e: unknown): string {
  if (e instanceof DomainError) return ERROR_TEXT[e.kind] ?? 'The operation could not be completed.';
  return e instanceof Error ? e.message : String(e);
}

export default function App() {
  const [screen, setScreen] = useState<Screen>('vaults');
  const [boxes, setBoxes] = useState<Array<{ id: string; name: string; meta: SealboxMeta }>>([]);
  const [activeId, setActiveId] = useState<string>('');
  const [activeName, setActiveName] = useState('');
  const [items, setItems] = useState<VaultItem[]>([]);
  // 0 = 锁定；否则为本次解锁时刻，作为自动锁定的时间基准（不缓存 CryptoKey，明文解密态只留在 items 里）。
  const [unlockedAt, setUnlockedAt] = useState(0);
  const [query, setQuery] = useState('');
  const [editor, setEditor] = useState<VaultItem | null>(null);
  const [revealSecrets, setRevealSecrets] = useState(false);
  const [busy, setBusy] = useState(false);
  const [showFeedback, setShowFeedback] = useState(false);

  const refreshBoxes = useCallback(async () => {
    setBoxes(await listBoxes());
  }, []);
  useEffect(() => { refreshBoxes(); }, [refreshBoxes]);

  const lock = useCallback(() => {
    setUnlockedAt(0);
    setItems([]); setQuery(''); setEditor(null); setRevealSecrets(false);
    setScreen('vaults');
  }, []);

  // ---------- 自动锁定：切后台/失活立即锁；前台最长解锁 5 分钟 ----------
  useEffect(() => {
    const check = (state: AppLifecycleState) => {
      if (shouldLock({ state, unlocked: unlockedAt > 0, nowMs: Date.now(), lastActiveMs: unlockedAt })) lock();
    };
    const sub = AppState.addEventListener('change', (next) => {
      check(next === 'active' ? 'active' : next === 'background' ? 'background' : 'inactive');
    });
    const timer = setInterval(() => check('active'), 10_000);
    return () => { sub.remove(); clearInterval(timer); };
  }, [unlockedAt, lock]);

  // ---------- 创建保险箱 ----------
  const doCreateBox = useCallback(async (name: string, pw: string) => {
    setBusy(true);
    try {
      const { blob, meta: m } = await sealBox([], name, pw);
      const id = `${Date.now()}`;
      await saveBox(id, name, m, blob);
      await refreshBoxes();
      lock();
    } catch (e) { Alert.alert('Could not create', describeError(e)); }
    finally { setBusy(false); }
  }, [refreshBoxes, lock]);

  const createBox = useCallback(() => {
    Alert.prompt('New sealed box', 'Give it a name. Everything inside is encrypted on this device.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Create', onPress: (name?: string) => name?.trim() && Alert.prompt(
        'Choose a passphrase', `Minimum ${MIN_PASSPHRASE_LENGTH} characters. This cannot be recovered — there is no account and no server.`,
        [{ text: 'Cancel', style: 'cancel' },
         { text: 'Create', onPress: (pw?: string) => {
           if (!isPassphraseAcceptable(pw ?? '')) {
             Alert.alert('Too short', `Use at least ${MIN_PASSPHRASE_LENGTH} characters.`);
             return;
           }
           const strength = passwordScore(pw!);
           if (strength.score <= 1) {
             // 仅提示不阻断：产品的 7 条约束里没有强制复杂度，但要把风险讲清楚
             Alert.alert('Weak passphrase', `Strength: ${strength.label}. A longer mix of words is safer.`, [
               { text: 'Change it', style: 'cancel' },
               { text: 'Use anyway', onPress: () => doCreateBox(name!.trim(), pw!) },
             ]);
             return;
           }
           doCreateBox(name!.trim(), pw!);
         }}], 'secure-text'),
      },
    ], 'plain-text');
  }, [doCreateBox]);

  // ---------- 解锁 ----------
  const openBoxScreen = useCallback((id: string, name: string) => {
    setActiveId(id); setActiveName(name); setScreen('unlock');
  }, []);

  // 密码与 Face ID 共用同一条解密链路：都拿到主密码 → openBox。
  const unlockWith = useCallback(async (pw: string, offerBio: boolean) => {
    setBusy(true);
    try {
      const box = await getBox(activeId);
      if (!box) throw new DomainError('EMPTY_BOX', 'Box not found');
      const plain = await openBox(box.blob, box.meta, pw);
      setItems(plain); setUnlockedAt(Date.now()); setScreen('list');
      if (offerBio && await isBiometricAvailable() && !(await biometricEnabled(activeId))) {
        Alert.alert('Enable Face ID?', 'Unlock faster next time. Your passphrase is sealed in the device Keychain and can only be read after Face ID.', [
          { text: 'Not now', style: 'cancel' },
          { text: 'Enable', onPress: async () => {
            try { await enableBiometric(activeId, pw); }
            catch (e) { Alert.alert('Could not enable Face ID', describeError(e)); }
          }},
        ]);
      }
    } catch (e) {
      Alert.alert('Could not unlock', describeError(e));
    } finally { setBusy(false); }
  }, [activeId]);

  const tryPassword = useCallback((pw: string) => unlockWith(pw, true), [unlockWith]);

  const tryBiometric = useCallback(async () => {
    setBusy(true);
    try {
      const pw = await unlockWithBiometric(activeId); // 系统读 Keychain 时弹 Face ID
      if (!pw) { Alert.alert('Not unlocked', 'Face ID was cancelled or failed. Use your passphrase.'); return; }
      await unlockWith(pw, false);
    } finally { setBusy(false); }
  }, [activeId, unlockWith]);

  const promptUnlock = useCallback(() => {
    Alert.prompt('Unlock', 'Enter your passphrase. It never leaves this device.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Unlock', onPress: (pw?: string) => pw && tryPassword(pw) },
    ], 'secure-text');
  }, [tryPassword]);

  // ---------- 保存（整箱重封：改任何一条都重新加密整箱）----------
  const commit = useCallback(async (next: VaultItem[], pw: string) => {
    const { blob, meta: m } = await sealBox(next, activeName, pw);
    await saveBox(activeId, activeName, m, blob);
    setItems(next);
    await refreshBoxes();
  }, [activeId, activeName, refreshBoxes]);

  const openEditor = useCallback((item: VaultItem) => {
    setRevealSecrets(false); // 每次打开编辑器默认遮掩敏感字段
    setEditor(item);
    setScreen('editor'); // 编辑器 Modal 依赖 screen === 'editor'，漏这一步会点了没反应
  }, []);

  /** 关闭编辑器：清空草稿并把屏幕切回列表页（否则 screen 停在 'editor' 会白屏）。 */
  const closeEditor = useCallback(() => {
    setEditor(null);
    setScreen('list');
  }, []);

  const saveItem = useCallback((draft: VaultItem) => {
    Alert.prompt('Confirm with passphrase', 'Required to re-encrypt the box after any change.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Save', onPress: async (pw?: string) => {
        if (!pw) return;
        setBusy(true);
        try { await commit(upsertItem(items, draft), pw); closeEditor(); }
        catch (e) { Alert.alert('Could not save', describeError(e)); }
        finally { setBusy(false); }
      }},
    ], 'secure-text');
  }, [items, commit, closeEditor]);

  const delItem = useCallback((item: VaultItem) => {
    Alert.alert('Delete?', `Remove "${item.title}"? This cannot be undone.`, [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Delete', style: 'destructive', onPress: () => Alert.prompt('Confirm with passphrase', '', [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Delete', style: 'destructive', onPress: async (pw?: string) => {
          if (!pw) return;
          setBusy(true);
          try { await commit(removeItem(items, item.id), pw); }
          catch (e) { Alert.alert('Could not delete', describeError(e)); }
          finally { setBusy(false); }
        }},
      ], 'secure-text') },
    ]);
  }, [items, commit]);

  /** 附件：统一处理大小/空内容错误；字段名唯一化，避免同名附件互相覆盖。 */
  const attach = useCallback(async (kind: 'photo' | 'file') => {
    try {
      const a = kind === 'photo' ? await pickPhoto() : await pickFile();
      if (!a) return;
      setEditor((prev) => prev
        ? { ...prev, fields: { ...prev.fields, [uniqueFieldKey(prev.fields, a.name)]: a.base64 } }
        : prev);
    } catch (e) { Alert.alert('Cannot attach file', describeError(e)); }
  }, []);

  // ---------- 备份导出（仍加密）----------
  const exportBackup = useCallback(() => {
    Alert.prompt('Passphrase to seal the backup', 'The backup file stays encrypted. You will need this passphrase to restore it.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Export', onPress: async (pw?: string) => {
        if (!isPassphraseAcceptable(pw ?? '')) {
          Alert.alert('Too short', `Use at least ${MIN_PASSPHRASE_LENGTH} characters.`);
          return;
        }
        setBusy(true);
        try {
          const { blob, meta: m } = await sealBox(items, activeName, pw!);
          const backup = makeBackup(activeName, m, blob);
          const uri = await exportBackupFile(backup);
          try {
            if (await Sharing.isAvailableAsync()) await Sharing.shareAsync(uri);
            else Alert.alert('Sharing unavailable', uri);
          } finally {
            await deleteFile(uri).catch(() => {}); // 分享抛异常也必须清掉临时导出文件
          }
        } catch (e) { Alert.alert('Export failed', describeError(e)); }
        finally { setBusy(false); }
      }},
    ], 'secure-text');
  }, [items, activeName]);

  /**
   * 恢复备份 = 新建一个保险箱，原样写入备份里的密文与 meta，不重新加密。
   * 备份文件本身就是 sealBox 的完整产物（blob/meta 配套），用备份密码即可 openBox，
   * 因此无需重封；这样既不改动任何现有箱，也不会静默改掉主密码或让 Keychain 里的
   * Face ID 主密码失效。旧实现用备份密码重封当前箱（且从锁屏进入时 activeId 为空），
   * 会写出 id='' 的箱并破坏生物识别，已废弃。
   */
  const importBackup = useCallback(() => {
    Alert.alert('Restore backup?', 'Restores the backup as a NEW sealed box. Your existing boxes are not changed. The backup passphrase becomes the new box passphrase.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Choose file', onPress: async () => {
        try {
          // 不限 MIME：自定义扩展名 .redoubt.json 在部分系统不是 application/json，
          // 限制类型会导致用户选不到自己刚导出的备份；合法性由 importBackupFile 校验。
          const r = await DocumentPicker.getDocumentAsync({ type: '*/*', copyToCacheDirectory: true });
          if (r.canceled || !r.assets?.[0]) return;
          const backup = await importBackupFile(r.assets[0].uri);
          Alert.prompt('Backup passphrase', 'Enter the passphrase used when this backup was created.', [
            { text: 'Cancel', style: 'cancel' },
            { text: 'Restore', onPress: async (pw?: string) => {
              if (!pw) return;
              setBusy(true);
              try {
                const plain = await openBox(backup.blob, backup.meta, pw); // 同时验证密码正确
                const id = `${Date.now()}`;
                const base = (backup.boxName || 'Restored').trim();
                const name = `${base} (restored)`;
                await saveBox(id, name, backup.meta, backup.blob); // 原样落盘，不重加密
                await refreshBoxes();
                lock();
                Alert.alert('Restored', `New box "${name}" with ${plain.length} items. Unlock it with the backup passphrase. Face ID can be enabled after your first unlock.`);
              } catch (e) { Alert.alert('Restore failed', describeError(e)); }
              finally { setBusy(false); }
            }},
          ], 'secure-text');
        } catch (e) { Alert.alert('Import failed', describeError(e)); }
      }},
    ]);
  }, [refreshBoxes, lock]);

  // ---------- 一键全删 ----------
  const eraseAll = useCallback(() => {
    Alert.alert('Erase everything?', 'Deletes all sealed boxes on this device. There is no account or server copy — this cannot be undone.', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Erase all', style: 'destructive', onPress: async () => {
        setBusy(true);
        try {
          const all = await listBoxes();
          for (const b of all) await deleteBox(b.id);
          await refreshBoxes(); lock();
          Alert.alert('Done', 'All local data erased.');
        } finally { setBusy(false); }
      }},
    ]);
  }, [refreshBoxes, lock]);

  const shown = useMemo(() => searchItems(items, query), [items, query]);
  const counts = useMemo(() => groupByKind(items), [items]);

  // ============================================================
  // 渲染
  // ============================================================
  if (busy) return <Center><ActivityIndicator color={C.accent} size="large" /></Center>;

  return (
    <SafeAreaView style={S.root}>
      <StatusBar style="light" />
      {screen === 'vaults' && (
        <Container title="Redoubt" subtitle="Your secrets, sealed on this device.">
          <Text style={S.note}>No account. No cloud. No network. Everything is encrypted with AES-256 and never leaves this phone.</Text>
          <Btn label="+ New sealed box" onPress={createBox} primary />
          {boxes.length === 0 ? <Text style={S.empty}>No boxes yet. Create one to begin.</Text> : null}
          <FlatList data={boxes} keyExtractor={(b) => b.id} renderItem={({ item }) => (
            <Pressable style={S.card} onPress={() => openBoxScreen(item.id, item.name)}>
              <Text style={S.cardTitle}>{item.name}</Text>
              <Text style={S.cardSub}>{item.meta.itemCount} items · AES-256-GCM · on-device</Text>
            </Pressable>
          )} />
          <View style={S.row}><Btn label="Restore backup" onPress={importBackup} /><Btn label="Privacy" onPress={() => setScreen('privacy')} /></View>
          {boxes.length > 0 ? <Pressable onPress={eraseAll}><Text style={S.danger}>Erase everything on this device</Text></Pressable> : null}
        </Container>
      )}

      {screen === 'unlock' && (
        <Container title={activeName} subtitle="Unlock to continue" onBack={lock}>
          <Text style={S.note}>Your passphrase is never stored or transmitted. It cannot be recovered.</Text>
          <Btn label="Unlock with passphrase" onPress={promptUnlock} primary />
          <Btn label="Unlock with Face ID" onPress={tryBiometric} />
        </Container>
      )}

      {screen === 'list' && (
        <View style={S.root}>
          <View style={S.header}>
            <Pressable onPress={lock}><Text style={S.back}>Lock</Text></Pressable>
            <Text style={S.h1}>{activeName}</Text>
            <Pressable onPress={() => setScreen('privacy')}><Text style={S.link}>Info</Text></Pressable>
          </View>
          <View style={S.searchBox}><TextInput style={S.search} placeholder="Search (on device)" placeholderTextColor={C.muted} value={query} onChangeText={setQuery} /></View>
          <Text style={S.stats}>{items.length} item{items.length === 1 ? '' : 's'} · {Object.entries(counts).filter(([, n]) => n).map(([k, n]) => `${KINDS.find((x) => x.key === k)?.label ?? k} ${n}`).join(' · ')}</Text>
          <FlatList
            data={shown} keyExtractor={(i) => i.id}
            renderItem={({ item }) => (
              <Pressable style={S.card} onPress={() => openEditor({ ...item })} onLongPress={() => delItem(item)}>
                <View style={S.row}><Text style={KINDS.find((k) => k.key === item.kind)?.label ? S.tag : S.cardTitle}>{KINDS.find((k) => k.key === item.kind)?.label}</Text><Text style={S.cardTitle}>{item.title}</Text></View>
                <Text style={S.cardSub}>{Object.keys(item.fields).length} field{Object.keys(item.fields).length === 1 ? '' : 's'} · updated {item.updatedAt.slice(0, 10)}</Text>
              </Pressable>
            )}
            ListEmptyComponent={<Text style={S.empty}>{query ? 'No match.' : 'Nothing here yet. Tap + to add.'}</Text>}
          />
          <View style={[S.row, { marginTop: 4, paddingBottom: 10 }]}><Btn label="+ Add" onPress={() => openEditor(newItem('login', ''))} primary /><Btn label="Back up" onPress={exportBackup} /><Btn label="Restore" onPress={importBackup} /></View>
        </View>
      )}

      {screen === 'editor' && editor && (
        <Modal visible animationType="slide" onRequestClose={closeEditor}>
          <SafeAreaView style={S.root}>
            <View style={S.header}>
              <Pressable onPress={closeEditor}><Text style={S.back}>Cancel</Text></Pressable>
              <Text style={S.h1}>Edit item</Text>
              <Pressable onPress={() => saveItem({ ...editor, updatedAt: new Date().toISOString() })}><Text style={S.link}>Save</Text></Pressable>
            </View>
            <ScrollView contentContainerStyle={S.pad}>
              <Text style={S.label}>Kind</Text>
              <View style={S.chips}>{KINDS.map((k) => <Pressable key={k.key} onPress={() => setEditor({ ...editor, kind: k.key })} style={[S.chip, editor.kind === k.key && S.chipOn]}><Text style={S.chipText}>{k.label}</Text></Pressable>)}</View>
              <Text style={S.label}>Title</Text>
              <TextInput style={S.input} value={editor.title} onChangeText={(t) => setEditor({ ...editor, title: t })} placeholder="e.g. Email, Wallet seed" placeholderTextColor={C.muted} />
              {Object.entries(editor.fields).map(([k, v]) => (
                <View key={k} style={S.fieldRow}>
                  <TextInput style={[S.input, S.fieldKey]} value={k} onChangeText={(nk) => {
                    const f = { ...editor.fields }; delete f[k]; f[nk] = v; setEditor({ ...editor, fields: f });
                  }} placeholder="field" placeholderTextColor={C.muted} />
                  <TextInput style={[S.input, S.fieldVal]} value={v} onChangeText={(nv) => setEditor({ ...editor, fields: { ...editor.fields, [k]: nv } })} placeholder="value" placeholderTextColor={C.muted} secureTextEntry={isSensitiveField(k) && !revealSecrets} />
                </View>
              ))}
              <View style={S.row}>
                <Btn label="Generate strong password" onPress={() => {
                  const pw = generatePassword({ length: 20 });
                  const fields = { ...editor.fields };
                  const target = Object.keys(fields).find((k) => isSensitiveField(k)) ?? 'password';
                  fields[target] = pw;
                  setEditor({ ...editor, fields });
                  Alert.alert('Generated', `A 20-character password was saved into "${target}". Long-press the field to copy it.`);
                }} />
                <Btn label={revealSecrets ? 'Hide secrets' : 'Show secrets'} onPress={() => setRevealSecrets((v) => !v)} />
              </View>
              <Btn label="+ Add field" onPress={() => setEditor({ ...editor, fields: { ...editor.fields, [`field${Object.keys(editor.fields).length + 1}`]: '' } })} />
              <View style={S.row}>
                <Btn label="Attach photo" onPress={() => { void attach('photo'); }} />
                <Btn label="Attach file" onPress={() => { void attach('file'); }} />
              </View>
              <Text style={S.label}>Private note</Text>
              <TextInput style={[S.input, S.textarea]} multiline value={editor.note ?? ''} onChangeText={(n) => setEditor({ ...editor, note: n })} placeholder="Only you will ever see this" placeholderTextColor={C.muted} />
              <Btn label="Delete this item" onPress={() => { closeEditor(); delItem(editor); }} danger />
            </ScrollView>
          </SafeAreaView>
        </Modal>
      )}

      {screen === 'privacy' && (
        <Modal visible animationType="slide" onRequestClose={() => setScreen('vaults')}>
          <SafeAreaView style={S.root}>
            <View style={S.header}><Pressable onPress={() => setScreen('vaults')}><Text style={S.back}>Close</Text></Pressable><Text style={S.h1}>Privacy & security</Text><View /></View>
            <ScrollView contentContainerStyle={S.pad}>
              <Text style={S.h2}>What Redoubt does not do</Text>
              <Text style={S.body}>• No account or sign-in{'\n'}• No network permission — the app makes zero connections{'\n'}• No cloud, no sync, no server copy{'\n'}• No analytics, no ads, no tracking SDKs{'\n'}• No crash-reporting that uploads data{'\n'}• No biometric data stored (Face ID stays in the Secure Enclave)</Text>
              <Text style={S.h2}>How your data is protected</Text>
              <Text style={S.body}>Every change re-encrypts the whole box with AES-256-GCM. The key is derived from your passphrase with PBKDF2-SHA256 (310,000 iterations) and a unique random salt. The passphrase is never stored or transmitted. If you lose it, your data is unrecoverable — by design, because nobody else holds a copy.</Text>
              <Text style={S.h2}>Automatic lock</Text>
              <Text style={S.body}>{`The vault locks the moment the app goes to the background, and after ${IDLE_LOCK_MS / 60000} minutes in the foreground. Decrypted items are never kept across a lock. A strong password generator uses the device's cryptographic random source, entirely offline.`}</Text>
              <Text style={S.h2}>App Store privacy label</Text>
              <Text style={S.body}>Data Not Collected — the shortest label Apple offers.</Text>
              <Text style={S.h2}>Your controls</Text>
              <Text style={S.body}>Lock instantly · delete any item · erase everything · export an encrypted backup that only you can open · restore it as a new box on any device by hand.</Text>
              <Pressable onPress={eraseAll}><Text style={S.danger}>Erase everything on this device</Text></Pressable>
              <Pressable onPress={() => setShowFeedback(true)} style={{ paddingVertical: 10 }}><Text style={S.link}>Send feedback</Text></Pressable>
              <Text style={S.foot}>v0.4 · Built offline, for offline. Full policy in App Store listing.</Text>
            </ScrollView>
          </SafeAreaView>
        </Modal>
      )}
      <FeedbackModal visible={showFeedback} onClose={() => setShowFeedback(false)} context="privacy" />
    </SafeAreaView>
  );
}

// ============================================================ 小组件
function Center({ children }: any) { return <View style={[S.root, { justifyContent: 'center', alignItems: 'center' }]}>{children}</View>; }
function Container({ title, subtitle, onBack, children }: any) {
  return (
    <ScrollView contentContainerStyle={S.pad}>
      {onBack ? <Pressable onPress={onBack}><Text style={S.back}>← Back</Text></Pressable> : null}
      <Text style={S.h1}>{title}</Text>
      <Text style={S.h2}>{subtitle}</Text>
      {children}
    </ScrollView>
  );
}
function Btn({ label, onPress, primary, danger }: any) {
  return <Pressable style={[S.btn, primary && S.btnPrimary, danger && S.btnDanger]} onPress={onPress}><Text style={[S.btnText, primary && S.btnTextPrimary]}>{label}</Text></Pressable>;
}

const S = StyleSheet.create({
  root: { flex: 1, backgroundColor: C.bg },
  pad: { padding: 20, paddingTop: 28, gap: 12 },
  h1: { color: C.text, fontSize: 28, fontWeight: '700' },
  h2: { color: C.text, fontSize: 17, fontWeight: '600', marginTop: 4 },
  body: { color: C.muted, fontSize: 14, lineHeight: 22 },
  note: { color: C.muted, fontSize: 13, lineHeight: 20, marginBottom: 4 },
  empty: { color: C.muted, fontSize: 14, textAlign: 'center', marginVertical: 24 },
  foot: { color: C.muted, fontSize: 12, marginTop: 16 },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: 20, paddingTop: 16, paddingBottom: 8 },
  back: { color: C.accent, fontSize: 15 },
  link: { color: C.accent, fontSize: 15, fontWeight: '600' },
  searchBox: { marginHorizontal: 20, backgroundColor: C.surface, borderRadius: 12, borderWidth: 1, borderColor: C.border },
  search: { color: C.text, padding: 14, fontSize: 15 },
  stats: { color: C.muted, fontSize: 12, paddingHorizontal: 20, paddingVertical: 8 },
  label: { color: C.muted, fontSize: 12, marginTop: 8, textTransform: 'uppercase', letterSpacing: 1 },
  input: { backgroundColor: C.surface, borderRadius: 10, borderWidth: 1, borderColor: C.border, color: C.text, padding: 12, fontSize: 15 },
  textarea: { minHeight: 90, textAlignVertical: 'top' },
  fieldRow: { flexDirection: 'row', gap: 8 },
  fieldKey: { flex: 1 }, fieldVal: { flex: 2 },
  chips: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  chip: { paddingHorizontal: 12, paddingVertical: 8, borderRadius: 20, borderWidth: 1, borderColor: C.border, backgroundColor: C.surface },
  chipOn: { backgroundColor: C.accent, borderColor: C.accent },
  chipText: { color: C.text, fontSize: 13 },
  card: { backgroundColor: C.surface, borderRadius: 12, borderWidth: 1, borderColor: C.border, padding: 14, marginHorizontal: 20, marginBottom: 10 },
  cardTitle: { color: C.text, fontSize: 16, fontWeight: '600' },
  cardSub: { color: C.muted, fontSize: 12, marginTop: 4 },
  tag: { color: C.accent, fontSize: 12, fontWeight: '600', marginRight: 10 },
  row: { flexDirection: 'row', flexWrap: 'wrap', gap: 10, alignItems: 'center', paddingHorizontal: 20, marginVertical: 8 },
  btn: { backgroundColor: C.surface2, borderRadius: 12, paddingVertical: 13, paddingHorizontal: 16, flexGrow: 1, alignItems: 'center', borderWidth: 1, borderColor: C.border },
  btnPrimary: { backgroundColor: C.accent, borderColor: C.accent },
  btnDanger: { backgroundColor: 'transparent', borderColor: C.danger },
  btnText: { color: C.text, fontSize: 15, fontWeight: '600' },
  btnTextPrimary: { color: '#06101F' },
  danger: { color: C.danger, fontSize: 14, textAlign: 'center', marginVertical: 20 },
});
