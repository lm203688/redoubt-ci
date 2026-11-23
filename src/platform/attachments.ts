/**
 * 文件附件选取（照片/文件进保险箱）。
 * 说明：把选中的文件读成 base64，作为字段值交给 domain 层加密；原文不出设备。
 *
 * v0.4 修复（本轮审计后）：
 *  - 读文件「之前」先按磁盘字节数判大小。v0.3 直接 readAsStringAsync，用户选中几十 MB
 *    文件时会先把整份内容读进内存才可能报错 → 真机 OOM 崩溃。
 *  - 照片 base64 为空时返回 null；v0.3 会把空字符串当有效附件写入，用户以为存好了。
 *  - 字段名唯一化在 UI 层用 uniqueFieldKey 完成，避免同名附件互相覆盖。
 *
 * 本文件依赖 Expo 原生模块，无法在本机 Node 测试；大小判定与字段名逻辑在 domain.test.ts 覆盖。
 */
import * as ImagePicker from 'expo-image-picker';
import * as DocumentPicker from 'expo-document-picker';
import * as FileSystem from 'expo-file-system/legacy';
import {
  MAX_ATTACHMENT_BYTES, assertAttachmentSize, assertFileSizeWithinLimit,
} from '../domain';

export interface Attachment { name: string; mime: string; base64: string; size: number }

export async function pickPhoto(): Promise<Attachment | null> {
  const perm = await ImagePicker.requestMediaLibraryPermissionsAsync();
  if (!perm.granted) return null;
  const r = await ImagePicker.launchImageLibraryAsync({ mediaTypes: ['images'], base64: true, quality: 0.8 });
  if (r.canceled || !r.assets?.[0]) return null;
  const a = r.assets[0];
  if (!a.base64) return null; // 选图成功但没有 base64：明确失败，不写入空附件
  // 由 base64 长度反推压缩后图片的原始字节数，防止超大图进入内存后再失败
  assertAttachmentSize(Math.ceil((a.base64.length * 3) / 4), '照片');
  return {
    name: a.fileName ?? 'photo.jpg',
    mime: a.mimeType ?? 'image/jpeg',
    base64: a.base64,
    size: a.base64.length,
  };
}

export async function pickFile(): Promise<Attachment | null> {
  const r = await DocumentPicker.getDocumentAsync({ type: '*/*', copyToCacheDirectory: true });
  if (r.canceled || !r.assets?.[0]) return null;
  const a = r.assets[0];
  assertAttachmentSize(a.size ?? 0, '附件');
  // DocumentPicker 在部分系统/来源下不返回 size，再用文件系统实际大小复核一次
  const info = await FileSystem.getInfoAsync(a.uri);
  if (info.exists) assertFileSizeWithinLimit(info.size ?? 0, '附件', MAX_ATTACHMENT_BYTES);
  const base64 = await FileSystem.readAsStringAsync(a.uri, { encoding: FileSystem.EncodingType.Base64 });
  if (!base64) return null;
  return {
    name: a.name,
    mime: a.mimeType ?? 'application/octet-stream',
    base64,
    size: base64.length,
  };
}
