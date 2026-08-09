#!/usr/bin/env python3
"""
微信备份文件解密工具 (WeChat Backup RMFH Decryptor)

支持解密 WeChat 备份导出的 RMFH 格式文件，包括：
- ChatPackage: 聊天记录数据库 (protobuf 格式)
- Index: 索引文件
- Media: 媒体文件 (图片、语音等)
- Media/*.tar.enc: 加密的 tar 归档文件

用法:
    python3 decrypt_backup.py --key <hex_key> [--input <file>] [--output <dir>]
    python3 decrypt_backup.py --key <hex_key> --all [--output <dir>]
"""

import argparse
import os
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES


# RMFH 文件格式常量
RMFH_MAGIC = b'RMFH'
RMFT_MAGIC = b'RMFT'
HEADER_SIZE = 128   # RMFH header 大小
FOOTER_SIZE = 128   # RMFT footer 大小
IV_OFFSET = 19      # IV 在 header 中的偏移
IV_LENGTH = 12       # AES-GCM IV 长度 (96-bit)
TAG_OFFSET = 10     # TAG 在 footer 中的偏移
TAG_LENGTH = 16      # AES-GCM Auth Tag 长度


class RMFHFile:
    """表示一个 RMFH 加密文件"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.size = os.path.getsize(filepath)

        with open(filepath, 'rb') as f:
            self._raw = f.read()

        if len(self._raw) < HEADER_SIZE + FOOTER_SIZE:
            raise ValueError(f"文件太小: {self.size} bytes")

        self.header = self._raw[:HEADER_SIZE]
        self.footer = self._raw[-FOOTER_SIZE:]
        self.ciphertext = self._raw[HEADER_SIZE:-FOOTER_SIZE]

        # 验证 RMFH/RMFT 魔数
        if self.header[:4] != RMFH_MAGIC:
            raise ValueError(f"不是有效的 RMFH 文件 (header magic: {self.header[:4]})")
        if self.footer[:4] != RMFT_MAGIC:
            raise ValueError(f"不是有效的 RMFH 文件 (footer magic: {self.footer[:4]})")

        # 解析 header
        self.version = struct.unpack('<I', self.header[4:8])[0]
        self.flags = struct.unpack('<H', self.header[8:10])[0]
        self.enc_type = struct.unpack('<H', self.header[10:12])[0]

        # 提取 IV 和 TAG
        self.iv = self.header[IV_OFFSET:IV_OFFSET + IV_LENGTH]
        self.tag = self.footer[TAG_OFFSET:TAG_OFFSET + TAG_LENGTH]

    def decrypt(self, key: bytes) -> bytes:
        """
        使用 AES-256-GCM 解密文件内容

        Args:
            key: 16 字节的 AES 密钥

        Returns:
            解密后的明文数据
        """
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES key 长度必须为 16/24/32 字节, 当前为 {len(key)}")

        cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv)
        try:
            plaintext = cipher.decrypt_and_verify(self.ciphertext, self.tag)
            return plaintext
        except ValueError as e:
            # MAC 校验失败 - 密钥错误
            raise ValueError(f"解密失败 (MAC 校验不通过): 密钥可能不正确") from e

    def decrypt_without_verify(self, key: bytes) -> bytes:
        """解密但跳过 MAC 验证 (用于测试密钥)"""
        cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv)
        return cipher.decrypt(self.ciphertext)

    def __repr__(self):
        return (f"RMFHFile({self.filename!r}, version=0x{self.version:08x}, "
                f"enc_type=0x{self.enc_type:04x}, size={self.size})")


def find_backup_dir(base_dir: str) -> dict:
    """扫描备份目录结构"""
    result = {
        'metadata_files': [],
        'chat_packages': [],
        'index_files': [],
        'media_files': [],
        'tar_enc_files': [],
        'other_files': [],
    }

    base = Path(base_dir)

    # 顶层 metadata 文件
    for f in sorted(base.glob('*.dat')):
        result['metadata_files'].append(str(f))
    for f in sorted(base.glob('pkg.*')):
        result['metadata_files'].append(str(f))

    # 查找 hash 目录
    for d in base.iterdir():
        if not d.is_dir() or d.name.startswith('.'):
            continue

        # ChatPackage
        cp_dir = d / 'ChatPackage'
        if cp_dir.exists():
            for f in sorted(cp_dir.iterdir()):
                result['chat_packages'].append(str(f))

        # Index
        idx_dir = d / 'Index'
        if idx_dir.exists():
            for f in sorted(idx_dir.iterdir()):
                result['index_files'].append(str(f))

        # Media
        media_dir = d / 'Media'
        if media_dir.exists():
            for f in sorted(media_dir.iterdir()):
                if f.suffix == '.enc':
                    result['tar_enc_files'].append(str(f))
                else:
                    result['media_files'].append(str(f))

    return result


def decrypt_file(filepath: str, key: bytes, output_dir: str | None = None) -> bytes:
    """解密单个文件"""
    rmfh = RMFHFile(filepath)
    plaintext = rmfh.decrypt(key)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        # 保持相对路径结构
        relpath = os.path.basename(filepath)
        outpath = os.path.join(output_dir, relpath + '.dec')
        with open(outpath, 'wb') as f:
            f.write(plaintext)
        print(f"  ✓ 解密成功 → {outpath} ({len(plaintext)} bytes)")

    return plaintext


def main():
    parser = argparse.ArgumentParser(
        description='微信备份文件解密工具 (WeChat Backup RMFH Decryptor)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 解密单个文件
  python3 decrypt_backup.py --key 59d88d4d815b97cf07449faadd5aa179 --input ChatPackage/xxx

  # 解密所有文件
  python3 decrypt_backup.py --key 59d88d4d815b97cf07449faadd5aa179 --all --output decrypted/

  # 预览备份结构
  python3 decrypt_backup.py --info
        """
    )

    parser.add_argument('--key', '-k', type=str,
                        help='AES 解密密钥 (hex 格式, 16/24/32 字节)')
    parser.add_argument('--input', '-i', type=str,
                        help='单个待解密文件路径')
    parser.add_argument('--all', '-a', action='store_true',
                        help='解密所有找到的文件')
    parser.add_argument('--output', '-o', type=str, default='decrypted',
                        help='输出目录 (默认: decrypted/)')
    parser.add_argument('--info', action='store_true',
                        help='显示备份结构信息')
    parser.add_argument('--base-dir', '-b', type=str, default='raw',
                        help='备份根目录 (默认: raw/)')
    parser.add_argument('--skip-media', action='store_true',
                        help='跳过媒体文件解密')
    parser.add_argument('--skip-tar', action='store_true',
                        help='跳过 tar.enc 文件解密')

    args = parser.parse_args()

    # 显示信息模式
    if args.info:
        print("=" * 60)
        print("微信备份结构分析")
        print("=" * 60)
        structure = find_backup_dir(args.base_dir)

        print(f"\n📋 元数据文件 ({len(structure['metadata_files'])}):")
        for f in structure['metadata_files']:
            print(f"    {f}")

        print(f"\n💬 聊天记录 (ChatPackage) ({len(structure['chat_packages'])}):")
        for f in structure['chat_packages']:
            size = os.path.getsize(f)
            print(f"    {os.path.basename(f)} ({size:,} bytes)")

        print(f"\n📑 索引文件 (Index) ({len(structure['index_files'])}):")
        for f in structure['index_files']:
            size = os.path.getsize(f)
            print(f"    {os.path.basename(f)} ({size:,} bytes)")

        print(f"\n🖼️ 媒体文件 ({len(structure['media_files'])}):")
        for f in structure['media_files'][:10]:
            size = os.path.getsize(f)
            print(f"    {os.path.basename(f)} ({size:,} bytes)")
        if len(structure['media_files']) > 10:
            print(f"    ... 还有 {len(structure['media_files']) - 10} 个文件")

        print(f"\n📦 加密 Tar 归档 ({len(structure['tar_enc_files'])}):")
        for f in structure['tar_enc_files']:
            size = os.path.getsize(f)
            print(f"    {os.path.basename(f)} ({size:,} bytes)")

        total_size = sum(
            os.path.getsize(f)
            for files in structure.values()
            for f in files
        )
        print(f"\n📊 总文件数: {sum(len(v) for v in structure.values())}")
        print(f"📊 总大小: {total_size:,} bytes ({total_size/1024/1024:.1f} MB)")
        return

    # 解密模式
    if not args.key:
        parser.error("请提供 --key 参数 (hex 格式的 AES 密钥)")

    try:
        key = bytes.fromhex(args.key)
    except ValueError:
        parser.error("密钥格式错误: 需要 hex 字符串 (例如: 59d88d4d815b97cf07449faadd5aa179)")

    if len(key) not in (16, 24, 32):
        parser.error(f"密钥长度错误: {len(key)} bytes, 需要 16/24/32 bytes")

    print(f"🔑 密钥: {key.hex()} ({len(key)*8}-bit)")

    if args.input:
        # 解密单个文件
        print(f"\n🔓 解密: {args.input}")
        try:
            decrypt_file(args.input, key, args.output)
        except Exception as e:
            print(f"  ✗ 错误: {e}")
            sys.exit(1)

    elif args.all:
        # 解密所有文件
        structure = find_backup_dir(args.base_dir)
        output = args.output

        success = 0
        failed = 0
        skipped = 0

        # 解密 metadata
        print(f"\n📋 解密元数据文件...")
        for f in structure['metadata_files']:
            if not open(f, 'rb').read(4) == RMFH_MAGIC:
                # 未加密的文件直接复制
                print(f"  → 复制 (未加密): {f}")
                os.makedirs(output, exist_ok=True)
                with open(f, 'rb') as src, open(os.path.join(output, os.path.basename(f)), 'wb') as dst:
                    dst.write(src.read())
                skipped += 1
                continue
            try:
                decrypt_file(f, key, output)
                success += 1
            except Exception as e:
                print(f"  ✗ {f}: {e}")
                failed += 1

        # 解密 ChatPackage
        print(f"\n💬 解密聊天记录 ({len(structure['chat_packages'])} 个文件)...")
        for f in structure['chat_packages']:
            try:
                out_subdir = os.path.join(output, 'ChatPackage')
                decrypt_file(f, key, out_subdir)
                success += 1
            except Exception as e:
                print(f"  ✗ {os.path.basename(f)}: {e}")
                failed += 1

        # 解密 Index
        print(f"\n📑 解密索引文件 ({len(structure['index_files'])} 个文件)...")
        for f in structure['index_files']:
            try:
                out_subdir = os.path.join(output, 'Index')
                decrypt_file(f, key, out_subdir)
                success += 1
            except Exception as e:
                print(f"  ✗ {os.path.basename(f)}: {e}")
                failed += 1

        # 解密 Media
        if not args.skip_media:
            print(f"\n🖼️ 解密媒体文件 ({len(structure['media_files'])} 个文件)...")
            for f in structure['media_files']:
                try:
                    out_subdir = os.path.join(output, 'Media')
                    decrypt_file(f, key, out_subdir)
                    success += 1
                except Exception as e:
                    print(f"  ✗ {os.path.basename(f)}: {e}")
                    failed += 1

        # 解密 Tar.enc
        if not args.skip_tar:
            print(f"\n📦 解密 Tar 归档 ({len(structure['tar_enc_files'])} 个文件)...")
            for f in structure['tar_enc_files']:
                try:
                    out_subdir = os.path.join(output, 'Media')
                    decrypt_file(f, key, out_subdir)
                    success += 1
                except Exception as e:
                    print(f"  ✗ {os.path.basename(f)}: {e}")
                    failed += 1

        print(f"\n{'='*60}")
        print(f"解密完成: {success} 成功, {failed} 失败, {skipped} 跳过")
        print(f"输出目录: {output}/")

    else:
        parser.error("请指定 --input <file> 或 --all")


if __name__ == '__main__':
    main()
