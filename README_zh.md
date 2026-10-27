# lyxAI

[English](README.md) | 简体中文

用于检查和解密 RMFH 格式备份文件的 Python 工具与格式笔记。

## 项目概述

脚本解析 RMFH 头部，使用外部提供的密钥处理备份文件，支持单文件及目录流程。仓库包含代码与格式分析笔记，备份数据和可用密钥需另行准备。

## 技术栈与依赖

Python 3.10 及以上、PyCryptodome（`Crypto.Cipher.AES`），并使用 Python 标准库的文件与二进制结构处理模块。

## 文件结构

- `decrypt_backup.py` — 解析器与命令行工具
- `analysis_report.md` — 格式分析笔记

## 快速上手

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome
python decrypt_backup.py --help
```

按帮助选择输入文件或目录，通过 `--info` 查看元数据并指定输出目录。解密需通过 `--key` 提供匹配密钥，密钥与备份内容保留在本地。
