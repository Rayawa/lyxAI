# lyxAI

English | [简体中文](README_zh.md)

A Python utility and format notes for inspecting and decrypting RMFH-format backup files.

## Overview

The script parses RMFH headers and processes backup files using a supplied key, with options for a single input or a directory workflow. The repository contains code and format-analysis notes; backup data and usable keys must be supplied separately.

## Technology and Dependencies

Python 3.10+ and PyCryptodome (`Crypto.Cipher.AES`). The script also uses Python standard-library filesystem and binary-structure modules.

## Repository Structure

- `decrypt_backup.py` — parser and command-line utility
- `analysis_report.md` — format-analysis notes

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome
python decrypt_backup.py --help
```

Use the help output to select an input file/directory, inspect its metadata with `--info`, and specify an output directory. Decryption requires the matching key through `--key`; keep keys and backup contents local.
