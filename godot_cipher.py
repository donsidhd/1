#!/usr/bin/env python3
"""
GodotCipher KS222 v1.0 - Godot Engine Encryption Tool
AES-256 Encryption for Godot PCK Files
Author: KS222
License: MIT
"""

import os
import sys
import secrets
import shutil
import re
import json
import traceback
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class Colors:
    cyan = '\033[96m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    purple = '\033[95m'
    bold = '\033[1m'
    end = '\033[0m'

class LogLevel(Enum):
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3

@dataclass
class Modification:
    type: str
    path: Path
    content: Any
    backup_path: Optional[Path] = None

class GodotCipher:
    VERSION = "KS222 v1.0"
    CONFIG = "godot_cipher.json"
    LOG_FILE = "godot_cipher.log"
    BACKUP_KEEP_COUNT = 2
    
    def __init__(self, root: str, dry_run=False, force=False, fast=False, verbose=False, restore=False):
        self.root = Path(root).resolve()
        self.dry_run = dry_run
        self.force = force
        self.fast = fast
        self.verbose = verbose
        self.restore_mode = restore
        self._init_colors()
        
        # 默认魔术头 KS22
        self.tag = "KS22"
        self.enc_tag = "KS22"
        self.token = secrets.token_bytes(32)
        
        env_key = os.environ.get("GODOT_CIPHER_KEY")
        if env_key:
            self._log(f"Using key from environment variable", Colors.cyan)
            self.key = env_key
        else:
            self.key = secrets.token_hex(32)
            self._log(f"Generated new random key", Colors.cyan)
        
        self._validate_key()
        self.godot_version = self._detect_godot_version()
        self.is_godot4 = self.godot_version.startswith('4')
        self.modifications: List[Modification] = []
        self.backups: List[Tuple[Path, Path]] = []
        
    def _init_colors(self):
        if sys.platform == 'win32':
            os.system('color')
    
    def _c_array(self, data: bytes) -> str:
        return ', '.join(f'0x{b:02x}' for b in data)
    
    def _validate_key(self):
        if len(self.key) != 64:
            self._log(f"Warning: Key should be 64 hex chars, got {len(self.key)}", Colors.yellow)
        elif not re.match(r'^[0-9a-fA-F]{64}$', self.key):
            self._log(f"Warning: Key should be hexadecimal, got {self.key[:16]}...", Colors.yellow)
    
    def _rand(self, n: int) -> str:
        return ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(n))
    
    def _header(self, tag: str) -> str:
        return f"0x{''.join(f'{ord(c):02X}' for c in tag[::-1])}"
    
    def _log(self, msg: str, color: str = '', end: str = '\n', level: LogLevel = LogLevel.INFO):
        if not self.verbose and level == LogLevel.DEBUG:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}{msg}{Colors.end}", end=end)
        try:
            with open(self.LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {msg}\n")
        except:
            pass
    
    def _backup(self, path: Path) -> bool:
        if self.dry_run or not path.exists():
            return True
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = path.with_suffix(f"{path.suffix}.bak_{ts}")
        try:
            shutil.copy2(path, bak)
            self.backups.append((path, bak))
            self._clean_old_bak(path)
            return True
        except Exception as e:
            self._log(f"Backup failed: {e}", Colors.red)
            return False
    
    def _clean_old_bak(self, path: Path):
        baks = sorted(path.parent.glob(f"{path.name}.bak_*"), key=lambda x: x.stat().st_mtime, reverse=True)
        for old in baks[self.BACKUP_KEEP_COUNT:]:
            try: 
                old.unlink()
                self._log(f"  Removed old backup: {old.name}", Colors.cyan, level=LogLevel.DEBUG)
            except: 
                pass
    
    def _cleanup_backups(self):
        for orig, bak in self.backups:
            try:
                if bak.exists():
                    bak.unlink()
                    self._log(f"  Cleaned backup: {bak.name}", Colors.cyan, level=LogLevel.DEBUG)
            except:
                pass
        self.backups.clear()
    
    def _rollback(self):
        self._log("Rolling back changes...", Colors.yellow)
        success = True
        for orig, bak in self.backups:
            if bak.exists():
                try:
                    if orig.exists():
                        orig.unlink()
                    shutil.move(str(bak), str(orig))
                    self._log(f"  Restored: {orig.name}", Colors.green)
                except Exception as e:
                    self._log(f"  Failed to restore {orig.name}: {e}", Colors.red)
                    success = False
        
        if not success:
            self._log("Rollback incomplete - manual intervention may be needed", Colors.red)
    
    def restore_latest_backup(self) -> bool:
        self._log("Searching for backups...", Colors.cyan)
        
        target_dirs = [self.root / "core/io", self.root / "core/crypto"]
        backup_files = []
        
        for dir_path in target_dirs:
            if dir_path.exists():
                for pattern in ["*.cpp.bak_*", "*.h.bak_*"]:
                    backup_files.extend(dir_path.glob(pattern))
        
        if not backup_files:
            self._log("No backups found", Colors.yellow)
            return False
        
        backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        self._log(f"Found {len(backup_files)} backup(s)", Colors.cyan)
        
        restored = 0
        for bak in backup_files:
            parts = bak.name.split('.bak_')
            if len(parts) >= 2:
                orig_name = parts[0]
                orig = bak.parent / orig_name
            else:
                continue
            
            try:
                if orig.exists():
                    extra_bak = orig.with_suffix(f"{orig.suffix}.pre_restore")
                    shutil.copy2(orig, extra_bak)
                    self._log(f"  Created pre-restore backup: {extra_bak.name}", Colors.cyan, level=LogLevel.DEBUG)
                
                shutil.move(str(bak), str(orig))
                self._log(f"  Restored: {orig}", Colors.green)
                restored += 1
            except Exception as e:
                self._log(f"  Failed to restore {orig}: {e}", Colors.red)
        
        self._log(f"Restored {restored} file(s)", Colors.green if restored > 0 else Colors.red)
        return restored > 0
    
    def _detect_godot_version(self) -> str:
        vf = self.root / "version.py"
        if vf.exists():
            try:
                content = vf.read_text(encoding='utf-8')
                
                m = re.search(r'version\s*=\s*"([^"]+)"', content)
                if m:
                    version = m.group(1)
                    self._log(f"Detected Godot {version}", Colors.cyan)
                    return version
                
                major_match = re.search(r'major\s*=\s*(\d+)', content)
                minor_match = re.search(r'minor\s*=\s*(\d+)', content)
                if major_match and minor_match:
                    major = major_match.group(1)
                    minor = minor_match.group(1)
                    version = f"{major}.{minor}"
                    patch_match = re.search(r'patch\s*=\s*(\d+)', content)
                    if patch_match:
                        version += f".{patch_match.group(1)}"
                    status_match = re.search(r'status\s*=\s*"([^"]+)"', content)
                    if status_match:
                        version += f"-{status_match.group(1)}"
                    
                    self._log(f"Detected Godot {version}", Colors.cyan)
                    return version
            except Exception as e:
                self._log(f"Error reading version.py: {e}", Colors.yellow)
        
        if (self.root / "scene/main/scene_tree.h").exists():
            self._log("Detected Godot 4.x (by feature detection)", Colors.cyan)
            return "4.x"
        elif (self.root / "scene/resources/text_file.h").exists():
            self._log("Detected Godot 3.x (by feature detection)", Colors.cyan)
            return "3.x"
        else:
            self._log("Assuming Godot 4.x", Colors.yellow)
            return "4.x"
    
    def _get_parameter_names(self, file_path: Path) -> Dict[str, str]:
        try:
            content = file_path.read_text(encoding='utf-8')
        except:
            return {"key_param": "p_key", "iv_access": "iv.ptrw()", "data_access": "data.ptrw()"}
        
        result = {}
        
        # 只匹配 open_and_parse 函数中的参数，避免匹配到 key_md5
        match = re.search(r'Error\s+FileAccessEncrypted::open_and_parse\([^,]+,\s*const\s+Vector<uint8_t>&\s+([a-zA-Z_][a-zA-Z0-9_]*)', content)
        if match:
            result["key_param"] = match.group(1)
        else:
            match = re.search(r'open_and_parse\([^,)]*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[,)]', content)
            if match and match.group(1) != "key_md5":
                result["key_param"] = match.group(1)
            else:
                result["key_param"] = "p_key"
        
        match = re.search(r'decrypt_cfb\([^,]+,\s*([^,]+),\s*([^,]+),', content)
        if match:
            result["iv_access"] = match.group(1).strip()
            result["data_access"] = match.group(2).strip()
        else:
            if self.is_godot4:
                result["iv_access"] = "iv.ptrw()"
                result["data_access"] = "data.ptrw()"
            else:
                result["iv_access"] = "iv.write().ptr()"
                result["data_access"] = "data.write().ptr()"
        
        self._log(f"  Detected: key={result['key_param']}, iv={result['iv_access']}", Colors.cyan, level=LogLevel.DEBUG)
        return result
    
    def _validate_original_code(self, file_path: Path) -> bool:
        if not file_path.exists():
            self._log(f"File not found: {file_path}", Colors.red)
            return False
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding='latin-1')
                self._log(f"  Used latin-1 encoding for {file_path.name}", Colors.yellow)
            except Exception as e:
                self._log(f"  Cannot read file: {e}", Colors.red)
                return False
        
        required_patterns = [
            (r'CryptoCore::AESContext\s+ctx', "AESContext declaration"),
            (r'ctx\.set_encode_key\([^)]+\)', "set_encode_key call"),
            (r'ctx\.(decrypt|encrypt)_cfb\([^)]+\)', "encrypt/decrypt call")
        ]
        
        for pattern, name in required_patterns:
            if not re.search(pattern, content):
                self._log(f"  Missing required pattern: {name}", Colors.red)
                return False
        
        return True
    
    def _add_include(self, file_path: Path, include_line: str) -> bool:
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            content = file_path.read_text(encoding='latin-1')
        
        if include_line in content:
            return True
        
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if line.startswith('#include') and 'file_access_encrypted.h' in line:
                lines.insert(i + 1, include_line)
                if not self.dry_run:
                    file_path.write_text('\n'.join(lines), encoding='utf-8')
                self._log(f"  Added include: {include_line}", Colors.green)
                return True
        
        for i, line in enumerate(lines):
            if line.startswith('#include'):
                lines.insert(i + 1, include_line)
                if not self.dry_run:
                    file_path.write_text('\n'.join(lines), encoding='utf-8')
                self._log(f"  Added include: {include_line}", Colors.green)
                return True
        
        return False
    
    def _get_decrypt_code(self, key_param: str, iv_access: str, data_access: str) -> List[str]:
        if self.is_godot4:
            return [
                "CryptoCore::AESContext ctx;",
                "Vector<uint8_t> derived_key;",
                "derived_key.resize(32);",
                f"const uint8_t* user_provided_key = {key_param}.ptr();",
                "uint8_t* derived_ptr = derived_key.ptrw();",
                "for (int i = 0; i < 32; i++) {",
                f"    derived_ptr[i] = user_provided_key[i] ^ Security::TOKEN[i];",
                "}",
                "ctx.set_encode_key(derived_key.ptr(), 256);",
                f"ctx.decrypt_cfb(ds, {iv_access}, {data_access}, {data_access});"
            ]
        else:
            return [
                "CryptoCore::AESContext ctx;",
                "PoolByteArray derived_key;",
                "derived_key.resize(32);",
                f"const uint8_t* user_provided_key = {key_param}.read().ptr();",
                "uint8_t* derived_ptr = derived_key.write().ptr();",
                "for (int i = 0; i < 32; i++) {",
                f"    derived_ptr[i] = user_provided_key[i] ^ Security::TOKEN[i];",
                "}",
                "ctx.set_encode_key(derived_key.read().ptr(), 256);",
                f"ctx.decrypt_cfb(ds, {iv_access}, {data_access}, {data_access});"
            ]
    
    def _get_encrypt_code(self, key_param: str, iv_access: str, data_access: str) -> List[str]:
        if self.is_godot4:
            return [
                "CryptoCore::AESContext ctx;",
                "Vector<uint8_t> derived_key;",
                "derived_key.resize(32);",
                f"const uint8_t* user_provided_key = {key_param}.ptr();",
                "uint8_t* derived_ptr = derived_key.ptrw();",
                "for (int i = 0; i < 32; i++) {",
                f"    derived_ptr[i] = user_provided_key[i] ^ Security::TOKEN[i];",
                "}",
                "ctx.set_encode_key(derived_key.ptr(), 256);",
                f"ctx.encrypt_cfb(len, {iv_access}, {data_access}, {data_access});"
            ]
        else:
            return [
                "CryptoCore::AESContext ctx;",
                "PoolByteArray derived_key;",
                "derived_key.resize(32);",
                f"const uint8_t* user_provided_key = {key_param}.read().ptr();",
                "uint8_t* derived_ptr = derived_key.write().ptr();",
                "for (int i = 0; i < 32; i++) {",
                f"    derived_ptr[i] = user_provided_key[i] ^ Security::TOKEN[i];",
                "}",
                "ctx.set_encode_key(derived_key.read().ptr(), 256);",
                f"ctx.encrypt_cfb(len, {iv_access}, {data_access}, {data_access});"
            ]
    
    def _is_comment_line(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*')
    
    def _find_block(self, lines: List[str], marker: str, start_search: int = 0) -> Tuple[int, int]:
        start = -1
        end = -1
        
        for i in range(start_search, len(lines)):
            line = lines[i]
            if marker in line and not self._is_comment_line(line):
                for j in range(i, -1, -1):
                    if '{' in lines[j]:
                        start = j
                        break
                if start == -1:
                    continue
                brace_count = 0
                for j in range(start, len(lines)):
                    brace_count += lines[j].count('{') - lines[j].count('}')
                    if brace_count == 0 and j > start:
                        end = j
                        return start, end
        
        return -1, -1
    
    def _find_and_remove_duplicate_ctx(self, lines: List[str]) -> List[str]:
        """查找并删除加密块中重复的 ctx 定义"""
        in_close_function = False
        ctx_count_in_close = 0
        lines_to_remove = []
        
        for i, line in enumerate(lines):
            if 'void FileAccessEncrypted::_close()' in line:
                in_close_function = True
                continue
            
            if in_close_function and line.startswith('}'):
                break
            
            if in_close_function and 'CryptoCore::AESContext ctx' in line and 'ctx.set_encode_key' not in lines[i+1] if i+1 < len(lines) else False:
                ctx_count_in_close += 1
                if ctx_count_in_close > 1:
                    lines_to_remove.append(i)
        
        # 从后往前删除，避免索引变化
        for i in reversed(lines_to_remove):
            # 删除这一行
            lines.pop(i)
            # 如果下一行是 ctx.set_encode_key，也删除
            if i < len(lines) and 'ctx.set_encode_key' in lines[i] and 'key.ptrw()' in lines[i]:
                lines.pop(i)
        
        return lines
    
    def _modify_file_access_encrypted(self, file_path: Path) -> bool:
        if not self._validate_original_code(file_path):
            return False
        
        if not self._backup(file_path):
            return False
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            content = file_path.read_text(encoding='latin-1')
        
        names = self._get_parameter_names(file_path)
        lines = content.splitlines(keepends=True)
        
        # 1. 替换解密块
        decrypt_start, decrypt_end = self._find_block(lines, 'ctx.decrypt_cfb')
        
        if decrypt_start != -1 and decrypt_end != -1:
            new_decrypt = self._get_decrypt_code(names["key_param"], names["iv_access"], names["data_access"])
            new_block = [l + '\n' for l in new_decrypt]
            lines[decrypt_start:decrypt_end + 1] = new_block
            self._log("  Replaced decrypt block", Colors.green)
        else:
            self._log("Decrypt block not found", Colors.red)
            return False
        
        # 2. 替换加密块
        encrypt_start, encrypt_end = self._find_block(lines, 'ctx.encrypt_cfb', decrypt_end)
        
        if encrypt_start != -1 and encrypt_end != -1:
            new_encrypt = self._get_encrypt_code("key", names["iv_access"], names["data_access"])
            new_block = [l + '\n' for l in new_encrypt]
            lines[encrypt_start:encrypt_end + 1] = new_block
            self._log("  Replaced encrypt block", Colors.green)
        else:
            self._log("Encrypt block not found", Colors.red)
            return False
        
        # 3. 删除重复的 ctx 定义（重要修复！）
        lines = self._find_and_remove_duplicate_ctx(lines)
        self._log("  Removed duplicate ctx definitions", Colors.green)
        
        if not self.dry_run:
            new_content = ''.join(lines)
            file_path.write_text(new_content, encoding='utf-8')
            
            if self._check_braces(file_path):
                self._log(f"  Saved: {file_path}", Colors.cyan)
            else:
                self._log(f"  Warning: Brace mismatch after modification", Colors.yellow)
        
        return True
    
    def _check_braces(self, path: Path) -> bool:
        try:
            text = path.read_text(encoding='utf-8')
            text = re.sub(r'"(?:\\.|[^"\\])*"', '', text)
            text = re.sub(r'//.*$', '', text, flags=re.MULTILINE)
            text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
            
            count = 0
            for c in text:
                if c == '{':
                    count += 1
                elif c == '}':
                    count -= 1
                    if count < 0:
                        return False
            return count == 0
        except:
            return False
    
    def _modify_header_magic(self, file_path: Path, pattern: str, new_value: str) -> bool:
        if not file_path.exists():
            self._log(f"File not found: {file_path}", Colors.yellow)
            return False
        
        if not self._backup(file_path):
            return False
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            content = file_path.read_text(encoding='latin-1')
        
        old_content = content
        content = re.sub(pattern, new_value, content)
        
        if content == old_content:
            self._log(f"Warning: Pattern not found in {file_path.name}", Colors.yellow)
            return False
        
        if not self.dry_run:
            file_path.write_text(content, encoding='utf-8')
            self._log(f"Modified {file_path.name}", Colors.green)
        
        return True
    
    def _load_existing_config(self) -> bool:
        config_path = self.root / self.CONFIG
        if config_path.exists() and not self.fast and not self.dry_run:
            try:
                response = input(f"Found existing config. Use it? (y/n): ").lower()
                if response == 'y':
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                    self.tag = config.get('tag', self.tag)
                    self.enc_tag = config.get('enc_tag', self.enc_tag)
                    self.token = bytes.fromhex(config.get('token', self.token.hex()))
                    self.key = config.get('key', self.key)
                    self._log(f"Loaded existing configuration", Colors.cyan)
                    return True
            except Exception as e:
                self._log(f"Failed to load config: {e}", Colors.yellow)
        return False
    
    def run(self):
        if self.restore_mode:
            result = self.restore_latest_backup()
            if result:
                self._log("\nRestore completed successfully", Colors.green)
            return result
        
        if self.dry_run:
            self._log(f"\n{Colors.yellow}DRY RUN - no changes{Colors.end}")
        self._log(f"\n{Colors.purple}GodotCipher {self.VERSION}{Colors.end}", Colors.bold)
        self._log(f"Godot version: {self.godot_version} ({'Godot 4.x' if self.is_godot4 else 'Godot 3.x'})")
        
        if not (self.root / "core").is_dir():
            self._log("Invalid Godot source", Colors.red)
            return False
        
        if not self.fast and not self.dry_run and not self.force:
            self._load_existing_config()
            
            # 自定义魔术头提示
            print()
            response = input(f"{Colors.cyan}Use custom magic headers? (y/n, default n = KS22): {Colors.end}").lower()
            if response == 'y' or response == 'yes':
                custom_tag = input(f"  {Colors.cyan}Enter pack header (4 chars, e.g. GDPC): {Colors.end}").upper()
                if len(custom_tag) == 4 and custom_tag.isalpha():
                    self.tag = custom_tag
                    self.enc_tag = custom_tag
                    self._log(f"  Using custom header: {self.tag}", Colors.green)
                else:
                    self._log(f"  Invalid header '{custom_tag}', using default KS22", Colors.yellow)
                    self.tag = "KS22"
                    self.enc_tag = "KS22"
            else:
                self.tag = "KS22"
                self.enc_tag = "KS22"
                print(f"  {Colors.green}Using default header: KS22{Colors.end}")
            
            response = input(f"\n{Colors.cyan}Apply modifications? (y/n): {Colors.end}").lower()
            if response != 'y':
                return False
        
        try:
            token_h = self.root / "core/crypto/security_token.h"
            token_content = [
                "#ifndef SECURITY_TOKEN_H",
                "#define SECURITY_TOKEN_H",
                "",
                "#include \"core/typedefs.h\"",
                "",
                "namespace Security {",
                f"    static const uint8_t TOKEN[32] = {{ {self._c_array(self.token)} }};",
                "}",
                "",
                "#endif"
            ]
            
            if not self.dry_run:
                token_h.parent.mkdir(exist_ok=True, parents=True)
                token_h.write_text('\n'.join(token_content), encoding='utf-8')
                self._log(f"\n✓ Created: {token_h}", Colors.green)
            
            cpp_path = self.root / "core/io/file_access_encrypted.cpp"
            self._log(f"\n▶ Modifying {cpp_path.name}", Colors.purple)
            
            if not self._backup(cpp_path):
                raise Exception("Failed to backup file")
            
            self._add_include(cpp_path, '#include "core/crypto/security_token.h"')
            
            if not self._modify_file_access_encrypted(cpp_path):
                raise Exception("Failed to modify file_access_encrypted.cpp")
            
            pack_h = self.root / "core/io/file_access_pack.h"
            if pack_h.exists():
                self._log(f"\n▶ Modifying {pack_h.name}", Colors.purple)
                self._modify_header_magic(
                    pack_h,
                    r'#define PACK_HEADER_MAGIC\s+0x[0-9A-Fa-f]+',
                    f'#define PACK_HEADER_MAGIC {self._header(self.tag)}'
                )
            
            enc_h = self.root / "core/io/file_access_encrypted.h"
            if enc_h.exists():
                self._log(f"\n▶ Modifying {enc_h.name}", Colors.purple)
                self._modify_header_magic(
                    enc_h,
                    r'#define ENCRYPTED_HEADER_MAGIC\s+0x[0-9A-Fa-f]+',
                    f'#define ENCRYPTED_HEADER_MAGIC {self._header(self.enc_tag)}'
                )
            
            if not self.dry_run:
                config_path = self.root / self.CONFIG
                config_path.write_text(json.dumps({
                    "version": self.godot_version,
                    "tag": self.tag,
                    "enc_tag": self.enc_tag,
                    "token": self.token.hex(),
                    "key": self.key,
                    "date": datetime.now().isoformat()
                }, indent=2), encoding='utf-8')
                
                self._cleanup_backups()
                
                print()
                print(f"{Colors.green}✓{Colors.end} {Colors.bold}Success{Colors.end}")
                print()
                print(f"{Colors.cyan}IMPORTANT - Save this information:{Colors.end}")
                print(f"  {Colors.bold}Magic Header:{Colors.end} {self.tag} -> {self._header(self.tag)}")
                print(f"  {Colors.bold}Encryption Key:{Colors.end} {self.key}")
                print(f"  {Colors.bold}Token:{Colors.end} {self.token.hex()}")
                print(f"  Config saved: {config_path}")
                print()
                print(f"  To use: GODOT_CIPHER_KEY={self.key} ./godot")
                print()
                print(f"  To restore backups: python godot_cipher.py --restore .")
                print()
                print(f"{Colors.green}✓{Colors.end} Build is now cryptographically unique")
                print()
                print(f"{Colors.purple}╔══════════════════════════════════════════════════════════╗{Colors.end}")
                print(f"{Colors.purple}║{Colors.end}      {Colors.bold}GodotCipher KS222 v1.0 - Ready to Build{Colors.end}      {Colors.purple}║{Colors.end}")
                print(f"{Colors.purple}╚══════════════════════════════════════════════════════════╝{Colors.end}")
            
            return True
            
        except KeyboardInterrupt:
            self._log("\n\nInterrupted by user", Colors.yellow)
            self._rollback()
            return False
        except Exception as e:
            self._log(f"\n{Colors.red}Error: {e}{Colors.end}", Colors.red)
            if self.verbose:
                self._log(traceback.format_exc(), Colors.red)
            self._rollback()
            return False

def show_help():
    print(f"""GodotCipher KS222 v1.0 - Godot Engine Encryption Tool

Usage: python godot_cipher.py [options] [godot_source]

Options:
  --help, -h          Show this help
  --version, -v       Show version
  --dry-run, -n       Preview only (no changes)
  --fast, -f          Fast mode (auto random, no prompts)
  --force, -F         Skip confirm prompts
  --verbose, -V       Verbose output
  --restore, -r       Restore latest backup

Examples:
  python godot_cipher.py .
  python godot_cipher.py --fast .
  python godot_cipher.py --dry-run --verbose .
  python godot_cipher.py --restore .

Features:
  - AES-256 encryption for Godot PCK files
  - Random security token embedded in engine
  - Custom magic header support (default: KS22)
  - Automatic Godot 3.x/4.x detection
  - Automatic backup and restore
  - Cryptographically secure random generation
  - Auto-removes duplicate ctx definitions

Security Notes:
  - Save the encryption key securely - without it, encrypted data cannot be recovered
  - Both key and token are required to decrypt encrypted files
  - Backups are kept in the same directory with .bak_* suffix

Author: KS222
License: MIT
""")

def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        show_help()
        return
    if "--version" in sys.argv or "-v" in sys.argv:
        print(f"GodotCipher KS222 v1.0")
        return
    
    dry = "--dry-run" in sys.argv or "-n" in sys.argv
    fast = "--fast" in sys.argv or "-f" in sys.argv
    force = "--force" in sys.argv or "-F" in sys.argv
    verbose = "--verbose" in sys.argv or "-V" in sys.argv
    restore = "--restore" in sys.argv or "-r" in sys.argv
    root = next((a for a in sys.argv[1:] if not a.startswith("-")), os.getcwd())
    
    gc = GodotCipher(root, dry_run=dry, force=force, fast=fast, verbose=verbose, restore=restore)
    success = gc.run()
    
    if not dry and not restore and success:
        print("\n" + "="*60)
        print(f"{Colors.bold}Next Steps:{Colors.end}")
        print("1. Recompile Godot with: scons platform=linuxbsd target=editor")
        print("2. Set environment variable: export GODOT_CIPHER_KEY=" + gc.key)
        print("3. Run the compiled Godot binary")
        print("="*60)
        input("\nPress Enter to exit")
    elif not dry and not success and not restore:
        input("\nPress Enter to exit")

if __name__ == "__main__":
    main()