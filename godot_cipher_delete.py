#!/usr/bin/env python3
"""
Godot Cipher Delete Tool - 删除 file_access_encrypted.cpp 中重复的 ctx 定义
"""

import os
import re
import shutil
from pathlib import Path

def main():
    # 设置路径
    cpp_path = Path("core/io/file_access_encrypted.cpp")
    
    if not cpp_path.exists():
        print(f"❌ 文件不存在: {cpp_path}")
        return
    
    # 备份原文件
    backup_path = cpp_path.with_suffix(cpp_path.suffix + ".clean_bak")
    shutil.copy2(cpp_path, backup_path)
    print(f"✅ 备份已创建: {backup_path}")
    
    # 读取文件内容
    with open(cpp_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 查找并删除重复的 ctx
    new_lines = []
    skip_next = False
    deleted_count = 0
    
    for i, line in enumerate(lines):
        # 检查是否需要跳过（删除 ctx.set_encode_key 行）
        if skip_next:
            skip_next = False
            continue
        
        # 在 _close 函数中查找重复的 ctx
        if 'void FileAccessEncrypted::_close()' in line:
            # 进入 _close 函数，标记开始
            in_close = True
        
        # 查找重复模式：CryptoCore::AESContext ctx; 后面紧跟 ctx.set_encode_key(key.ptrw(), 256);
        if 'CryptoCore::AESContext ctx' in line and 'derived_key' not in line:
            # 检查下一行是否是 ctx.set_encode_key(key.ptrw(), 256);
            if i + 1 < len(lines) and 'ctx.set_encode_key' in lines[i + 1] and 'key.ptrw()' in lines[i + 1]:
                # 这是旧代码，跳过这两行
                print(f"🗑️  删除第 {i+1} 行: {line.strip()}")
                print(f"🗑️  删除第 {i+2} 行: {lines[i+1].strip()}")
                deleted_count += 2
                skip_next = True
                continue
        
        new_lines.append(line)
    
    # 写回文件
    with open(cpp_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print(f"\n✅ 已删除 {deleted_count} 行重复代码")
    print(f"✅ 文件已保存: {cpp_path}")
    
    # 验证结果
    with open(cpp_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    ctx_count = content.count('CryptoCore::AESContext ctx')
    print(f"\n📊 当前 ctx 定义次数: {ctx_count}")
    
    if ctx_count == 2:
        print("✅ 完美！解密块1个 ctx，加密块1个 ctx")
    else:
        print(f"⚠️  还有 {ctx_count} 个 ctx，可能需要手动检查")

if __name__ == "__main__":
    main()