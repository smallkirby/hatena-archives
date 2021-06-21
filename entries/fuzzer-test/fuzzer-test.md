keywords

# イントロ


# ex1. Diary from Balsn CTF 2020
## 問題概要
```static.sh
$ file ./diary
./diary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=53d5963091eba5e6879841c661d474196be39e5c, for GNU/Linux 3.2.0, stripped
$ checksec --file ./diary
[*] '/home/wataru/Documents/ctf/balsn2020/diary/share/diary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$ strings ./libc-2.29.so | grep GLIBC | tail -n1
GNU C Library (Ubuntu GLIBC 2.29-0ubuntu2) stable release version 2.29.
```
制約
- サイズ0x80以下
- エントリ数は13個以下

# exploit
```exploit.py
```

# おまけ
Ghidraのヘッドレススクリプト
競プロの例
今年の振り返りと来年の目標

# アウトロ

# 参考
