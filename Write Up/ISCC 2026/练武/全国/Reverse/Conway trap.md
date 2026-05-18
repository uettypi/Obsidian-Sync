
基本情况

附件解压后得到 Conway's Trap.exe。

file 显示它是 PE32 executable for MS Windows，Intel i386，控制台程序。导入表和字符串都能正常看到，未见壳。PE 头里 DllCharacteristics 带有 DYNAMIC_BASE 和 NX_COMPAT，也就是开启 ASLR 和 NX。

逆向分析

我先从字符串入手，程序有两个输入阶段。

第一阶段输出 Enter seed，要求输入 32 位十六进制字符串。程序把它转成 16 字节，然后连续做 5 轮字节变换，最后把结果转成小写 hex，与全局字符串 df7b6a5d4da0f5facf32c4ee4b28b792 比较。

这一轮变换本身是可逆的，核心逻辑如下。

```c
for (i = 0; i < 16; i += 2) {
    a = buf[i];
    b = buf[i + 1];
    buf[i] = (a + b) & 0xff;
    buf[i + 1] = rol8(buf[i] ^ b, 1);
}
rotate_left(buf, 16, 1);
```

逆回去时先右移一位，再按每两个字节反推。

```c
old_b = ror8(new_b, 1) ^ new_a;
old_a = (new_a - old_b) & 0xff;
```

因此 seed 为：

```text
0b5e321c68e0e4fb2d972226e8c70f8d
```

第二阶段输出 Enter flag。明面逻辑先检查格式，必须是 ISCC{...}，然后取花括号里的内容。

这里真正的坑在 DoNotPatchMe 附近。程序初始化时安装了异常处理，并把一个检查函数的首字节改成 int3。表面上看的函数只是干扰代码，实际执行时会触发断点异常，异常处理函数把执行流改到隐藏校验函数。

隐藏校验只在第一次进入时完整检查 flag 内容。它先把一段栈上常量整体异或 0xcc 得到 23 字节目标，然后用原始 seed 的 16 字节作为密钥校验 flag 内容。

关键逻辑可以整理成下面这样。

```c
secret = const_bytes ^ 0xcc;
for (i = 0; i < 23; i++) {
    t = seed[i & 0xf] ^ flag_body[i];
    t = (t + i * 0x17) & 0xff;
    t = rol8(t, 3) ^ 0xaa;
    if (t != secret[i]) fail;
}
seed[0] = 0xde;
seed[1] = 0xad;
```

主校验函数后面会检查 seed 前两字节是否已经被改成 dead。如果是，就直接返回正确。所以后面那段很长的字符串比较更像是干扰项，不是正常拿 flag 的关键路径。

把隐藏校验逆回去，得到 flag 内容：

```text
XotJoq#6Wesa$eM(ZHtjcal
```

最终 flag 为：

```text
ISCC{XotJoq#6Wesa$eM(ZHtjcal}
```

解题脚本

脚本默认读取 ./附件，也可以手动指定 zip 或 exe 路径。它会从附件中提取 seed 目标和隐藏校验常量，再按算法计算 seed 和 flag。

```python
import re
import sys
import zipfile
from pathlib import Path


def read_attachment(path: Path) -> bytes:
    data = path.read_bytes()
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if not n.endswith('/')]
            if not names:
                raise ValueError('zip archive is empty')
            exe_names = [n for n in names if n.lower().endswith('.exe')]
            name = exe_names[0] if exe_names else names[0]
            data = zf.read(name)
    return data


def rol8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xff


def ror8(x: int, n: int) -> int:
    return ((x >> n) | (x << (8 - n))) & 0xff


def inv_seed_round(buf: bytes) -> bytes:
    b = list(buf)
    b = [b[-1]] + b[:-1]
    for i in range(0, 16, 2):
        new_a = b[i]
        new_b = b[i + 1]
        old_b = ror8(new_b, 1) ^ new_a
        old_a = (new_a - old_b) & 0xff
        b[i] = old_a
        b[i + 1] = old_b
    return bytes(b)


def recover_seed(data: bytes) -> bytes:
    hits = re.findall(rb'(?<![0-9A-Fa-f])([0-9A-Fa-f]{32})\x00', data)
    if not hits:
        raise ValueError('seed target was not found')
    target = bytes.fromhex(hits[0].decode())
    seed = target
    for _ in range(5):
        seed = inv_seed_round(seed)
    return seed


def extract_hidden_secret(data: bytes) -> bytes:
    pattern = (
        rb'\xc7\x45\xe4(.{4})\xc7\x45\xe8(.{4})\xc7\x45\xec(.{4})'
        rb'\xc7\x45\xf0(.{4})\xc7\x45\xf4(.{4})\x66\xc7\x45\xf8(.{2})\xc6\x45\xfa(.)'
    )
    match = re.search(pattern, data, re.S)
    if not match:
        raise ValueError('hidden checker constants were not found')
    enc = b''.join(match.groups())
    return bytes(x ^ 0xcc for x in enc)


def recover_flag_body(seed: bytes, secret: bytes) -> str:
    out = []
    for i, value in enumerate(secret):
        t = ror8(value ^ 0xaa, 3)
        t = (t - ((i * 0x17) & 0xff)) & 0xff
        out.append(t ^ seed[i & 0x0f])
    return bytes(out).decode('latin1')


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('./附件')
    data = read_attachment(path)
    seed = recover_seed(data)
    secret = extract_hidden_secret(data)
    body = recover_flag_body(seed, secret)
    print('seed:', seed.hex())
    print('flag:', f'ISCC{{{body}}}')


if __name__ == '__main__':
    main()
```

运行结果如下。

```text
seed: 0b5e321c68e0e4fb2d972226e8c70f8d
flag: ISCC{XotJoq#6Wesa$eM(ZHtjcal}
```

EXP运行截图

![image.png](https://img.uettypi.top/2026/05/20260518114132796.png)