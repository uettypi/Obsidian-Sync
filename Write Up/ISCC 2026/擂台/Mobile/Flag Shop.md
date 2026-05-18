
## 第一部分：题目剖析

从题干描述中，我们能提取到一个极具价值的线索：

- 所有伪造的 flag 格式均为 `ISCC{fakeflagfake}`
- 由此可以推断，APK 内部署了多组虚假商品数据，且正确的 flag 绝不可能在 Java 代码里直接以明文形式暴露
- 破局的关键必定隐藏于某个特定的校验机制，或是 native 层的加密算法之中

题目提供的附件为一个安卓安装包：

- `FlagShop.apk`

综合上述线索，我们可以敲定以下解题策略：

1. 首先逆向 DEX 文件，找出所有的商品清单及其关联的函数调用链条
2. 接着深入剖析 `libflagshop.so` 动态库，解析出管理员的登录验证机制以及 `encryptFlag` 的内部运作
3. 借助 fakeflag 作为测试样本，在本地搭建 oracle 进行仿真验证
4. 验证跑通后，将目标转向 `realflag` 以推导出真实的 flag 字符串

---

## 第二部分：DEX 逻辑逆向

### 1. 提取商品清单

通过反编译 `classes.dex`，我们在商品加载的初始化阶段锁定了 4 个核心商品项：

- `fakeflag1`
- `fakeflag2`
- `fakeflag3`
- `realflag`

与之对应，每个商品在代码中都绑定了一串 `encryptedHex`（加密后的十六进制数据）。

具体的十六进制内容提取如下：

### 伪造商品一：fakeflag1

```text
46534850840912118da77c2d7f480b5a3497e1c9cfd5fb6a15ffc5a68067f7bbd6b07028b9d52e53f1ea68d460c840a407db326f5e986d7e1305f8df01796fc56e188068355aff017715c6673d15e5f3af30a9e818e229d8
```

### 伪造商品二：fakeflag2

```text
46534850840912112ba9a049c2cc27ba76c2fd1340624573a1133272a504c589b360fac0d187c7db0346ad02dc4e38638e5f336155f28b64d71ae1f61769c6c91c3130d83d675755ee56f0d5c4bd74a07e4c794222cef2f2
```

### 伪造商品三：fakeflag3

```text
465348508409121105764efa14c617d84804c0e4f4e669ea8f5abd029b6b5c7a0ded5b1cdd0abb7f1cd9b765fe9e9009bd0e8e3f4354746c5e20f6d946ff2ff2fadcefcab00bb06984633a4ca24a690368951c43d8a507c5
```

### 真实商品：realflag

```text
4653485084083011788fb5d735cfa35810b48a3433ced888c02965457ad21cf80e4936cc8a536fee26b3ffc2a64981a878511f0d3ab96cdd05879fac83f005f9b5e311fa07d299b0d0580b4611afd6c8a4db205c1f278134
```

上述数据表明：

- 应用程序并没有把 flag 字符串直接存入商品信息中
- 商品绑定的这串数据，实际上是经过某种 native 加密流程处理后得到的十六进制密文

---

### 2. 追踪 Native 函数接口

顺着 DEX 中的代码逻辑向上回溯调用链，我们定位到了如下接口：

```text
NativeBridge.encryptFlag(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
```

继续追溯该方法的上层调用者，弄清了这 4 个字符串参数所代表的实际含义：

```text
encryptFlag(itemId, flagInput, username, password)
```

传参的先后顺序至关重要。在后续进行本地 Unicorn 仿真时，我们必须要严格遵照这一顺序进行赋值。

---

## 第三部分：Native 动态库分析

本题的核心 native 逻辑都在以下动态链接库中：

- `libflagshop.so`

使用逆向工具分析该 so 文件，我们可以找到几个极其关键的函数：

- `adminLogin`
- `encryptFlag`
- `helper_copy_jstring`
- `helper_compare_or_transform`

综合分析可得出如下结论：

- 对管理员身份的合法性校验是放在 native 侧执行的
- 针对商品 flag 的比对及加密过程同样是在 native 环境下完成的
- 单纯依靠修改或分析 DEX 层代码是无法还原出真实 flag 的

---

## 第四部分：管理员登录凭证还原

### 1. 账号获取

通过查看只读数据段（rodata），能直接找到和管理员相关的字符串。结合 `adminLogin` 函数内部的比较逻辑，可以认定登录用户名为：

```text
admin
```

---

### 2. 密码破解

管理员密码并不能通过简单地搜索明文获取。程序在 native 层初始化运行时，会动态将其写入 `.bss` 内存段中。

通过提取密码初始化函数并独立进行模拟运行，我们最终在内存地址 `0xf6f67` 附近成功截获了真实的密码：

```text
FlagShopAdmin2026
```

需要特别警惕的是，分析过程中极易将其误认为：

```text
FlagShopAdmin202
```

但是，正确的密码尾部必须包含数字 `6`：

```text
FlagShopAdmin2026
```

这个细节绝对不容忽视。哪怕只是遗漏了这一个末尾字符，也会致使 `encryptFlag` 函数永远跳转到失败逻辑，从而只返回一个空的字符串。

---

## 第五部分：搭建本地仿真 Oracle

为了能够不受限制且稳定地调用 `encryptFlag` 方法，我们使用 Unicorn 引擎针对 `libflagshop.so` 构建了一套本地仿真环境。

### 核心实现方案

1. 将 so 库中类型为 PT_LOAD 的段映射至内存
2. 修复 `.rela.dyn` 以及 `.rela.plt` 节区内的重定位信息
3. 伪造一个可用的 `JNIEnv` 环境及其虚函数表（vtable）
4. 对 `helper_copy_jstring` 进行 hook 处理，从而将 Java 层面的字符串转换为 native 形式的字符串结构
5. 将以下导入函数 stub（占位）掉：
   - `strlen`
   - `memcmp`
   - `memcpy`
   - `memmove`
   - `malloc`
   - `free`
   - `__open_2`
   - `read`
   - `close`
   - `__memcpy_chk`
6. 首选用 fakeflag 的已知数据进行对照校验，测试通过后再转入对 `realflag` 的运算

---

## 第六部分：利用 fakeflag 进行基准测试

题干里已经明确给出了虚假 flag 的标准明文：

```text
ISCC{fakeflagfake}
```

故而，用作基础校验的输入参数组合应当是：

```text
itemId    = fakeflag1
flagInput = ISCC{fakeflagfake}
username  = admin
password  = FlagShopAdmin2026
```

执行此步骤的主要目的在于确认：

- 四个参数的传递顺序是否存在偏差
- 提取到的管理员账号与密码是否准确无误
- Java 与 native 的交互模拟是否顺畅
- 仿真 oracle 是否顺利步入了代表“成功”的分支路径

测试得到的结论如下：

- 当密码错填为 `FlagShopAdmin202` 时，程序毫无悬念地走入异常分支并输出空串
- 修正为 `FlagShopAdmin2026` 之后，代码开始按照正常的工作流运转，不再触发失败逻辑

此现象充分印证了：

1. 提取所得的管理员鉴权凭证是正确的
2. `encryptFlag(itemId, flagInput, username, password)` 的参数排布完全符合预期
3. 目前构建的本地 oracle 具备极高的可靠性，可以放心应用到 `realflag` 的解密环节

---

## 第七部分：推导最终 Flag

在确定了上述所有前置条件后，这道题的脉络已经完全打通：

- 目标 `realflag` 所对应的预期密文已掌握
- `encryptFlag` 各项入参的真实排序已探明
- 管理员验证所需的账户密码已确认：
  - `admin`
  - `FlagShopAdmin2026`
- 针对 fakeflag 样本的本地 oracle 仿真也已验证成功

依托这些基础，我们将仿真的目标切换至 `realflag` 商品，以该商品对应的 native 返回结果为突破口进行逆向推演，最终得到了本次比赛的真正 flag：

```text
ISCC{7H15_1$_r431_f146_4nd_17_h45n'7_501d_0u7?!}
```

---

## 第八部分：赛题要点归纳

本题考察的重点绝非简单的静态字符串检索，其核心挑战在于：

1. 分析 DEX 文件，理清商品数据与 native 函数间的交互流程
2. 深入 so 底层，动态还原出管理员的登录密钥
3. 借助假 flag 样本构建并校验本地的 oracle 仿真脚本
4. 最后针对 `realflag` 进行加密算法分析以获取 flag 明文

在解题过程中容易踩到的坑主要包含以下三点：

- 容易被 fakeflag 的信息干扰解题方向
- 误以为 Java 层包含完整信息，而实际上关键逻辑都藏在 so 库里
- 还原管理员密码时极易漏掉末尾的数字 `6`

---

## 第九部分：最终答案输出

```text
ISCC{7H15_1$_r431_f146_4nd_17_h45n'7_501d_0u7?!}
```

---

## 第十部分：仿真脚本 (EXP)

下文附上在解答此题期间，用来在本地执行 Unicorn 仿真 `encryptFlag` 方法的完整代码：

```python
import glob
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.arm64_const import *

path = glob.glob(r'C:/Users/*/Downloads/FlagShop_extracted/lib/arm64-v8a/libflagshop.so')[0]
PAGE = 0x1000

def align_down(x):
    return x & ~(PAGE - 1)

def align_up(x):
    return (x + PAGE - 1) & ~(PAGE - 1)

def read_cstr(mu, addr, limit=0x1000):
    out = bytearray()
    for i in range(limit):
        b = mu.mem_read(addr + i, 1)[0]
        if b == 0:
            break
        out.append(b)
    return out.decode('utf-8', 'replace')

def write_cstr(mu, addr, s):
    mu.mem_write(addr, s.encode() + b'\x00')

with open(path, 'rb') as f:
    elf = ELFFile(f)
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    for seg in elf.iter_segments():
        if seg['p_type'] != 'PT_LOAD':
            continue
        vaddr = seg['p_vaddr']
        memsz = seg['p_memsz']
        filesz = seg['p_filesz']
        start = align_down(vaddr)
        end = align_up(vaddr + memsz)
        perms = 0
        flags = seg['p_flags']
        if flags & 4:
            perms |= UC_PROT_READ
        if flags & 2:
            perms |= UC_PROT_WRITE
        if flags & 1:
            perms |= UC_PROT_EXEC
        mu.mem_map(start, end - start, perms)
        mu.mem_write(vaddr, seg.data())
        if memsz > filesz:
            mu.mem_write(vaddr + filesz, b'\x00' * (memsz - filesz))

    for secname in ('.rela.dyn', '.rela.plt'):
        sec = elf.get_section_by_name(secname)
        if not sec:
            continue
        symtab = elf.get_section(sec['sh_link']) if sec['sh_link'] else None
        for rel in sec.iter_relocations():
            rtype = rel['r_info_type']
            off = rel['r_offset']
            addend = rel['r_addend'] if rel.is_RELA() else 0
            if rtype == 1027:
                mu.mem_write(off, struct.pack('<q', addend))

    stack = 0x2000000
    mu.mem_map(stack, 0x200000, UC_PROT_ALL)
    sp = stack + 0x1f0000
    mu.reg_write(UC_ARM64_REG_SP, sp)
    mu.reg_write(UC_ARM64_REG_X29, sp)

    env = 0x3000000
    vtbl = 0x3001000
    mu.mem_map(0x3000000, 0x30000, UC_PROT_ALL)
    mu.mem_write(env, struct.pack('<Q', vtbl))

    stub_base = 0x3100000
    mu.mem_map(stub_base, 0x10000, UC_PROT_ALL)
    ret_stub = b'\xc0\x03\x5f\xd6'
    stub_for = {}
    stub_i = 0
    plt = elf.get_section_by_name('.rela.plt')
    if plt:
        symtab = elf.get_section(plt['sh_link'])
        for rel in plt.iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym']).name if rel['r_info_sym'] else ''
            if sym not in stub_for:
                stub_for[sym] = stub_base + stub_i * 0x100
                mu.mem_write(stub_for[sym], ret_stub)
                stub_i += 1
            mu.mem_write(rel['r_offset'], struct.pack('<Q', stub_for[sym]))

    newstring_stub = 0x3200000
    mu.mem_map(newstring_stub, 0x1000, UC_PROT_ALL)
    mu.mem_write(newstring_stub, ret_stub)
    mu.mem_write(vtbl + 0x538, struct.pack('<Q', newstring_stub))

    data = 0x3300000
    mu.mem_map(data, 0x40000, UC_PROT_ALL)

    def cstr(addr, s):
        write_cstr(mu, addr, s)
        return addr

    item = cstr(data + 0x000, 'fakeflag1')
    flag = cstr(data + 0x100, 'ISCC{fakeflagfake}')
    user = cstr(data + 0x200, 'admin')
    pw = cstr(data + 0x300, 'FlagShopAdmin2026')

    heap = 0x3400000
    mu.mem_map(heap, 0x40000, UC_PROT_ALL)
    heap_next = [heap]

    def alloc(size, align=0x10):
        cur = (heap_next[0] + align - 1) & ~(align - 1)
        heap_next[0] = cur + size
        return cur

    def write_std_string(addr, s):
        b = s.encode()
        mu.mem_write(addr, b'\x00' * 0x20)
        if len(b) <= 22:
            mu.mem_write(addr, bytes([len(b) << 1]) + b + b'\x00' * (23 - len(b)))
            return
        ptr = alloc(len(b) + 1)
        mu.mem_write(ptr, b + b'\x00')
        mu.mem_write(addr, struct.pack('<Q', 1))
        mu.mem_write(addr + 8, struct.pack('<Q', len(b)))
        mu.mem_write(addr + 16, struct.pack('<Q', ptr))

    ret_strings = []
    trace = []

    def decode_std_string(addr):
        b0 = mu.mem_read(addr, 1)[0]
        if (b0 & 1) == 0:
            n = b0 >> 1
            raw = bytes(mu.mem_read(addr + 1, n))
            return raw.decode('utf-8', 'replace')
        n = struct.unpack('<Q', bytes(mu.mem_read(addr + 8, 8)))[0]
        p = struct.unpack('<Q', bytes(mu.mem_read(addr + 16, 8)))[0]
        raw = bytes(mu.mem_read(p, min(n, 0x200)))
        return raw.decode('utf-8', 'replace')

    def emulate_symbol(sym):
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        x2 = mu.reg_read(UC_ARM64_REG_X2)
        lr = mu.reg_read(UC_ARM64_REG_LR)
        if sym == 'strlen':
            trace.append(('call', sym, hex(lr), hex(x0), read_cstr(mu, x0)[:120]))
            mu.reg_write(UC_ARM64_REG_X0, len(read_cstr(mu, x0).encode()))
        elif sym == 'strcmp':
            a = read_cstr(mu, x0)
            b = read_cstr(mu, x1)
            trace.append(('call', sym, hex(lr), a[:80], b[:80]))
            mu.reg_write(UC_ARM64_REG_X0, (a > b) - (a < b))
        elif sym == 'strncmp':
            a = read_cstr(mu, x0)[:x2]
            b = read_cstr(mu, x1)[:x2]
            trace.append(('call', sym, hex(lr), a[:80], b[:80], x2))
            mu.reg_write(UC_ARM64_REG_X0, (a > b) - (a < b))
        elif sym == 'memcmp':
            a = bytes(mu.mem_read(x0, x2))
            b = bytes(mu.mem_read(x1, x2))
            trace.append(('call', sym, hex(lr), x2, a[:64].hex(), b[:64].hex()))
            mu.reg_write(UC_ARM64_REG_X0, (a > b) - (a < b))
        elif sym in ('memcpy', '__memcpy_chk', 'memmove'):
            trace.append(('call', sym, hex(lr), hex(x0), hex(x1), x2))
            mu.mem_write(x0, bytes(mu.mem_read(x1, x2)))
            mu.reg_write(UC_ARM64_REG_X0, x0)
        elif sym == 'memset':
            mu.mem_write(x0, bytes([x1 & 0xff]) * x2)
            mu.reg_write(UC_ARM64_REG_X0, x0)
        elif sym == 'malloc':
            mu.reg_write(UC_ARM64_REG_X0, alloc(max(x0, 1)))
        elif sym == 'realloc':
            p = alloc(max(x1, 1))
            if x0:
                mu.mem_write(p, bytes(mu.mem_read(x0, x1)))
            mu.reg_write(UC_ARM64_REG_X0, p)
        elif sym == 'free':
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif sym == '__system_property_get':
            prop = read_cstr(mu, x0)
            val = '1' if 'frida' in prop.lower() else ''
            write_cstr(mu, x1, val)
            mu.reg_write(UC_ARM64_REG_X0, len(val))
        elif sym == 'strstr':
            hay = read_cstr(mu, x0)
            nee = read_cstr(mu, x1)
            idx = hay.find(nee)
            mu.reg_write(UC_ARM64_REG_X0, 0 if idx < 0 else x0 + idx)
        elif sym == 'getpid':
            mu.reg_write(UC_ARM64_REG_X0, 1234)
        elif sym == 'syscall':
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif sym in ('abort', '__stack_chk_fail'):
            raise RuntimeError(sym)
        else:
            mu.reg_write(UC_ARM64_REG_X0, 0)

    def hook_code(mu, addr, size, user_data):
        if addr == 0x5007c:
            src = mu.reg_read(UC_ARM64_REG_X1)
            target = mu.reg_read(UC_ARM64_REG_X8)
            s = read_cstr(mu, src)
            write_std_string(target, s)
            trace.append(('copy', hex(target), s, bytes(mu.mem_read(target, 24)).hex()))
            mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
            return
        if addr == newstring_stub:
            s = read_cstr(mu, mu.reg_read(UC_ARM64_REG_X1))
            ret_strings.append(s)
            trace.append(('retstr', hex(mu.reg_read(UC_ARM64_REG_LR)), s[:120]))
            mu.reg_write(UC_ARM64_REG_X0, mu.reg_read(UC_ARM64_REG_X1))
            mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
            return
        if addr in (0x52280, 0x522b4, 0x522c8, 0x522f4, 0x52384, 0x523b8, 0x523cc, 0x523f8, 0x52464, 0x52498, 0x524ac, 0x524d8, 0x53024, 0x53058, 0x5306c, 0x53098, 0x53154, 0x53188, 0x5319c, 0x531c8, 0x5377c, 0x537a8, 0x537bc):
            base = mu.reg_read(UC_ARM64_REG_X8)
            target = struct.unpack('<Q', bytes(mu.mem_read(base, 8)))[0] if base else 0
            trace.append(('indirect', hex(addr), hex(base), hex(target)))
        for sym, stub in stub_for.items():
            if addr == stub:
                trace.append(('ext', sym))
                emulate_symbol(sym)
                mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
                return
        if addr == 0x6e1ac:
            trace.append(('skip', hex(addr)))
            mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
            return

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.reg_write(UC_ARM64_REG_X0, env)
    mu.reg_write(UC_ARM64_REG_X1, 0x1234)
    mu.reg_write(UC_ARM64_REG_X2, item)
    mu.reg_write(UC_ARM64_REG_X3, flag)
    mu.reg_write(UC_ARM64_REG_X4, user)
    mu.reg_write(UC_ARM64_REG_X5, pw)

    try:
        mu.emu_start(0x517a8, 0x56000, count=10000000)
        print('EMU_OK')
    except Exception as e:
        print('EMUERR', type(e).__name__, e)
        print('PC', hex(mu.reg_read(UC_ARM64_REG_PC)))
        print('LR', hex(mu.reg_read(UC_ARM64_REG_LR)))

    print('RETCOUNT', len(ret_strings))
    for i, s in enumerate(ret_strings[:20]):
        print('RET', i, repr(s[:200]))
    print('TRACECOUNT', len(trace))
    for t in trace:
        print('TRACE', t)
```