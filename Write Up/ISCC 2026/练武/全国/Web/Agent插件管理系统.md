
## 漏洞剖析与思路

本题构建了一个模拟的插件管理平台，其主要业务流程包含接收用户上传的插件压缩包、执行安全性检验以及后续的插件装载操作。

对前端逻辑和获取到的 `agent-core.jar` 核心包进行逆向审查后，可以提炼出如下几个核心机制：

- 提交的压缩包内部必须具备 `manifest.json` 与 `metadata.ser` 这两个核心文件
- 系统会利用 HMAC 算法针对 `metadata.ser` 实施数据完整性与合法性校验
- 校验阶段所需的 HMAC 密钥硬编码于 `application.yml` 配置文件内，其具体取值为 `k3y_5A62_X86`
- 当文件上传完毕后，服务器端会立即触发针对 `metadata.ser` 的反序列化处理

进一步深挖与反序列化机制相关的底层类，能够挖掘出一条完整的利用链条，涉及以下组件：

- `ResourceRefresher`
- `DataStream`
- `FileExporter`

在此链条中，`FileExporter.export(path)` 负责获取目标路径下的文件数据，并随后触发 `LogService.log(...)` 方法，将提取到的数据写入与特定 `team_id` 绑定的日志记录中。

根据上述逻辑，只要我们能够成功传入精心构造的恶意序列化载荷，就能顺理成章地达成读取服务器任意文件的目的。

## 攻击复现步骤

1. 制作恶意的序列化文件 `metadata.ser`：
   - 将最外层的反序列化入口（即根对象）设定为 `ResourceRefresher`
   - 引导该对象在解析过程中自动调用 `DataStream`
   - 最终借由 `FileExporter` 完成将靶机本地文件信息外带至系统日志的操作

2. 运用前置分析获取到的 HMAC 密钥来为上述构造的 `metadata.ser` 生成合法签名：
   - 签名所用密钥：`k3y_5A62_X86`

3. 按照系统要求的目录结构打包生成最终的恶意插件文件：
   - `manifest.json`
   - `metadata.ser`

4. 向系统指定的路由发起请求以上传恶意插件：
   - `/api/upload`

5. 访问日志查询接口提取已被写入的外带数据：
   - `/api/logs?team_id=你的team_id`

## 结果与信息提取

最初尝试抓取目标 `/etc/flag`，然而返回的内容为具备迷惑性的虚假 flag：

`ISCC{f4k3_fl4g_d3c0y_d0nt_subm1t}`

随后进一步对服务器的实际运行环境进行了信息探测，明确了真正的业务部署目录及关键配置文件位置，随即执行了对以下文件的读取操作：

- `/opt/app/.env`

此时系统日志中成功回显了真正的 flag 字符串：

`ISCC{aunXV6waj5Hp8cT35SwVcKK}`

## 最终 Flag 获取

`ISCC{aunXV6waj5Hp8cT35SwVcKK}`