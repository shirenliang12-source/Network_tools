# 网络运维与故障排除工具平台（netops-console）

面向企业、园区和数据中心网络的**纯内网可运行**运维工具平台。产品默认进入工具箱，不包含运营大屏或展示型模块；所有页面都服务于网络发现、设备查询、故障定位、配置操作、抓包分析和处置闭环。

内置能力按行业常用工作流组织：

| 主流工具/方法 | 平台内置能力 |
| --- | --- |
| Nmap | 主机发现、端口扫描、Banner/服务/OS 指纹、暴露面检查 |
| MTR / traceroute / ping | 连通性、逐跳延迟、丢包与抖动定位 |
| dig / nslookup | 多记录类型、多 DNS 服务器一致性与劫持检查 |
| curl / OpenSSL | HTTP 可用性、重定向链、响应头、TLS 证书与加密套件 |
| Net-SNMP | SNMP v1/v2c/v3 GET 与 WALK（只读，不提供 SET） |
| Wireshark / tshark | 抓包任务、PCAP 解析、协议识别、会话回溯与性能指标 |
| iperf3 | TCP/UDP 吞吐测试，并提供无外部依赖的内置测速引擎 |
| SSH / 厂商 CLI | Web 终端、命令模板、批量下发、预检查、录像与审计 |

### 工具运行时：随平台自动就绪

Windows 首次启动后，平台会在后台检测并静默部署 **Nmap 7.991、TShark/Wireshark 4.6.9、iperf3 3.22**，运行文件与状态统一放在 `data/runtime/`，无需用户逐个下载安装。下载来自项目官网或 Windows Package Manager；Nmap 与 Wireshark 安装包会做 SHA-256 校验。MTR 使用平台内置的逐跳丢包/延迟引擎，Net-SNMP 使用内置 `net-snmp` 模块，所以这两项从首次启动起即可使用。打包版首次启动会统一申请一次 Windows 管理员权限，用于本机抓包和受 UAC 保护的工具部署，不会再弹出各软件自己的安装向导。

Npcap 免费版的许可与安装器不支持第三方产品静默再分发，因此平台不会绕过其授权限制：本机已有 Npcap 时使用 **TShark + Npcap** 实时采集；未安装时自动使用 Windows 自带 **PktMon** 抓包，再转为 PCAP/PCAPNG 交给 TShark 解析。Nmap 的免费 Windows 静默安装器同样要求机器已存在 Npcap；不满足时平台保留已校验的官方安装包并自动启用内置 TCP/ICMP/端口扫描器，不影响扫描功能，拥有 Npcap/Nmap OEM 授权的部署可直接静默启用原生 Nmap。两种抓包后端都在平台页面内完成，不需要另开软件。可在「系统管理 → 运行状态 → 网络工具运行时」查看部署进度或一键重试；设 `AUTO_INSTALL_TOOLS=0` 可关闭后台部署。

- 技术栈：Node.js 20+ / Express 5 / WebSocket / ssh2，前端 Vue 3 + ECharts（**零构建**，直接从 `node_modules` 静态映射，无外网也能跑）
- 数据存储：不依赖外部数据库，全部落在 `data/` 目录，备份即打包该文件夹

---

## 一、快速开始

### 方式 0：正式发布包（Windows / Linux / Docker / macOS）

GitHub Releases 提供四套部署包：

| 发布包 | 内容 | 启动方式 |
| --- | --- | --- |
| Windows x64 | 单文件 EXE + 启动脚本 | 双击 `启动平台.cmd` |
| Linux x64 | 单文件二进制 + systemd 安装脚本 | `sudo ./install.sh` |
| Docker | Dockerfile + Compose + 完整源码 | `docker compose up -d --build` |
| macOS | Apple Silicon 与 Intel 双架构、ad-hoc 签名二进制 | 双击 `start.command` |

四种版本都不需要用户逐项配置平台依赖。Windows 会在首次启动后后台检测工具；Linux 安装脚本和 Docker 镜像会安装 Nmap、TShark、MTR、iperf3、Net-SNMP；macOS 包提供一键 Homebrew 工具安装脚本，平台自身的回退能力无需这些外部命令也可启动。

Windows 解压后双击 `启动平台.cmd` 即可，**不需要装 Node.js**，也不用执行 `npm install`。

- 服务就绪后自动打开 `http://127.0.0.1:8787`，关闭黑窗口即停止服务
- 数据（账号、凭据、测速记录、抓包索引、审计日志）写在 **exe 所在目录的 `data\` 文件夹**里
- **不要把 exe 放在 `C:\Program Files\` 等只读目录**，那样启动会报「数据目录不可用」。放到桌面、D 盘、项目目录等普通可写位置即可

重新打包四个平台二进制（改过 `server/` 或 `public/` 之后需要）：

```bash
npm run build          # 产出 dist/bin 下的 Windows、Linux、macOS x64/arm64 二进制
```

打包依赖仍在维护的 [@yao-pkg/pkg](https://github.com/yao-pkg/pkg)，首次执行会从网上下载 Node 基础运行时（约 37 MB），需要能联网。缓存目录是 `C:\Users\<你>\.pkg-cache`。

已知限制：

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `Error! No available node version satisfies 'node20'` | pkg-fetch 目前最高只提供到 **Node 18** 的基础运行时 | 项目已改用 `node18-win-x64` 目标（Express 5 要求 ≥ 18，够用） |
| 打包卡住很久无输出 | 基础运行时是从 GitHub 下载的，国内网络慢 | 见下方「手动预置缓存」 |
| 打包报 `Property 'bin' does not exist` | `package.json` 缺 `bin` 字段 | 已补 `"bin": "server/index.js"`，pkg 的硬性要求 |

手动预置缓存（下载太慢时用）：

```bash
# 基础运行时本体在 GitHub 上的文件名【不带扩展名】
curl -L -o "$USERPROFILE/.pkg-cache/Fetcher/v3.4/node-v18.5.0-win-x64" \
  https://github.com/vercel/pkg-fetch/releases/download/v3.4/node-v18.5.0-win-x64
# 校验，应与 e0e9a647d81011612f8cb19c6a41760643eedd27222af548e9ffdff7d8ebb94b 一致
sha256sum "$USERPROFILE/.pkg-cache/Fetcher/v3.4/node-v18.5.0-win-x64"
```

放到这个位置后 pkg 会直接复用，不再重复下载。

打包前后建议各跑一遍真实浏览器验证（会启动无头 Chrome，登录后逐页检查渲染并抓取控制台报错，`SHOTS=1` 额外输出截图到 `dist\ui-shot\`）：

```bash
npm run check                            # 静态自检：模板编译 + 重复键扫描
npm run e2e                              # 接口回归 98 项
node tools/verify-ui.js http://127.0.0.1:8787/        # 验证源码服务（需先启动）
USE_EXE=1 node tools/verify-ui.js http://127.0.0.1:8791/   # 验证打包出的 EXE 本体
```

`verify-ui.js` 支持 `SKIP_SRV=1`（复用已运行的服务，不自己拉起）和 `SHOTS=1`（截图取证）。

### 方式 A：Windows 一键启动（推荐）

双击项目根目录下的 **start.bat**：

- 自动检测 Node.js（未安装会提示下载地址）
- 首次运行若缺依赖，自动执行 `npm install`
- 自动打开浏览器 `http://127.0.0.1:8787`
- **控制台窗口请勿关闭**，关闭即停止服务

### 方式 B：命令行

```bash
node -v                  # 需 >= 20
npm install
node server/index.js
```

自定义端口：`PORT=8080 node server/index.js`

### 局域网多人访问

启动后控制台会打印本机局域网 IP，例如：

```
本机访问        http://127.0.0.1:8787
局域网访问      http://10.252.28.66:8787
```

同事在同一网段（或已经连上 FortiClient VPN）打开 `http://<你的办公电脑内网IP>:8787` 即可，无需安装任何客户端。

> 若打不开，检查办公电脑的 Windows 防火墙是否放行 8787 端口，或在管理员 PowerShell 执行一次：
> `netsh advfirewall firewall add rule name="netops-console" dir=in action=allow protocol=TCP localport=8787`

### 访问不了怎么排查

按下面顺序逐条试，一般前两条就能解决：

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `127.0.0.1:8787` 能开，但 `localhost:8787` 打不开 | Windows 把 `localhost` 解析到了 `::1`，而服务没监听 IPv6 | 服务端已默认双栈监听（同时绑 `0.0.0.0` 与 `[::]`），无需改动；仍不行时改用 `127.0.0.1` |
| 双击 `start.bat` 后浏览器显示「无法访问此网站」 | **旧版脚本在服务启动之前就打开了浏览器**，此时 node 还没绑定端口 | 已修复：改为**服务就绪后**由服务自己打开浏览器（`start.bat` 不再抢跑）。若浏览器仍停在旧错误页，刷新一次即可 |
| 双击 `start.bat` 后窗口一闪，报 `EADDRINUSE` | 8787 已被上一个实例占用，新实例启动失败 | 控制台会提示「端口 8787 已在监听」并直接打开页面。**要重启就先关掉另一个命令行窗口**再重新双击 |
| `start.bat` 里冒出 `'副本），先建库再执行迁移：'`、`'TABASE_URL' is not recognized` | `start.bat` / `check.bat` 被改成了 UTF-8 编码 | 这两个文件**必须保持 GBK(936) 编码**。UTF-8 中文是多字节，`cmd` 在 `chcp 65001` 下按字节重新分词会把 `rem` 注释当命令执行 |
| `http://[::1]:8787` 返回 000 | 服务只监听了 IPv4 | 已修复为双栈，见第一行；升级后重启即可 |

> 自检这两条最省事：
> `netstat -ano | findstr ":8787"` 看是否同时有 `0.0.0.0:8787` 和 `[::]:8787` 两条 LISTENING；
> `curl -o /dev/null -w "%{http_code}" http://localhost:8787/` 应返回 `200`。

### 使用 PostgreSQL（可选，推荐）

默认零依赖跑在 `data/db.json`。数据量上来（会话库每天几万条）或要让**应用与数据库分离部署**时，切到 PostgreSQL：

```bash
# 1) 建库（本机没装 PG 就去 https://www.postgresql.org/download/windows/ 装一路 next 即可）
createdb netops

# 2) 建表 + 可选的数据迁移（把 db.json 里已有的数据搬进 PG）
node tools/migrate.js --url postgres://postgres:密码@127.0.0.1:5432/netops --data data/db.json

# 只体检不写入 / 只看 SQL：
node tools/migrate.js --url postgres://... --check
node tools/migrate.js --url postgres://... --dry-run
```

然后把连接串写进环境变量（PowerShell：`$env:DATABASE_URL = "postgres://..."`；或项目根目录建一个 `.env` 写一行 `DATABASE_URL=postgres://...`），再启动服务：

```bash
DATABASE_URL=postgres://postgres:密码@127.0.0.1:5432/netops node server/index.js
```

- 只要 `DATABASE_URL` 非空就走 PG；不设就是 JSON 文件，业务代码零改动
- 启动时会打印 `存储 PostgreSQL / JSON 文件`，「系统管理 → 运行状态」里也有实时驱动与延迟
- 迁移脚本全部幂等（IF NOT EXISTS），可反复执行；`--force` 可覆盖已存在行
- 外置 PG 后应用自身可完全无状态：多副本共享同一库，令牌密钥用 `AUTH_SHARED_SECRET` 环境变量固定，方便 nginx 反代下多实例水平扩容

### 数据存哪：JSON 与 PostgreSQL 双实现

| | JSON 模式（默认） | PostgreSQL 模式 |
|---|---|---|
| 适用 | 单机、几十台设备 | 多人协作、会话库长期留存、程序与库分离部署 |
| 数据位置 | `data/db.json` | 你自己的 PG 实例 |
| 建表 | 无需 | `tools/migrate.js` 一键建 14 张表 |
| 备份 | 拷 `data/` 整个目录 | `pg_dump` |

应用层只依赖 `server/db/` 这一层接口（`settings / users / credentials / templates / alarms / inventory / topology / aiHistory / audit / speedResults / recordingMeta / captureFiles / captureTasks / flowSessions`），换成 PG 不改任何业务代码。

### 默认账号

| 账号 | 密码 | 角色 | 说明 |
|---|---|---|---|
| `admin` | `admin@123` | 管理员 | 全部权限，可改系统配置、建用户、管凭据 |
| `ops` | `ops@123` | 运维 | 可看设备、开终端、下发配置、抓包、测速、处理告警 |
| `audit` | `audit@123` | 审计 | 只读 + 会话回放 + 审计日志，**不能**下发与抓包 |

> 首次登录后建议立刻到「系统管理 → 用户与分权」改掉默认密码。

---

## 二、权限矩阵

| 能力 | admin | ops | audit |
|---|:---:|:---:|:---:|
| 设备 / 端口 / 详情 / 拓扑 查看 | ✅ | ✅ | ✅ |
| Web 终端连接 | ✅ | ✅ | ❌ |
| 命令模板与批量配置下发 | ✅ | ✅ | ❌ |
| 会话录像读取与回放 | ✅ | ✅ | ✅ |
| 抓包发起与 pcap 下载 | ✅ | ✅ | ❌ |
| 内网测速（内置吞吐 / 探测） | ✅ | ✅ | ❌ |
| 网络扫描发起与任务管理 | ✅ | ✅ | ❌ |
| SNMP GET / WALK 设备查询 | ✅ | ✅ | ❌ |
| 扫描结果读取（主机 / 端口 / 统计 / 报告） | ✅ | ✅ | ✅ |
| 诊断工具箱发起（摄像头 / IP 冲突 / 环路 / 日志审计 / 测速 / DHCP） | ✅ | ✅ | ❌ |
| 诊断结果读取（问题清单 / 主机 / 审计日志 / 历史） | ✅ | ✅ | ✅ |
| Syslog 接收开关 | ✅ | ❌ | ❌ |
| 告警确认 / 关闭 / 手动创建 / 推送 | ✅ | ✅ | ✅ |
| AI 助手问答 | ✅ | ✅ | ✅ |
| 修改系统设置 / 用户 / 凭据 | ✅ | ❌ | ❌ |
| 审计日志读取 | ✅ | ✅ | ✅ |

所有敏感操作（登录、下发、抓包、改密、改配置）都会写入 `data/logs/audit-*.ndjson`，可在「系统管理 → 审计日志」筛选查询与导出 CSV。

---

## 三、接入 Zabbix（真实数据）

系统默认跑在**演示模式**，内置 13 台多厂商设备（Cisco N9K/C9200/C9300/C9500/2960、华为 S5735/S1730、H3C S5560、FortiGate 400F、Palo Alto PA-820、Cisco Firepower 2110），先把功能跑通。接真数据只需两步：

1. 进入 **系统管理 → 数据源**
2. 数据源模式选 **Zabbix**，填写：

| 字段 | 说明 |
|---|---|
| API URL | 如 `http://10.252.28.99`（Zabbix 7.x 无需带 `/api_jsonrpc.php`，程序会自动拼） |
| 用户名 | 建议单独建一个只读/只写 API 用户，如 `api_snmp` |
| 密码 | Zabbix 用户密码，保存时以 AES-256-GCM 加密落盘 |
| 超时 | 默认 15000 ms，Zabbix 卡顿时调大 |
| TLS 校验 | 用自签证书的内网 Zabbix 关掉即可 |

3. 点 **测试连接**，平台会读取 Zabbix 主机组；勾选需要纳管的组（可多选）。不勾选表示同步当前 API 账号有权限访问的全部组
4. 点 **立即同步**，同步结果会回显设备数、主机组和完成时间；保存后同步范围持续生效
5. 回**告警中心 / 设备资产**刷新，数据即来自 Zabbix，资产列表与详情均会显示所属主机组

对接要点：

- 数据源切换后，端口列表会优先读取 Zabbix 中已配置的 Item（对外网口/CPU/内存/温度），读不到的数据项自动回退到演示值，不会白屏
- 主机组筛选直接传给 Zabbix `host.get`，只拉取选中组中的设备；同一设备属于多个组选中时只保留一条，并完整展示组归属
- 所有 Zabbix 查询带 **25 秒 TTL 缓存**，频繁查看设备与告警也不会把 Zabbix 打爆
- 每次取数失败会在「系统管理 → 运行状态」显示 `lastError`，页面会给出错误提示

---

## 四、凭据库：让 Web 终端连真机

演示模式下终端连的是**内置 CLI 模拟器**（已内置 Cisco IOS/NX-OS、华为 VRP、H3C Comware、Fortinet、Palo Alto 的应答，命令随便敲都有正常回显，非常适合培训与演练）。要连真机：

1. **系统管理 → 凭据库 → 新增**
   - 名称：如 `核心机房-SSH`
   - 类型：`ssh`（后续可扩展 telnet/snmp/zabbix）
   - 地址/端口：`10.252.28.11` / `22`
   - 账号：`admin`，密码：设备登录密码
   - Enable 密码：Cisco 的 `enable` 密码可单独填
2. 点 **测试** 按钮，会做一次真实 TCP + SSH 握手验证
3. 回 **Web 终端** 页，新建会话时选中该凭据，连接模式会显示「真机」而不是「演示」

> 凭据密码以 AES-256-GCM 加密，`data/.masterkey` 保存主密钥（文件权限 600）。**备份 `db.json` 时请连同 `.masterkey` 一起备份，否则凭据无法解密。**

---

## 五、Web 终端与配置下发

页面：**/terminal**，四个功能区块：

### 1. 多标签会话
- 可同时开多个标签连不同设备（核心/汇聚/接入同时排障）
- 支持 ↑ / ↓ 调出历史命令、点输入框自动聚焦、按窗口宽度自适应换行
- 会话全程录像（ndjson），可随时回放

### 2. 命令模板
- 内置 13 个常用模板（查版本、端口状态、错包统计、MAC/ARP 表、生成树、CPU/内存、保存配置、FortiGate/Palo Alto 巡检）
- 可新建/编辑/复制/删除，支持按厂商与分类搜索
- 「导入下发」把模板直接送到下面的下发队列

### 3. 批量配置下发
- 勾选多台设备 → 填命令或选模板 → **先 dryRun 预检**（只模拟执行不落盘，检查语法与连通性）
- 危险命令（默认含 `reload`、`erase`、`write erase`、`shutdown`、`undo`、`factory-reset` 等）会**强制二次确认**，终端与下发两条路径都会拦截
- 下发结果按台展示，输出可展开回看，全过程写入审计

### 4. 会话录像回放
- 支持 0.5x ~ 8x 倍速播放、上一段/跳到末尾、跟随自动滚动
- 审计角色也可用（只读回放，不能开新会话）

---

## 六、会话与流量分析（/traffic）

| Tab | 用途 | 实操 |
|---|---|---|
| **IP/MAC 定位** | 输入一个 IP 或 MAC，反查它接在哪个交换机哪个端口 | 填 `10.252.28.101` → 给出命中 MAC 表条目数、ARP 条目数、扫描过的接入台数，以及未命中的原因提示 |
| **设备表查询** | 按设备拉 MAC 表 / ARP 表 / 会话表 | 选设备 → 切表格 → 关键词过滤 → 导出 CSV |
| **流量会话分析** | 汇聚对流量 Top、端口流量排行 | 自动出横向柱状图 + Top 表，快速定位拥塞链路 |
| **抓包诊断** | 本机抓包 / 设备侧抓包 | 见下 |

### 抓包三种模式

1. **自动**：有 Npcap 时使用 TShark，没有 Npcap 时自动切换 Windows PktMon，不要求用户单独安装
2. **本机抓包**：选网卡 + BPF 过滤条件（如 `host 10.252.28.101 and port 443`）+ 时长，抓完可在页面下载 `.pcap` / `.pcapng`，直接回溯分析
3. **设备侧抓包**：填目标设备 IP，程序按厂商生成抓包命令下发（Cisco `monitor capture` / 华为·H3C `capture-packet` / Fortinet `diagnose sniffer packet` / Palo Alto `debug dataplane packet-diag`），可复制命令手动去设备上敲

> **没装 Wireshark/Npcap 也能用**：平台启动后会后台部署 TShark；部署完成前或没有 Npcap 时，Windows PktMon 会直接接管实时抓包。若系统不提供 PktMon，再降级为设备侧抓包。

---

## 六·B、旁路持续采集与全流量回溯（/capture · /flow）

一次性抓包解决不了「事后回溯」：故障发生时没抓、事后就查不到了。这里对标 AnaTraf 的做法——**旁路持续采集 → 完整留存 → 随时回溯**。

### 1. 旁路采集任务（/capture）

| 能力 | 说明 |
|---|---|
| 两种采集源 | **旁路抓包**：本机网卡镜像，自动用 TShark/Npcap 或 PktMon 滚动抓；**设备侧采集**：SSH 周期拉交换机 MAC/ARP 表 |
| 滚动轮转 | 按时长（`duration`）与文件大小（`filesize`）双条件自动切文件，不会撑爆磁盘 |
| 周期执行 | 服务每 5 秒巡检一次，到点自动跑；任务可单独启停 |
| 自动留存 | 按 `retainHours` 定时清理过期 pcap 与会话记录（保留策略随时可改） |
| 过滤 | BPF 语法，如 `port 80 or port 443 or host 10.252.28.99` |

新建任务填：名称、类型、网卡、BPF 过滤、单次时长、轮转间隔、单文件大小、保留时长。点「▶」可立即手动执行一次。

### 2. 全流量回溯（/flow）

采集到的 pcap 由内置解析器（**不依赖 tshark**）直接读二进制，做四层到七层的会话还原，结果入库，可跨时间检索：

| Tab | 用途 |
|---|---|
| **协议总览** | 累计会话数、协议种类、累计流量、覆盖时段；协议构成表按会话数与流量排序，Top 汇聚对可直接点 IP 下钻 |
| **会话检索** | 按 IP/协议/时间范围筛选，分页浏览；点任意一行看五元组、载荷特征、关联 pcap |
| **协议字典** | 内置 61 类协议与特征端口（含 Modbus TCP / S7comm / OPC UA / MQTT 等工控协议） |
| **pcap 解析** | 填一个 pcap 文件名即可解析预览，勾选「入库」后进入会话库长期留存 |

**协议识别（DPI）**为「载荷特征 + 端口特征」双重判定，载荷优先：

| 协议 | 识别依据 |
|---|---|
| HTTP | 请求行 / 响应头正则，抽取方法、路径、Host、User-Agent |
| HTTPS / TLS | ClientHello/ServerHello 特征，解析 SNI、TLS 版本 |
| DNS | 查询头特征，抽取查询域名与类型 |
| SSH / Telnet | 版本横幅 / 转义序列 |
| Modbus TCP / S7comm / OPC UA / MQTT | MBAP 头、协议 ID、固定字节位等特征 |
| 其余 | 落到 61 类特征端口表兜底（如 3306→mysql、502→modbus-tcp） |

> 会话库字段：`id / 开始时间 / 五元组 / 四层与七层协议 / 报文数 / 字节数 / 时长 / 载荷特征 / 标签 / 来源任务与文件`。

---

## 七、内网测速（/speed）

| Tab | 用途 | 说明 |
|---|---|---|
| **测速服务端** | 把本机变成测速目标 | 页面会列出局域网 IP，复制给同事，他执行 `iperf3 -c <该IP> -t 10` 或浏览器打开 `http://<该IP>:5202` 即可测 |
| **吞吐 / iperf3** | 主动测两台机器之间带宽 | 目标 IP + 端口 + 方向（上传/下载）+ 时长 + 并发。装了 iperf3 优先用，没装自动使用内置 TCP 吞吐引擎（实测回环 4.8~5.5 Gbps，零依赖） |
| **浏览器 HTTP** | 纯浏览器下载/上传测速 | 预设 50/100/200/500MB，用 Streams 统计；上传走 XHR `progress`，带实时速率曲线。测的是"浏览器到本服务"这条链路 |
| **延迟丢包探测** | ping / TCP 延迟与丢包 | 支持 `IP` 或 `IP:端口`（TCP 握手延迟）。出平均延迟、丢包率、抖动、最差值 + 明细表与质量评分 |
| **测速历史** | 所有测速记录 | 按类型着色，可展开看完整参数与结果 |

**设备间链路测速**：让 A 机当服务端、B 机当客户端，两边都打开本工具页面，用「吞吐」页互相指定对方 IP 即可，不必装 iperf3。

---

## 八、告警管理与通知推送（/alarms）

- KPI 卡：灾难/严重/一般/警告/待确认数量，可按关键词、级别、状态、设备筛选，20 秒自动刷新
- 操作：确认（写清确认人）、关闭、重开、详情弹窗（含事件 ID、来源、处置建议）
- 手动创建告警，用于补录 Zabbix 之外的业务告警
- **通知推送**：企微 / 钉钉 / 通用 Webhook / SMTP 邮件 四通道，可分别开关与**单独测试**
  - 企微：群机器人 Webhook URL 即可，无需加签
  - 钉钉：Webhook URL + 加签 Secret（机器人安全设置选"加签"时填）
  - SMTP：主机/端口（465 或 587）/账号/密码/发件人/收件人
  - 全局：最小触发级别（默认 high）、同事件冷却时间（默认 300 秒，防骚扰）

> 告警的「AI 处置」按钮会把告警上下文交给 AI 助手，给出排查建议命令。

---

## 八·B、网络扫描（/scan）

在控制台**本机**直接发包扫描目标网段，不依赖任何云端服务，也不需要 nmap（装了会在 `auto` 模式下自动用上）。左侧「安全扫描」→「网络扫描」进入，五个 Tab：

| Tab | 用途 |
|---|---|
| **扫描任务** | 保存的扫描计划，可手动执行、可设周期自动跑；支持新建/编辑/启停/删除/导出 |
| **发现主机** | 存活主机清单：IP、主机名、开放端口数、风险等级 |
| **开放端口** | 逐条列出端口、服务、产品、banner、风险等级，可按 IP/端口/服务/风险过滤 |
| **风险清单** | 只列高危（high / critical），点右侧按钮可跳转处置 |
| **扫描报告** | 单轮结果的完整视图：主机分布、风险分布（点柱可下钻到端口表）、耗时统计 |

**怎么填参数**

- **扫描目标**：`10.252.28.0/24`（CIDR）、`10.0.0.1-50`（区间，也支持 `10.0.0.1-10.0.0.50`）、单个 IP、`localhost` 这类主机名，逗号/分号/空格混写均可，重复地址自动去重。**单次最多 4096 个地址**（`MAX_HOSTS`），误填 `/8` 会在展开阶段直接拦下并提示，不会把服务拖死
- **发现方式**：`tcp`（扫常用端口判断能否连上，最快，零依赖，大网段首选）/ `icmp`（真实 ping，准但慢，一个地址一次探测）/ `mixed`（先 TCP 摸存活再补 ping 拿时延）/ `auto`（有 nmap 走 `nmap -sn`，没有自动退回 tcp）
- **端口**：直接写 `22,80,443` 或 `1000-2000`，也能填预设名（常用端口 / Web 服务 / 数据库 / Windows / 工控·IoT / 网络管理）
- 并发与超时可调；默认并发 60、单连接超时 1200ms。扫描结束会做一次**主机名反查**（主机数 ≤ 64 时才做，避免 DNS 拖慢整轮）
- **自定义参数**：可单独指定 TCP 存活发现端口、排除 IP / 区间 / CIDR、失败重试 0～3 次、开关 Banner 指纹与反向 DNS，并记录工单号或变更窗口备注；平台只接收结构化参数，不开放原始命令行入口
- **快速扫描回传**：扫描完成后不再只弹一个计数，而是直接显示可用率、存活/离线、开放端口、高危主机、平均时延、服务分布、主机明细和处置建议，并可继续进入完整报告下钻

**结果怎么落地（四项打通）**

1. **入库成资产台账** — 发现的主机自动写入设备补充信息，带厂商线索（按开放端口特征猜 Siemens / Modbus / Cisco / 网络管理设备 / Windows 等）与归属区域，随后出现在 `/devices` 与 `/topology`
2. **并入告警与风险** — 命中 high / critical 的主机自动生成告警（critical 映射为「灾难」，high 为「严重」），来源标记 `scan`，同一台主机只报一条，不会被端口数刷屏
3. **单独出扫描报告页** — `/scan` 五个 Tab + 扫描历史 + 统计，另支持 CSV 导出（**带 BOM**，Excel 双击直接打开不乱码）
4. **定时自动扫描** — 任务里设好周期并启用，`scanner` 随服务启动后台巡检到点执行；结果按 `retainHours`（默认 72 小时）保留，超期自动清理

**风险判定**：内置 22 条规则，按「banner 特征 > 端口表 > 未识别兜底」三级判定。特别地，**没抓到 banner 时服务名是 `unknown`，此时必须仍能按端口兜底**——否则 445 / 3389 这类高危端口会因为"没识别出服务"被错判成无风险。命中工控端口（502 Modbus / 102 S7comm / 44818 EtherNet-IP）、Redis / MongoDB / ES 未授权、RDB / SMB / RDP / Telnet / FTP 明文等会直接判到 high 甚至 critical，并给出处置建议。

**权限**：admin / ops 可发起与管理扫描（`scan`），审计角色只能**读**结果不能发起。扫描是主动向网段发包的行为，需单独授权。

---

## 八·C、网络诊断工具箱（/diag）

扫描回答的是「网段里有什么」，诊断回答的是「网络哪里不对」。左侧「安全扫描」→「诊断工具箱」进入，六种检测共用一套**目标范围 → 执行 → 问题清单 → 告警**的流程，六个 Tab：

| Tab | 用途 |
|---|---|
| **诊断工作台** | 选「本机网段」或「指定网段」→ 预览会扫哪些地址 → 点工具卡片开始诊断；下方展示最近一次的健康评分与问题摘要 |
| **问题清单** | 全量问题记录，可按工具 / 等级 / 目标过滤，支持按单次结果导出 CSV |
| **诊断主机** | 诊断过程中发现的主机（摄像头扫描的 IPC、IP 冲突检测的双 MAC 等） |
| **审计日志** | Syslog 接收开关与接收状态、日志等级/规则分布、明细表、按工具清空 |
| **诊断任务** | 把常用检查固化成定时巡检，支持启停与手动执行 |
| **历史记录** | 每轮诊断的评分、等级、问题数、耗时 |

**六种检测器与判据**

| 工具 | 查什么 | 关键判据 |
|---|---|---|
| **摄像头扫描** | 网段里的 IPC | 15 个常见端口指纹识别厂商/型号；`DESCRIBE` 返回 200 且带 `m=video` 即**未鉴权可拉流**，401 才算需要账号 |
| **IP 冲突检测** | 谁在抢 IP | 多轮 ARP 采样 + 旁路嗅探交叉取证，同一 IP 出现两个 MAC 即判冲突 |
| **环路检测** | 二层环路 / 广播风暴 | 抓包找**同一 IP-ID、不同 TTL** 的重复帧：同一份报文从两条路径回来，是环路的教科书特征 |
| **日志审计** | 谁在爆破、谁改了配置 | 内置 12 条规则（登录爆破、未授权访问、配置变更、日志被清除…）+ Windows 事件日志（`wevtutil` 读 Security/System），按等级阈值聚合避免刷屏 |
| **外网测速** | 出口带宽与质量 | 多线程下行 + 定长上行，与网关延迟基线对比，命中「延迟偏高 / 丢包 / 抖动」分别出结论 |
| **DHCP 检测** | 私接 DHCP | 主动发 OFFER 探测 + 被动嗅探 + 本机租约核对，发现 Rogue DHCP 与异常下发参数 |

**两种目标模式**

- **本机所在网段**：自动从活动网卡推导（需要网卡带 `netmask`；只有回环地址时会明确提示改用指定网段）。截断到单次上限时会**保证本机地址一定在列表里**——扫不到自己，结果就没有意义
- **指定网段**：`10.252.28.0/24` 或 `192.168.1.1-50`，复用扫描器的目标展开逻辑，遵守同样的单次上限

**结果口径**：每个检测器只产出 `findings`，由统一入口打分（`critical -40 / high -20 / medium -8 / low -3`，不低于 0）并按最高等级定级，同步入库、联动告警中心（同一 `标题|目标` 只报一条，上限 20 条，不会刷屏）。前端因此只需一套渲染逻辑。

**Syslog 接收**：UDP 监听 514 既需要管理员权限又常与系统 syslog 冲突，配置里默认给的是 **5140**；接不上时界面会直接显示原因，而不是静默失败。设备侧把 `log-server` 指向控制台 IP + 对应端口即可上报。

**权限**：诊断同样要 `scan` 权限（会主动发包），审计角色只读；Syslog 开关是`admin` 专属。

---

## 九、AI 智能助手

系统管理 → AI 助手，支持两种来源（**先留接口，随时可配**）：

| provider | 填什么 | 示例 |
|---|---|---|
| `openai`（OpenAI 兼容） | baseUrl / apiKey / model | `https://api.deepseek.com/v1` + `sk-...` + `deepseek-chat` |
| `ollama`（本地离线） | baseUrl | `http://127.0.0.1:11434/v1`，model 填 `qwen2.5:7b` |

- temperature / maxTokens / 系统提示词均可调，默认系统提示词已针对多厂商命令行优化
- 未配置任何 Key 时，AI 助手自动降级为**本地规则引擎**（内置端口不通、CPU 高、环路风暴、告警处置、带宽慢、配置命令、Zabbix 对接 7 类场景的判断逻辑），照样能用，只是不联网；打开设备上下文后，回答会带上该设备的实时状态与告警
- 提问历史保存在 `data/db.json`，对同一台设备问 AI 会自动带上设备上下文

---

## 十、设备资产与网络拓扑

登录后默认进入 **/alarms 告警中心**，导航按「监控与资产 → 操作与排障 → 流量可观测 → 网络检测 → 平台管理」组织，优先支持值班人员从问题发现进入设备定位与处置流程。

**/devices 设备管理**：设备列表（厂商/型号/IP/区域/角色/在线/健康度/CPU/内存/温度/运行时长），支持关键词搜索、按角色筛选、端口速览、导出 CSV、点进详情。

**/device/:host 设备详情**：基本信息 + 端口矩阵（一眼看出哪个口 down、谁的流量高）+ 实时曲线 + 端口逐个展开看收发包与错包。

**/topology 网络拓扑**：按 防火墙 → 核心 → 汇聚 → 接入 四层自动布局，节点实时挂 CPU/内存/温度，可拖动、可缩放、点节点看详情、点链路看明细，支持手动画线保存自己的拓扑。

**/cleanup 数据清理中心（管理员）**：本地资产采用可恢复的软删除；Zabbix 资产可仅在平台隐藏，或解除同步后保留为本地快照，均不会删除 Zabbix 上游主机。扫描、诊断、Syslog、流量会话、测速、抓包文件和终端录像可按保留天数预览并批量清理，清理动作会写入不可随业务数据清理的审计日志。

---

## 十一、自检与排障

```bash
npm run check      # 后端模块自检 + 前端模板自检（不需要服务）
npm run smoke      # 后端模块自检（存储/认证/数据源/终端/网络工具/数据层）
npm run tpl        # 前端模板编译自检（用 Vue 编译器跑一遍 template）
npm run e2e        # 端到端接口自检（需服务已启动）
npm run pcap       # 抓包链路自检：造 pcap → DPI 解析 → 入库 → 接口查询
npm run scan       # 网络扫描自检：目标展开 → 风险判定 → 真实扫描 → 入库 → 接口（需服务已启动）
npm run diag       # 诊断工具箱自检：帧解码 → DHCP/Syslog 解析 → 规则聚合 → 双模式目标展开（引擎层，不需服务）
npm run migrate -- --check    # PG 建表体检（不写入）

node tools/e2e.js http://127.0.0.1:8787                  # 指定地址
node tools/migrate.js --check --url postgres://...       # 指定连接串体检
```

连接失败时会给出可执行的原因提示（`ECONNREFUSED` / `ENOTFOUND` / `ETIMEDOUT` 对应什么、怎么处理），不会只抛一个 `AggregateError`。

Windows 双击 `check.bat` 会依次跑完三段：后端模块自检 → 前端模板编译自检 → 端到端接口自检。它会先探测 8787 端口，没起服务就自动拉起并等待就绪，任一段失败会停在出错处不继续。

`e2e.js` 会模拟真实前端调用，覆盖认证 / 设备 / 告警 / 终端下发 / 会话流量 / 旁路采集任务 / 全流量回溯 / 网络扫描 / **诊断工具箱** / 测速 / 系统管理 / AI 拓扑 / 权限校验；断言数量会随工具扩展，以脚本最后的通过/失败统计为准。

`netdiag-smoke.js` 是诊断引擎的离线自检（不碰数据库、不需要服务）：手工拼 ARP / IPv4-UDP / DHCP Offer 等字节验证帧级解码器，验证 Syslog 的 RFC3164 / RFC5424 解析、12 条审计规则的命中与阈值聚合、双模式目标展开（含「截断时保住本机地址」这条约束）。

`pcap-smoke.js` 会现场拼一个含 HTTP / HTTPS(SNI) / DNS / SSH / Modbus / MySQL 会话的 pcap，走完整链路验证 16 项断言（协议识别、载荷抽取、入库、检索、统计、详情）。

`scan-smoke.js` 分两段共 70 项断言：A 段在引擎层验目标展开（CIDR/区间/去重/超上限拦截）、端口解析、banner 服务识别与 22 条风险规则；B 段走 HTTP 验任务 CRUD、真实扫描入库、主机/端口/统计查询、CSV 导出与三角色权限。A 段为了不依赖外部环境，会临时在本机起一个「连上就吐 SSH banner」的监听口，扫它必然拿到 open + ssh，扫没人监听的端口必然 closed。

### 常见问题

| 现象 | 原因与处理 |
|---|---|
| 启动报 `Missing parameter name` | Express 5 不再支持 `app.get('*')`，代码已用 `/*splat`，确认版本是 express 5 |
| 页面白屏 / 控制台报 `Vue is not defined` | `node_modules/vue` 缺失，跑一次 `npm install` |
| 终端连不上真机 | 凭据库点「测试」看具体报错；常见为 22 端口未通、账号仅允许反向 Telnet、VPN 未连 |
| 抓包提示没有权限 | PktMon 需要管理员权限；请以管理员运行平台，或切到「设备侧抓包」模式 |
| 环路/DHCP 检测暂时没有网卡数据 | 首次启动时 TShark 可能仍在后台部署；到「系统管理 → 运行状态」查看进度，完成后重试 |
| Syslog 开了却收不到日志 | 报 `EADDRINUSE / EACCES` 多为 514 被系统占用或非管理员；改用 5140 等高位端口，并让设备指向该端口 |
| 测速跑不出速度 | 确认测的是同一网段的两台机器；跨 VPN 会受封包开销影响，实测回环 4.8~5.5 Gbps 属正常 |
| 数据不刷新 | 数据源有 25 秒缓存，等 30 秒或去「系统管理 → 数据源」重新保存一次 |
| 改密码后掉线 | 无状态 Token 在改密时失效属预期，重新登录即可 |

---

## 十二、目录结构

```
netops-console/
├─ server/
│  ├─ index.js          # 服务入口、静态映射、WebSocket、启动横幅
│  ├─ api.js            # 全部业务 REST 路由（55+ 接口）
│  ├─ auth.js           # 登录、三角色 RBAC、无状态 Token、审计中间件
│  ├─ store.js          # 存储层：db.json、AES 凭据、scrypt 密码、录像、审计
│  ├─ datasource.js     # 数据适配层：DemoProvider / ZabbixProvider
│  ├─ term.js           # Web 终端引擎、CLI 模拟器、危险命令拦截、批量下发
│  ├─ netutil.js        # ping/TCP/SSH/吞吐服务/iperf/tshark/MAC/ARP 解析
│  ├─ notify.js         # 企微/钉钉/Webhook/SMTP 四通道推送
│  ├─ dpi.js            # 协议识别（端口特征 + 载荷签名）、pcap 二进制解析
│  ├─ capture.js        # 旁路持续采集引擎（tshark/dumpcap、滚动轮转、留存清理）
│  ├─ scanner.js        # 网络扫描引擎：目标展开 / 存活发现 / 端口+banner / 风险判定 / 调度
│  └─ netdiag.js        # 网络诊断引擎：摄像头/IP冲突/环路/日志审计/测速/DHCP 六个检测器 + Syslog 接收
├─ db/
│  ├─ schema.js         # 存储契约：23 张表的 PG DDL、列名解析、camel↔snake 映射
│  ├─ repo-json.js      # JSON 文件实现（零依赖，开箱可用）
│  └─ repo-pg.js        # PostgreSQL 实现（连接池、JSONB、批量写入）
├─ public/
│  ├─ index.html
│  ├─ css/app.css       # 运维业务页面设计系统
│  └─ js/
│     ├─ core.js        # 请求封装、路由、格式化、通用组件（NcChart/NcTable…）
│     ├─ app.js         # 布局、侧边栏、登录、全局状态
│     └─ pages/         # devices / terminal / traffic / speed / alarms
│                       # / topology / system / flow / capture / scan / diag
├─ tools/
│  ├─ smoke.js          # 后端模块自检
│  ├─ e2e.js            # 端到端接口自检（98 项）
│  ├─ tpl-check.js      # 前端模板编译自检（@vue/compiler-dom）
│  ├─ pcap-smoke.js     # 抓包链路自检（造包 → 解析 → 入库）
│  ├─ scan-smoke.js     # 网络扫描自检（引擎 70 项：展开/端口/服务/风险/入库/接口）
│  ├─ netdiag-smoke.js  # 诊断引擎自检（帧解码/DHCP/Syslog/规则聚合/双模式目标展开）
│  └─ migrate.js        # PostgreSQL 建表 + JSON→PG 数据迁移
├─ data/                # 运行时数据（备份打包这个目录即可）
│  ├─ db.json           # 用户/凭据/设置/模板/告警/拓扑
│  ├─ .masterkey        # 凭据加密主密钥（务必与 db.json 一起备份）
│  ├─ recordings/       # 终端会话录像 ndjson
│  ├─ captures/         # 抓包 pcap 与元数据
│  ├─ speed/            # 测速结果
│  └─ logs/             # 审计日志 audit-YYYY-MM-DD.ndjson
├─ start.bat            # Windows 一键启动
├─ check.bat            # 双击跑端到端自检
└─ package.json
```

---

## 十三、安全建议（上线前必做）

1. 修改三个默认账号的密码，删除不再使用的账号
2. 凭据库只给需要下发的运维配 SSH 账号，遵循最小权限
3. 通过反向代理加 HTTPS 与基础认证，不要在明文 HTTP 下长期使用
4. 把 `data/logs` 纳入定期归档，审计日志为 append-only，不要手动删
5. 办公电脑关机/离岗时关闭服务窗口
