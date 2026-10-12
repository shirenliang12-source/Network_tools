网络运维与故障排除工具平台 v1.1.1 - Windows x64

1. 解压整个目录，不要放在 C:\Program Files 等只读目录。
2. 双击“启动平台.cmd”，首次启动按 Windows 提示允许管理员权限。
3. 浏览器访问 http://127.0.0.1:8787
4. 数据保存在同目录 data 文件夹，升级前请备份该文件夹。

默认管理员：admin / admin@123（首次登录后请立即修改密码）

Windows 版会自动检测并静默部署 Nmap、TShark 与 iperf3；MTR、Net-SNMP
能力已经内置。Npcap 受第三方许可限制，不随包分发；没有 Npcap 时平台自动使用
Windows PktMon 或设备侧抓包，不影响平台启动。
