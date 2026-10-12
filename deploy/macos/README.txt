网络运维与故障排除工具平台 v1.1.1 - macOS

此包同时包含 Apple Silicon（M1/M2/M3/M4/M5）与 Intel Mac 版本。

1. 双击 start.command，脚本会自动选择匹配的处理器版本。
2. 浏览器访问 http://127.0.0.1:8787。
3. 如需原生 Nmap/TShark/MTR/iperf3/Net-SNMP，双击 install-tools.command；
   未安装时仍可使用平台内置回退能力。

两个可执行文件均已加入 ad-hoc 签名，可满足 macOS 对本地 Mach-O 的完整性要求，
但没有使用 Apple Developer ID 做公证。首次启动如被 Gatekeeper 阻止，请到
“系统设置 → 隐私与安全性”选择“仍要打开”。

默认管理员：admin / admin@123（首次登录后请立即修改密码）
数据保存在本目录 data 文件夹。
