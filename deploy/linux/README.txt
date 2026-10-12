网络运维与故障排除工具平台 v1.1.0 - Linux x64

快速安装：
  chmod +x install.sh
  sudo ./install.sh

安装脚本会自动安装 Nmap、TShark、MTR、iperf3、Net-SNMP 等网络工具，
注册并启动 systemd 服务。浏览器访问 http://服务器IP:8787。

默认管理员：admin / admin@123（首次登录后请立即修改密码）
数据目录：/opt/netops-console/data
查看日志：journalctl -u netops-console -f
