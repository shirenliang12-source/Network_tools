网络运维与故障排除工具平台 v1.1.1 - Docker

本包的镜像构建过程会直接安装 Nmap、TShark、MTR、iperf3、Net-SNMP、
tcpdump、dig、traceroute 等工具，无需进入容器单独安装。

启动：
  docker compose up -d --build

访问：http://服务器IP:8787
停止：docker compose down
日志：docker compose logs -f

默认管理员：admin / admin@123（首次登录后请立即修改密码）
数据持久化在当前目录 data 文件夹。

compose 默认使用 host 网络与 NET_ADMIN/NET_RAW 能力，以便执行真实网络探测和抓包。
该模式面向 Linux Docker 主机；Docker Desktop 可根据环境改为端口映射 8787:8787。
