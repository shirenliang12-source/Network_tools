#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 sudo ./install.sh 运行"
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/netops-console"
SERVICE_USER="netops-console"

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl dnsutils iperf3 iputils-ping mtr-tiny net-tools nmap openssl snmp tcpdump traceroute tshark
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y ca-certificates curl bind-utils iperf3 iputils mtr net-tools nmap openssl net-snmp-utils tcpdump traceroute wireshark-cli
elif command -v yum >/dev/null 2>&1; then
  yum install -y ca-certificates curl bind-utils iperf3 iputils mtr net-tools nmap openssl net-snmp-utils tcpdump traceroute wireshark
else
  echo "未识别包管理器，将只安装平台二进制；网络工具可稍后由系统管理员安装。"
fi

id -u "${SERVICE_USER}" >/dev/null 2>&1 || useradd --system --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${INSTALL_DIR}" "${INSTALL_DIR}/data"
install -m 0755 "${SOURCE_DIR}/netops-console-linux-x64" "${INSTALL_DIR}/netops-console"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

if command -v setcap >/dev/null 2>&1; then
  DUMPCAP_BIN="$(command -v dumpcap || true)"
  [[ -z "${DUMPCAP_BIN}" ]] || setcap cap_net_raw,cap_net_admin+eip "${DUMPCAP_BIN}" || true
fi

install -m 0644 "${SOURCE_DIR}/netops-console.service" /etc/systemd/system/netops-console.service
systemctl daemon-reload
systemctl enable --now netops-console.service

echo "安装完成：http://本机IP:8787"
echo "状态查看：systemctl status netops-console"
