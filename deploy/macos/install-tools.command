#!/bin/bash
set -e

if ! command -v brew >/dev/null 2>&1; then
  echo "未检测到 Homebrew。平台内置诊断能力仍可使用；如需原生工具，请先安装 Homebrew。"
  read -r
  exit 0
fi

brew update
brew install nmap mtr iperf3 net-snmp wireshark
echo "Nmap、TShark、MTR、iperf3、Net-SNMP 已就绪。"
read -r
