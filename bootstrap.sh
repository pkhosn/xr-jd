#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[error] 请使用 root 运行：sudo bash bootstrap.sh"
  exit 1
fi

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

install_with_apt() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 curl ca-certificates
}

install_with_dnf() {
  dnf makecache -y
  dnf install -y python3 curl ca-certificates
}

install_with_yum() {
  yum makecache -y
  yum install -y python3 curl ca-certificates
}

install_with_apk() {
  apk update
  apk add --no-cache python3 curl ca-certificates
}

install_with_pacman() {
  pacman -Sy --noconfirm python curl ca-certificates
}

install_with_zypper() {
  zypper --non-interactive refresh
  zypper --non-interactive install python3 curl ca-certificates
}

echo "[info] 检测系统并安装依赖..."
if command_exists apt-get; then
  install_with_apt
elif command_exists dnf; then
  install_with_dnf
elif command_exists yum; then
  install_with_yum
elif command_exists apk; then
  install_with_apk
elif command_exists pacman; then
  install_with_pacman
elif command_exists zypper; then
  install_with_zypper
else
  echo "[error] 未识别的包管理器，请手动安装 python3/curl/ca-certificates"
  exit 2
fi

echo "[ok] 依赖安装完成"
python3 --version || true
curl --version | head -n 1 || true
