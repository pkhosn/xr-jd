#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo bash "$0" "$@"
  fi
  echo "[error] 请使用 root 运行，或安装 sudo 后重试。"
  exit 1
fi

YES=0
if [[ "${1:-}" == "--yes" ]]; then
  YES=1
fi

if [[ "${YES}" -ne 1 ]]; then
  echo "[warn] 将执行 XrayR 完全卸载："
  echo "       - 停止并禁用 XrayR 服务"
  echo "       - 删除 /etc/systemd/system/XrayR.service"
  echo "       - 删除 /usr/local/XrayR"
  echo "       - 删除 /etc/XrayR（含备份）"
  read -r -p "确认继续？输入 YES: " ans
  if [[ "${ans}" != "YES" ]]; then
    echo "[info] 已取消。"
    exit 0
  fi
fi

echo "[step] stop/disable service"
systemctl stop XrayR 2>/dev/null || true
systemctl disable XrayR 2>/dev/null || true

echo "[step] remove service unit"
rm -f /etc/systemd/system/XrayR.service
rm -f /lib/systemd/system/XrayR.service
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

echo "[step] remove XrayR files"
rm -rf /usr/local/XrayR
rm -rf /etc/XrayR

echo "[step] cleanup done"
echo "[ok] XrayR 已完全卸载。"
