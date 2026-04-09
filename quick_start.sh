#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_with_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
    return
  fi
  if need_cmd sudo; then
    sudo "$@"
    return
  fi
  echo "[error] 当前不是 root，且系统没有 sudo。请切换 root 后重试。"
  exit 1
}

echo "[step] 1/3 检查并安装依赖（python3/curl/ca-certificates）"
if ! need_cmd python3 || ! need_cmd curl; then
  run_with_root bash "${SCRIPT_DIR}/bootstrap.sh"
else
  echo "[ok] 依赖已存在，跳过安装"
fi

echo "[step] 2/3 检查 python 版本"
python3 --version

echo "[step] 3/3 启动部署向导"
if [[ "$#" -gt 0 ]]; then
  echo "[info] 检测到参数，按参数模式执行"
  if [[ " $* " == *" --apply "* ]]; then
    run_with_root python3 "${SCRIPT_DIR}/deploy_xrayr_wizard.py" "$@"
  else
    python3 "${SCRIPT_DIR}/deploy_xrayr_wizard.py" "$@"
  fi
else
  echo "[info] 无参数：进入交互式 + 自动应用模式"
  run_with_root python3 "${SCRIPT_DIR}/deploy_xrayr_wizard.py" --apply
fi

