# xr-jd

`xr-jd` 是一个用于自动化部署 XRayR 上游映射的脚本工具，支持：
- 交互式向导（一步步输入）
- 命令行参数模式（适合批量/自动化）
- 自动安装 XRayR（调用一键脚本）
- 自动生成并应用 3 个核心配置文件
- 自动备份与回滚
- 傻瓜式一键入口（`quick_start.sh`）

---

## 1. 工具做了什么
脚本会完成以下事情：

1. 检测 XRayR 是否安装（未安装则执行一键脚本）
2. 拉取上游订阅并解析（支持 `vmess://` 与 Mihomo/Clash YAML 中的 `type: vmess`）
3. 根据你输入的端口和 NodeID 生成：
   - `/etc/XrayR/config.yml`
   - `/etc/XrayR/custom_outbound.json`
   - `/etc/XrayR/route.json`
4. （`--apply` 模式）自动备份旧配置并重启 XRayR

---

## 2. 新服务器首次准备（先做这个）

很多新 VPS 默认没有 `python3`，请先执行：

```bash
sudo bash bootstrap.sh
```

该脚本会自动安装：
- `python3`
- `curl`
- `ca-certificates`

然后检查版本：

```bash
python3 --version
curl --version
```

---

## 3. 快速开始（最推荐）

### 3.0 傻瓜式一键（推荐）

```bash
bash quick_start.sh
```

说明：
- 自动检查并安装依赖（缺什么装什么）
- 自动进入交互式向导
- 默认按 `--apply` 执行，直接写入 `/etc/XrayR` 并重启服务

如果你要命令行自动化，也可以直接透传参数：

```bash
bash quick_start.sh --non-interactive --api-host https://panel.example.com --api-key YOUR_SERVER_TOKEN --node-ids 5 --node-type V2ray --ports 26210 --sub-url 'https://example.com/sub?token=xxx' --apply
```

新 VPS 可直接一条命令：

```bash
git clone https://github.com/pkhosn/xr-jd.git && cd xr-jd && bash quick_start.sh
```

### 3.1 交互模式
直接运行：

```bash
python3 deploy_xrayr_wizard.py
```

然后按提示输入：
- `ApiHost`：你的 V2Board 面板地址（如 `https://panel.example.com`）
- `ApiKey`：面板 `SERVER_TOKEN`
- `NodeID`：可填 1 个或多个（如 `5` 或 `5,6` 或 `5-8`）
- `NodeType`：默认 `V2ray`
- `Local ports`：本地端口（如 `26210` 或 `26210-26215`）
- `Upstream subscription URL`：上游订阅链接
- `Mapping mode`：`auto`（自动前 N 个）或 `manual`（手动序号）

> 注意：`NodeID` 数量必须与端口数量一致。

---

## 4. 命令行模式

### 4.1 仅生成文件（不改系统）

```bash
python3 deploy_xrayr_wizard.py \
  --non-interactive \
  --api-host https://panel.example.com \
  --api-key YOUR_SERVER_TOKEN \
  --node-ids 5 \
  --node-type V2ray \
  --ports 26210 \
  --sub-url 'https://example.com/sub?token=xxx' \
  --dry-run \
  --output-dir ./generated
```

### 4.2 直接应用到系统

```bash
sudo python3 deploy_xrayr_wizard.py \
  --non-interactive \
  --api-host https://panel.example.com \
  --api-key YOUR_SERVER_TOKEN \
  --node-ids 5,6 \
  --node-type V2ray \
  --ports 26210-26211 \
  --sub-url 'https://example.com/sub?token=xxx' \
  --apply
```

---

## 5. 回滚
回滚到最近一次备份：

```bash
sudo python3 deploy_xrayr_wizard.py --rollback
```

备份目录：

```text
/etc/XrayR/backups/<timestamp>/
```

---

## 6. 参数说明

- `--api-host`：面板地址
- `--api-key`：面板密钥（敏感）
- `--node-ids`：支持单值/逗号/范围（`5`、`5,6`、`5-8`）
- `--node-type`：`V2ray` / `Shadowsocks` / `Trojan`
- `--ports`：支持单值/逗号/范围
- `--sub-url`：上游订阅链接
- `--map-mode`：`auto` 或 `manual`
- `--map-indices`：手动模式下指定上游节点序号（如 `1,3,5`）
- `--dry-run`：只生成，不应用
- `--apply`：写入 `/etc/XrayR` 并重启
- `--skip-install`：跳过安装检测
- `--rollback`：回滚最近备份
- `--non-interactive`：关闭交互，必须配齐必要参数

---

## 7. 运行后的验证

```bash
systemctl status XrayR --no-pager -l
journalctl -u XrayR -n 80 --no-pager
```

成功常见日志：
- `Added xxx new users`
- `Start node monitor periodic task`

失败常见日志：
- `panic` / `segmentation fault`
- `Failed to listen`
- `invalid memory address`

---

## 8. 注意事项

1. `--apply` 需要 root 权限。
2. 脚本会改写：
   - `/etc/XrayR/config.yml`
   - `/etc/XrayR/custom_outbound.json`
   - `/etc/XrayR/route.json`
3. 请妥善保管 `ApiKey` 和上游订阅 token，不要提交到仓库。
4. v1 当前仅解析 `vmess://`，后续可扩展 `ss://`、`trojan://`。

---

## 9. 模板文件（`/root/xrayr-parasitic/`）

仓库已包含你要求的模板目录：

```text
xrayr-parasitic/
├── config.yml
├── config.with-panel.yml
├── config.with-panel.annotated.yml
├── custom_outbound.json
├── custom_outbound.annotated.jsonc
├── route.json
└── route.annotated.jsonc
```

使用方式（手工部署）：

```bash
# 1) 先安装 XRayR 一键脚本
bash <(curl -Ls https://raw.githubusercontent.com/mieba1/XrayR/master/install.sh)

# 2) 按你的实际参数修改 3 个核心文件
vim xrayr-parasitic/config.with-panel.yml
vim xrayr-parasitic/custom_outbound.json
vim xrayr-parasitic/route.json

# 3) 覆盖到系统目录
cp xrayr-parasitic/config.with-panel.yml /etc/XrayR/config.yml
cp xrayr-parasitic/custom_outbound.json /etc/XrayR/custom_outbound.json
cp xrayr-parasitic/route.json /etc/XrayR/route.json

# 4) 重启并检查
systemctl restart XrayR
systemctl status XrayR --no-pager -l
journalctl -u XrayR -n 80 --no-pager
```

> 模板已脱敏（域名、密钥、UUID 均为占位符），请替换为你自己的真实参数。
