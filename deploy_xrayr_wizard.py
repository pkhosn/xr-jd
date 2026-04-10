#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

INSTALL_SCRIPT_URL = "https://raw.githubusercontent.com/mieba1/XrayR/master/install.sh"
DEFAULT_ETC = Path("/etc/XrayR")


def run(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-lc", cmd], text=True, capture_output=True, check=check)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def mask_secret(s: str) -> str:
    if not s:
        return s
    if len(s) <= 8:
        return "*" * len(s)
    return s[:3] + "***" + s[-3:]


def is_bad_upstream_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return True
    if h in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        return True
    return False


def parse_range_list(value: str) -> List[int]:
    value = value.strip()
    if not value:
        raise ValueError("empty input")
    # 兼容中文输入法：中文逗号与全角/长横线
    value = value.replace("，", ",").replace("－", "-").replace("—", "-").replace("–", "-").replace("~", "-")
    out: List[int] = []
    for part in [x.strip() for x in value.split(",") if x.strip()]:
        if "-" in part:
            a, b = part.split("-", 1)
            start = int(a)
            end = int(b)
            if start > end:
                raise ValueError(f"invalid range: {part}")
            out.extend(range(start, end + 1))
        else:
            out.append(int(part))
    return out


def parse_node_types(value: str) -> List[str]:
    raw = value.strip()
    if not raw:
        raise ValueError("empty node types")
    raw = raw.replace("，", ",")
    out: List[str] = []
    for part in [x.strip() for x in raw.split(",") if x.strip()]:
        out.append(normalize_node_type(part))
    if not out:
        raise ValueError("empty node types")
    return out


def normalize_node_type(node_type: str) -> str:
    t = node_type.strip().lower()
    if t in ("v2ray", "vmess", "vless"):
        return "V2ray"
    if t in ("shadowsocks", "ss"):
        return "Shadowsocks"
    if t in ("trojan",):
        return "Trojan"
    return node_type


def inbound_tag_prefix(node_type: str) -> str:
    t = normalize_node_type(node_type)
    return {
        "V2ray": "V2ray",
        "Shadowsocks": "Shadowsocks",
        "Trojan": "Trojan",
    }.get(t, t)


def fetch_text(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "xr-jd-wizard/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="ignore").strip()


def maybe_b64_decode(text: str) -> str:
    compact = re.sub(r"\s+", "", text)
    pad = "=" * ((4 - len(compact) % 4) % 4)
    try:
        out = base64.b64decode(compact + pad).decode("utf-8", errors="ignore")
        return out
    except Exception:
        return text


def decode_subscription(raw: str) -> List[str]:
    if "vmess://" in raw or "ss://" in raw or "trojan://" in raw:
        text = raw
    else:
        text = maybe_b64_decode(raw)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return lines


def parse_vmess(line: str) -> Dict:
    payload = line.split("vmess://", 1)[1]
    pad = "=" * ((4 - len(payload) % 4) % 4)
    obj = json.loads(base64.b64decode(payload + pad).decode("utf-8", errors="ignore"))
    return {
        "protocol": "vmess",
        "ps": obj.get("ps", ""),
        "add": obj.get("add", ""),
        "port": int(obj.get("port", 0)),
        "id": obj.get("id", ""),
        "aid": int(obj.get("aid", 0) or 0),
        "net": obj.get("net", "tcp") or "tcp",
        "path": obj.get("path", "") or "",
        "host": obj.get("host", "") or "",
        "tls": (obj.get("tls", "") or "").lower(),
    }


def parse_vless(line: str) -> Dict:
    u = urllib.parse.urlparse(line)
    if u.scheme.lower() != "vless":
        raise ValueError("not vless link")
    qs = urllib.parse.parse_qs(u.query)

    def q(name: str, default: str = "") -> str:
        v = qs.get(name, [default])[0]
        return v or default

    uid = urllib.parse.unquote(u.username or "")
    host = u.hostname or ""
    port = int(u.port or 0)
    if not uid or not host or not port:
        raise ValueError("invalid vless link")

    return {
        "protocol": "vless",
        "ps": urllib.parse.unquote(u.fragment or ""),
        "add": host,
        "port": port,
        "id": uid,
        "net": q("type", "tcp"),
        "path": urllib.parse.unquote(q("path", "")),
        "host": urllib.parse.unquote(q("host", "")),
        "tls": q("security", "").lower(),  # tls/reality/none
        "sni": urllib.parse.unquote(q("sni", "")),
        "flow": q("flow", ""),
        "fp": q("fp", ""),
        "pbk": q("pbk", ""),
        "sid": q("sid", ""),
    }


def parse_hysteria2(line: str) -> Dict:
    u = urllib.parse.urlparse(line)
    scheme = u.scheme.lower()
    if scheme not in ("hysteria2", "hy2"):
        raise ValueError("not hysteria2 link")
    qs = urllib.parse.parse_qs(u.query)

    def q(name: str, default: str = "") -> str:
        v = qs.get(name, [default])[0]
        return v or default

    password = urllib.parse.unquote(u.username or "")
    host = u.hostname or ""
    port = int(u.port or 0)
    if not password or not host or not port:
        raise ValueError("invalid hysteria2 link")

    insecure_v = q("insecure", "0").lower()
    insecure = insecure_v in ("1", "true", "yes", "on")
    sni = urllib.parse.unquote(q("sni", ""))
    obfs = q("obfs", "")
    obfs_pwd = q("obfs-password", "")

    return {
        "protocol": "hysteria2",
        "ps": urllib.parse.unquote(u.fragment or ""),
        "add": host,
        "port": port,
        "password": password,
        "sni": sni,
        "insecure": insecure,
        "obfs": obfs,
        "obfs_password": obfs_pwd,
    }


def parse_nodes(lines: List[str]) -> Tuple[List[Dict], Dict[str, int]]:
    nodes: List[Dict] = []
    skipped = {"vmess": 0, "vless": 0, "hy2": 0, "other": 0}
    for l in lines:
        if l.startswith("vmess://"):
            try:
                nodes.append(parse_vmess(l))
            except Exception:
                skipped["vmess"] += 1
        elif l.startswith("vless://"):
            try:
                nodes.append(parse_vless(l))
            except Exception:
                skipped["vless"] += 1
        elif l.startswith("hysteria2://") or l.startswith("hy2://"):
            try:
                nodes.append(parse_hysteria2(l))
            except Exception:
                skipped["hy2"] += 1
        else:
            skipped["other"] += 1
    return nodes, skipped


def _clean_yaml_scalar(v: str) -> str:
    s = v.strip()
    if " #" in s:
        s = s.split(" #", 1)[0].strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]
    return s.strip()


def parse_mihomo_yaml_vmess(raw: str) -> List[Dict]:
    lines = raw.splitlines()
    in_proxies = False
    proxy_lines: List[str] = []
    for line in lines:
        if not in_proxies:
            if re.match(r"^\s*proxies\s*:\s*$", line):
                in_proxies = True
            continue
        if re.match(r"^[A-Za-z0-9_-]+\s*:\s*$", line):
            break
        proxy_lines.append(line)

    if not proxy_lines:
        return []

    blocks: List[str] = []
    cur: List[str] = []
    for line in proxy_lines:
        if re.match(r"^\s*-\s+name\s*:", line):
            if cur:
                blocks.append("\n".join(cur))
            cur = [line]
        elif cur:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur))

    out: List[Dict] = []
    for b in blocks:
        def g(pat: str) -> str:
            m = re.search(pat, b, flags=re.IGNORECASE | re.MULTILINE)
            return _clean_yaml_scalar(m.group(1)) if m else ""

        ptype = g(r"^\s*type\s*:\s*([^\n]+)")
        if ptype.lower() != "vmess":
            continue

        add = g(r"^\s*server\s*:\s*([^\n]+)")
        port_s = g(r"^\s*port\s*:\s*([^\n]+)")
        uid = g(r"^\s*uuid\s*:\s*([^\n]+)")
        if not add or not port_s or not uid:
            continue

        try:
            port = int(port_s)
        except Exception:
            continue

        ps = g(r"^\s*name\s*:\s*([^\n]+)")
        net = g(r"^\s*network\s*:\s*([^\n]+)") or "tcp"
        tls_v = g(r"^\s*tls\s*:\s*([^\n]+)").lower()
        tls = "tls" if tls_v in ("true", "1", "tls", "yes", "on") else ""
        path = g(r"^\s*path\s*:\s*([^\n]+)") or "/"
        host = g(r"^\s*Host\s*:\s*([^\n]+)") or g(r"^\s*host\s*:\s*([^\n]+)")
        aid_s = g(r"^\s*alterId\s*:\s*([^\n]+)") or g(r"^\s*alter-id\s*:\s*([^\n]+)") or "0"
        try:
            aid = int(aid_s)
        except Exception:
            aid = 0

        out.append(
            {
                "protocol": "vmess",
                "ps": ps,
                "add": add,
                "port": port,
                "id": uid,
                "aid": aid,
                "net": net,
                "path": path,
                "host": host,
                "tls": tls,
            }
        )

    return out


def parse_mihomo_yaml_ss(raw: str) -> Tuple[List[Dict], int]:
    lines = raw.splitlines()
    in_proxies = False
    proxy_lines: List[str] = []
    for line in lines:
        if not in_proxies:
            if re.match(r"^\s*proxies\s*:\s*$", line):
                in_proxies = True
            continue
        if re.match(r"^[A-Za-z0-9_-]+\s*:\s*$", line):
            break
        proxy_lines.append(line)

    if not proxy_lines:
        return [], 0

    blocks: List[str] = []
    cur: List[str] = []
    for line in proxy_lines:
        if re.match(r"^\s*-\s+name\s*:", line):
            if cur:
                blocks.append("\n".join(cur))
            cur = [line]
        elif cur:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur))

    out: List[Dict] = []
    skipped_invalid = 0
    for b in blocks:
        def g(pat: str) -> str:
            m = re.search(pat, b, flags=re.IGNORECASE | re.MULTILINE)
            return _clean_yaml_scalar(m.group(1)) if m else ""

        ptype = g(r"^\s*type\s*:\s*([^\n]+)").lower()
        if ptype != "ss":
            continue

        add = g(r"^\s*server\s*:\s*([^\n]+)")
        port_s = g(r"^\s*port\s*:\s*([^\n]+)")
        method = g(r"^\s*cipher\s*:\s*([^\n]+)")
        password = g(r"^\s*password\s*:\s*([^\n]+)")
        if not add or not port_s or not method or not password:
            skipped_invalid += 1
            continue

        try:
            port = int(port_s)
        except Exception:
            skipped_invalid += 1
            continue

        # Clash/Mihomo 常见 obfs 写法:
        # plugin: obfs
        # plugin-opts:
        #   mode: tls
        #   host: example.com
        plugin = g(r"^\s*plugin\s*:\s*([^\n]+)").lower()
        obfs_mode = g(r"^\s*mode\s*:\s*([^\n]+)").lower()
        obfs_host = g(r"^\s*host\s*:\s*([^\n]+)")

        out.append(
            {
                "protocol": "ss",
                "ps": g(r"^\s*name\s*:\s*([^\n]+)"),
                "add": add,
                "port": port,
                "method": method,
                "password": password,
                "plugin": plugin,
                "obfs_mode": obfs_mode,
                "obfs_host": obfs_host,
            }
        )

    return out, skipped_invalid


def pick_nodes(nodes: List[Dict], count: int, manual_indices: Optional[List[int]]) -> List[Dict]:
    if manual_indices:
        picked = []
        for idx in manual_indices:
            i = idx - 1
            if i < 0 or i >= len(nodes):
                raise ValueError(f"manual index out of range: {idx}")
            picked.append(nodes[i])
        if len(picked) != count:
            raise ValueError("manual indices count must equal ports count")
        return picked
    if len(nodes) < count:
        raise ValueError(f"not enough parsed vmess nodes: need {count}, got {len(nodes)}")
    return nodes[:count]


def build_outbound(ports: List[int], upstream: List[Dict]) -> List[Dict]:
    out = []
    for port, n in zip(ports, upstream):
        if n.get("protocol") == "ss":
            server = {
                "address": n["add"],
                "port": n["port"],
                "method": n["method"],
                "password": n["password"],
            }
            # 尝试兼容 simple-obfs。若不支持，后续可在日志中看到连接失败。
            if n.get("plugin") == "obfs":
                mode = n.get("obfs_mode") or "tls"
                host = n.get("obfs_host") or ""
                opts = f"obfs={mode}"
                if host:
                    opts += f";obfs-host={host}"
                server["plugin"] = "obfs-local"
                server["pluginOpts"] = opts

            item = {
                "tag": f"up_{port}",
                "protocol": "shadowsocks",
                "settings": {"servers": [server]},
            }
        else:
            if n.get("protocol") == "hysteria2":
                item = {
                    "tag": f"up_{port}",
                    "protocol": "hysteria2",
                    "settings": {
                        "server": f"{n['add']}:{n['port']}",
                        "password": n["password"],
                    },
                    "streamSettings": {
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": n.get("sni") or n["add"],
                            "insecure": bool(n.get("insecure", False)),
                        },
                    },
                }
                if n.get("obfs") and n.get("obfs_password"):
                    item["settings"]["obfs"] = {
                        "type": n["obfs"],
                        "password": n["obfs_password"],
                    }
            elif n.get("protocol") == "vless":
                security = n.get("tls", "none")
                if security in ("", "none"):
                    security = "none"
                user = {"id": n["id"], "encryption": "none"}
                if n.get("flow"):
                    user["flow"] = n["flow"]
                item = {
                    "tag": f"up_{port}",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": n["add"],
                                "port": n["port"],
                                "users": [user],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": n.get("net", "tcp"),
                        "security": security,
                    },
                }
                if n.get("net") == "ws":
                    ws = {"path": n.get("path") or "/"}
                    if n.get("host"):
                        ws["headers"] = {"Host": n["host"]}
                    item["streamSettings"]["wsSettings"] = ws
                if security == "tls":
                    item["streamSettings"]["tlsSettings"] = {
                        "serverName": n.get("sni") or n.get("host") or n["add"]
                    }
                if security == "reality":
                    rs = {"serverName": n.get("sni") or n["add"]}
                    if n.get("fp"):
                        rs["fingerprint"] = n["fp"]
                    if n.get("pbk"):
                        rs["publicKey"] = n["pbk"]
                    if n.get("sid"):
                        rs["shortId"] = n["sid"]
                    item["streamSettings"]["realitySettings"] = rs
            else:
                security = "tls" if n["tls"] == "tls" else "none"
                item = {
                    "tag": f"up_{port}",
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": n["add"],
                                "port": n["port"],
                                "users": [
                                    {
                                        "id": n["id"],
                                        "alterId": n["aid"],
                                        "security": "auto",
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": n["net"],
                        "security": security,
                    },
                }
                if n["net"] == "ws":
                    ws = {"path": n["path"] or "/"}
                    if n["host"]:
                        ws["headers"] = {"Host": n["host"]}
                    item["streamSettings"]["wsSettings"] = ws
        out.append(item)

    out.extend(
        [
            {"tag": "IPv4_out", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ]
    )
    return out


def build_route(ports: List[int], node_types: List[str]) -> Dict:
    rules = [
        {"type": "field", "outboundTag": "block", "ip": ["geoip:private"]},
        {"type": "field", "outboundTag": "block", "protocol": ["bittorrent"]},
    ]
    for p, t in zip(ports, node_types):
        prefix = inbound_tag_prefix(t)
        rules.append(
            {
                "type": "field",
                "inboundTag": [f"{prefix}_0.0.0.0_{p}"],
                "outboundTag": f"up_{p}",
            }
        )
    rules.append({"type": "field", "outboundTag": "IPv4_out", "network": "tcp,udp"})
    return {"domainStrategy": "IPOnDemand", "rules": rules}


def build_config_yaml(api_host: str, api_key: str, node_ids: List[int], node_types: List[str]) -> str:
    blocks = []
    for nid, ntype in zip(node_ids, node_types):
        blocks.append(
            textwrap.dedent(
                f"""
                  - PanelType: \"V2board\"
                    ApiConfig:
                      ApiHost: \"{api_host}\"
                      ApiKey: \"{api_key}\"
                      NodeID: {nid}
                      NodeType: {ntype}
                      Timeout: 30
                      EnableVless: false
                      EnableXTLS: false
                      SpeedLimit: 0
                      DeviceLimit: 0
                    ControllerConfig:
                      ListenIP: 0.0.0.0
                      SendIP: 0.0.0.0
                      UpdatePeriodic: 60
                      EnableDNS: false
                      DNSType: AsIs
                      EnableProxyProtocol: false
                """
            ).rstrip()
        )

    head = textwrap.dedent(
        """
        Log:
          Level: warning
          AccessPath:
          ErrorPath:
        DnsConfigPath:
        InboundConfigPath:
        RouteConfigPath: /etc/XrayR/route.json
        OutboundConfigPath: /etc/XrayR/custom_outbound.json
        ConnetionConfig:
          Handshake: 4
          ConnIdle: 30
          UplinkOnly: 2
          DownlinkOnly: 4
          BufferSize: 64
        Nodes:
        """
    ).rstrip()

    return head + "\n" + "\n".join(blocks) + "\n"


def ensure_installed(install_script_url: str) -> None:
    if Path("/usr/local/XrayR/XrayR").exists():
        print("[ok] XRayR already installed")
        return
    print("[info] XRayR not found, running one-click installer...")
    cmd = f"bash <(curl -Ls {install_script_url})"
    run(cmd, check=True)
    if not Path("/usr/local/XrayR/XrayR").exists():
        raise RuntimeError("XRayR installer finished but binary not found")
    print("[ok] XRayR installed")


def backup_files(base: Path, files: List[str]) -> Path:
    ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    bdir = base / "backups" / ts
    bdir.mkdir(parents=True, exist_ok=True)
    for f in files:
        p = base / f
        if p.exists():
            shutil.copy2(p, bdir / f)
    return bdir


def write_outputs(out_dir: Path, config_text: str, outbound_obj: List[Dict], route_obj: Dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "config.yml").write_text(config_text)
    (out_dir / "custom_outbound.json").write_text(json.dumps(outbound_obj, ensure_ascii=False, indent=2) + "\n")
    (out_dir / "route.json").write_text(json.dumps(route_obj, ensure_ascii=False, indent=2) + "\n")


def restart_and_check() -> None:
    run("systemctl restart XrayR", check=True)
    status = run("systemctl is-active XrayR", check=False).stdout.strip()
    if status != "active":
        logs = run("journalctl -u XrayR -n 80 --no-pager", check=False).stdout
        raise RuntimeError(f"XrayR not active after restart (status={status})\n{logs}")


def interactive_fill(args: argparse.Namespace) -> argparse.Namespace:
    if not args.api_host:
        args.api_host = input("ApiHost (e.g. https://panel.example.com): ").strip()
    if not args.api_key:
        args.api_key = getpass.getpass("ApiKey (SERVER_TOKEN): ").strip()
    if not args.node_ids:
        args.node_ids = input("NodeID (single or comma list, e.g. 5 or 5,6): ").strip()
    if not args.node_types and not args.node_type:
        v = input("NodeTypes (single or comma list, e.g. V2ray or V2ray,Shadowsocks) [V2ray]: ").strip()
        args.node_types = v or "V2ray"
    if not args.ports:
        args.ports = input("Local ports (single/list/range, e.g. 26210 or 26210-26215): ").strip()
    if not args.sub_url:
        args.sub_url = input("Upstream subscription URL: ").strip()
    if not args.map_mode:
        v = input("Mapping mode [auto/manual]: ").strip().lower()
        args.map_mode = v or "auto"
    if args.map_mode == "manual" and not args.map_indices:
        args.map_indices = input("Manual node indexes (e.g. 1,3,5): ").strip()
    return args


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="XRayR upstream wizard")
    p.add_argument("--api-host")
    p.add_argument("--api-key")
    p.add_argument("--node-ids", help="single/list/range, e.g. 5 or 5,6 or 5-8")
    p.add_argument("--node-type")
    p.add_argument("--node-types", help="single/list, e.g. V2ray or V2ray,Shadowsocks")
    p.add_argument("--ports", help="single/list/range, e.g. 26210-26215")
    p.add_argument("--sub-url")
    p.add_argument("--map-mode", choices=["auto", "manual"], default="auto")
    p.add_argument("--map-indices", help="manual indexes list, e.g. 1,2,5")
    p.add_argument("--apply", action="store_true", help="write /etc/XrayR and restart service")
    p.add_argument("--dry-run", action="store_true", help="only generate files")
    p.add_argument("--output-dir", default="./generated", help="used when dry-run")
    p.add_argument("--skip-install", action="store_true")
    p.add_argument("--install-script-url", default=INSTALL_SCRIPT_URL)
    p.add_argument("--rollback", action="store_true", help="rollback latest backup in /etc/XrayR/backups")
    p.add_argument("--non-interactive", action="store_true")
    return p.parse_args()


def do_rollback(base: Path) -> int:
    broot = base / "backups"
    if not broot.exists():
        eprint("[err] no backups directory")
        return 1
    cand = sorted([p for p in broot.iterdir() if p.is_dir()])
    if not cand:
        eprint("[err] no backup snapshots")
        return 1
    latest = cand[-1]
    for name in ["config.yml", "custom_outbound.json", "route.json"]:
        src = latest / name
        if src.exists():
            shutil.copy2(src, base / name)
    print(f"[ok] rolled back from: {latest}")
    try:
        restart_and_check()
        print("[ok] XrayR restarted")
    except Exception as ex:
        eprint(f"[err] restart after rollback failed: {ex}")
        return 1
    return 0


def main() -> int:
    args = parse_args()

    if args.rollback:
        return do_rollback(DEFAULT_ETC)

    if not args.non_interactive:
        args = interactive_fill(args)

    if not args.node_ids or not args.ports or not args.sub_url or not args.api_host or not args.api_key:
        eprint("[err] missing required inputs")
        return 1

    try:
        node_ids = parse_range_list(args.node_ids)
        ports = parse_range_list(args.ports)
    except Exception as ex:
        eprint(f"[err] parse list/range failed: {ex}")
        return 1

    if len(node_ids) != len(ports):
        eprint(f"[err] node_ids count ({len(node_ids)}) must equal ports count ({len(ports)})")
        return 1

    # 节点类型支持两种模式：
    # 1) 单个类型（--node-type 或 --node-types 仅一个值）广播到全部 NodeID
    # 2) 多个类型（--node-types 多值）与 NodeID/端口一一对应
    node_types_input = args.node_types or args.node_type or "V2ray"
    try:
        node_types = parse_node_types(node_types_input)
    except Exception as ex:
        eprint(f"[err] parse node types failed: {ex}")
        return 1
    if len(node_types) == 1:
        node_types = node_types * len(node_ids)
    if len(node_types) != len(node_ids):
        eprint(
            f"[err] node_types count ({len(node_types)}) must be 1 or equal node_ids count ({len(node_ids)})"
        )
        return 1

    manual_indices = None
    if args.map_mode == "manual":
        if not args.map_indices:
            eprint("[err] manual mode requires --map-indices")
            return 1
        try:
            manual_indices = parse_range_list(args.map_indices)
        except Exception as ex:
            eprint(f"[err] parse --map-indices failed: {ex}")
            return 1

    if not args.skip_install:
        try:
            ensure_installed(args.install_script_url)
        except Exception as ex:
            eprint(f"[err] install failed: {ex}")
            return 1

    print(f"[info] Fetching subscription: {mask_secret(args.sub_url)}")
    yaml_vmess_nodes: List[Dict] = []
    yaml_ss_nodes: List[Dict] = []
    yaml_ss_skipped = 0
    try:
        raw = fetch_text(args.sub_url)
        lines = decode_subscription(raw)
        nodes, skipped = parse_nodes(lines)
        yaml_vmess_nodes = parse_mihomo_yaml_vmess(raw)
        yaml_ss_nodes, yaml_ss_skipped = parse_mihomo_yaml_ss(raw)
        if yaml_vmess_nodes:
            nodes.extend(yaml_vmess_nodes)
        if yaml_ss_nodes:
            nodes.extend(yaml_ss_nodes)
    except Exception as ex:
        eprint(f"[err] subscription parse failed: {ex}")
        return 1

    before_filter = len(nodes)
    nodes = [n for n in nodes if not is_bad_upstream_host(n.get("add", ""))]
    dropped_bad_host = before_filter - len(nodes)

    print(
        f"[info] parsed upstream nodes: {len(nodes)}, "
        f"from-links: {len(nodes) - len(yaml_vmess_nodes) - len(yaml_ss_nodes)}, "
        f"from-yaml-vmess: {len(yaml_vmess_nodes)}, "
        f"from-yaml-ss: {len(yaml_ss_nodes)}, "
        f"skipped-yaml-ss-invalid: {yaml_ss_skipped}, "
        f"dropped-bad-host: {dropped_bad_host}, "
        f"skipped vmess-decode: {skipped['vmess']}, "
        f"skipped vless-decode: {skipped['vless']}, "
        f"skipped hy2-decode: {skipped['hy2']}, "
        f"skipped-other-protocol: {skipped['other']}"
    )
    if not nodes:
        eprint("[err] no supported nodes parsed (vmess/vless/ss-yaml)")
        return 1

    for i, n in enumerate(nodes[:10], 1):
        if n.get("protocol") == "ss":
            plugin = n.get("plugin") or "none"
            print(
                f"  [{i}] {n.get('ps','')} | {n['add']}:{n['port']} | "
                f"ss:{n.get('method','')} | plugin={plugin}"
            )
        elif n.get("protocol") == "vless":
            print(
                f"  [{i}] {n.get('ps','')} | {n['add']}:{n['port']} | "
                f"vless:{n.get('net','tcp')} | security={n.get('tls','none') or 'none'}"
            )
        elif n.get("protocol") == "hysteria2":
            print(
                f"  [{i}] {n.get('ps','')} | {n['add']}:{n['port']} | "
                f"hy2 | sni={n.get('sni','') or n['add']} | insecure={int(bool(n.get('insecure', False)))}"
            )
        else:
            print(f"  [{i}] {n.get('ps','')} | {n['add']}:{n['port']} | {n['net']} | tls={n['tls'] or 'none'}")

    try:
        picked = pick_nodes(nodes, len(ports), manual_indices)
    except Exception as ex:
        eprint(f"[err] select upstream nodes failed: {ex}")
        return 1

    out_obj = build_outbound(ports, picked)
    route_obj = build_route(ports, node_types)
    cfg_text = build_config_yaml(args.api_host, args.api_key, node_ids, node_types)

    if args.apply and args.dry_run:
        eprint("[err] choose either --apply or --dry-run, not both")
        return 1

    if args.apply:
        if os.geteuid() != 0:
            eprint("[err] --apply requires root")
            return 1
        try:
            bdir = backup_files(DEFAULT_ETC, ["config.yml", "custom_outbound.json", "route.json"])
            write_outputs(DEFAULT_ETC, cfg_text, out_obj, route_obj)
            os.chmod(DEFAULT_ETC / "config.yml", 0o600)
            os.chmod(DEFAULT_ETC / "custom_outbound.json", 0o600)
            os.chmod(DEFAULT_ETC / "route.json", 0o600)
            restart_and_check()
            print(f"[ok] applied to {DEFAULT_ETC}")
            print(f"[ok] backup: {bdir}")
            logs = run("journalctl -u XrayR -n 30 --no-pager", check=False).stdout
            print("[info] latest logs:\n" + logs)
            return 0
        except Exception as ex:
            eprint(f"[err] apply failed: {ex}")
            return 1

    out_dir = Path(args.output_dir).resolve()
    write_outputs(out_dir, cfg_text, out_obj, route_obj)
    print(f"[ok] dry-run files generated at: {out_dir}")
    print("[next] inspect then apply by running with --apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
