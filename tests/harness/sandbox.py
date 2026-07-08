#!/usr/bin/env python3
"""Build a network topology in an unprivileged user namespace, load a
firewall ruleset on the fw node, run the probe matrix, report verdicts.

Usage: sandbox.py CASE_DIR --load ipt:PAYLOAD | --load nft:RULESET

Reads CASE_DIR/case.toml for links, routes and probes. Output is one
JSON document on stdout:

    {"load": "...", "verdicts": [{"id": ..., "verdict": ..., "peer": ...}]}

Verdict classes: tcp probes give allow, drop (timeout) or reject
(active refusal, detail carries the errno name). icmp probes give
allow or blocked. No self-grading happens here. Comparison is the
runner's job.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import tomllib

RAWTCP = r'''
# Craft a TCP segment with arbitrary flags and send it. Verdict is
# whether the firewall passed it: sniff the far side with a raw socket
# for one round-trip. No dependencies, needs CAP_NET_RAW (root in the
# userns). argv: dst_addr dport flags src_addr sport
import socket, sys, struct, json, time, select

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

dst, dport = sys.argv[1], int(sys.argv[2])
flags = int(sys.argv[3], 0)
src, sport = sys.argv[4], int(sys.argv[5])
mss = int(sys.argv[6]) if len(sys.argv) > 6 else 0

def build(src, dst, sport, dport, flags, mss=0):
    seq = 0x11223344
    # An MSS option (kind 2, length 4) is exactly one 32-bit word, so
    # the data offset becomes 6 and no padding is needed.
    opts = struct.pack("!BBH", 2, 4, mss) if mss else b""
    off = 6 if mss else 5
    off_flags = (off << 12) | flags
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0, off_flags,
                      1024, 0, 0) + opts
    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)
              + struct.pack("!BBH", 0, 6, len(tcp)))
    csum = checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    return tcp

r = {"verdict": None, "peer": None, "detail": None}
# Receiver on the destination host is a separate process; here we only
# send from the source. The destination side records arrivals via a
# raw sniffer started by the harness. We report send success only.
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
try:
    s.sendto(build(src, dst, sport, dport, flags, mss), (dst, 0))
    r["verdict"] = "sent"
except OSError as e:
    r["verdict"] = "senderror"
    r["detail"] = str(e)
print(json.dumps(r))
'''

RAWSNIFF = r'''
# Sniff arriving TCP segments to a port and report the first source
# address seen, or timeout. argv: dport timeout
import socket, sys, struct, json, select
dport = int(sys.argv[1])
timeout = float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.settimeout(timeout)
r = {"verdict": "drop", "peer": None, "detail": None}
end = None
import time as _t
deadline = _t.time() + timeout
while _t.time() < deadline:
    ready, _, _ = select.select([s], [], [], deadline - _t.time())
    if not ready:
        break
    pkt, addr = s.recvfrom(65535)
    ihl = (pkt[0] & 0xf) * 4
    tcp = pkt[ihl:]
    if len(tcp) < 4:
        continue
    dst_port = struct.unpack("!H", tcp[2:4])[0]
    if dst_port == dport:
        r["verdict"] = "arrived"
        r["peer"] = addr[0]
        # The TCP flags byte, the IP TOS byte, and the MSS option if
        # present. Walk the TCP options between the fixed header and the
        # data offset: kind 0 ends, kind 1 is a nop, kind 2 is the MSS.
        detail = "flags=0x%02x tos=0x%02x" % (tcp[13], pkt[1])
        off = (tcp[12] >> 4) * 4
        i = 20
        while i < off and i < len(tcp):
            kind = tcp[i]
            if kind == 0:
                break
            if kind == 1:
                i += 1
                continue
            olen = tcp[i + 1] if i + 1 < len(tcp) else 2
            if kind == 2 and olen == 4:
                detail += " mss=%d" % struct.unpack("!H", tcp[i + 2:i + 4])[0]
            i += max(olen, 2)
        r["detail"] = detail
        break
print(json.dumps(r))
'''

LISTENER = r'''
import socket, sys
bind = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
srv = socket.socket(fam)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((bind, int(sys.argv[1])))
srv.listen(16)
while True:
    c, a = srv.accept()
    try:
        c.sendall(("peer=" + a[0]).encode())
    finally:
        c.close()
'''

CONNECT = r'''
import socket, sys, json, errno
host, port = sys.argv[1], int(sys.argv[2])
source = sys.argv[3] if len(sys.argv) > 3 else ""
r = {"verdict": None, "peer": None, "detail": None}
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(fam)
s.settimeout(3)
try:
    if source:
        s.bind((source, 0))
    s.connect((host, port))
    r["verdict"] = "allow"
    try:
        data = s.recv(64).decode(errors="replace").strip()
        if data.startswith("peer="):
            r["peer"] = data[5:]
    except OSError:
        pass
except socket.timeout:
    r["verdict"] = "drop"
except OSError as e:
    r["verdict"] = "reject"
    r["detail"] = errno.errorcode.get(e.errno, str(e.errno))
finally:
    s.close()
print(json.dumps(r))
'''

LISTENER_UDP = r'''
import socket, sys
bind = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
srv = socket.socket(fam, socket.SOCK_DGRAM)
srv.bind((bind, int(sys.argv[1])))
while True:
    data, addr = srv.recvfrom(64)
    srv.sendto(("peer=" + addr[0]).encode(), addr)
'''

CONNECT_UDP = r'''
import socket, sys, json, errno
host, port = sys.argv[1], int(sys.argv[2])
r = {"verdict": None, "peer": None, "detail": None}
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(b"probe", (host, port))
    data, addr = s.recvfrom(64)
    r["verdict"] = "allow"
    text = data.decode(errors="replace").strip()
    if text.startswith("peer="):
        r["peer"] = text[5:]
except socket.timeout:
    r["verdict"] = "drop"
except OSError as e:
    r["verdict"] = "reject"
    r["detail"] = errno.errorcode.get(e.errno, str(e.errno))
finally:
    s.close()
print(json.dumps(r))
'''


def sh(*args, check=True, **kw):
    return subprocess.run(list(args), check=check, **kw)


def ns(node, *args, **kw):
    return sh("ip", "netns", "exec", node, *args, **kw)


def build(case):
    nodes = {"fw"}
    for link in case.get("links", []):
        nodes.add(link["node_a"])
        nodes.add(link["node_b"])
    for node in sorted(nodes):
        sh("ip", "netns", "add", node)
        ns(node, "ip", "link", "set", "lo", "up")
    for link in case.get("links", []):
        sh("ip", "link", "add", link["dev_a"], "netns", link["node_a"],
           "type", "veth", "peer", "name", link["dev_b"], "netns", link["node_b"])
        for side in ("a", "b"):
            node, dev, addr = (link[f"node_{side}"], link[f"dev_{side}"],
                               link[f"addr_{side}"])
            mac = link.get(f"mac_{side}")
            if mac:
                ns(node, "ip", "link", "set", dev, "address", mac)
            extra = ["nodad"] if ":" in addr else []
            ns(node, "ip", "addr", "add", addr, "dev", dev, *extra)
            ns(node, "ip", "link", "set", dev, "up")
    for node, addrs in case.get("extra_addrs", {}).items():
        for addr in addrs:
            addr, _, dev = addr.partition("@")
            ns(node, "ip", "addr", "add", addr, "dev", dev or "lo")
    for node, gw in case.get("routes", {}).items():
        ns(node, "ip", "route", "add", "default", "via", gw)
    ns("fw", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    ns("fw", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
    _settle(case)
    return nodes


def _settle(case):
    """Wait out duplicate address detection and warm neighbor caches
    before any ruleset loads. Models an established network, where
    neighbors are already resolved. IPv6 first-contact ND otherwise
    eats the probe timeout."""
    for _ in range(50):
        out = sh("ip", "-all", "netns", "exec", "ip", "-6", "addr",
                 check=False, capture_output=True, text=True).stdout
        if "tentative" not in out:
            break
        time.sleep(0.1)
    for link in case.get("links", []):
        addr_a = link["addr_a"].split("/")[0]
        addr_b = link["addr_b"].split("/")[0]
        ns(link["node_a"], "ping", "-c1", "-W1", addr_b, check=False,
           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ns(link["node_b"], "ping", "-c1", "-W1", addr_a, check=False,
           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def load_ruleset(spec):
    mode, _, path = spec.partition(":")
    if mode == "ipt":
        with open(path) as f:
            ns("fw", "iptables-nft-restore", stdin=f)
    elif mode == "ipt6":
        with open(path) as f:
            ns("fw", "ip6tables-nft-restore", stdin=f)
    elif mode == "nft":
        ns("fw", "nft", "-f", os.path.realpath(path))
    elif mode == "script":
        # A firewall script, ours or upstream's. Runs entirely inside
        # the fw namespace.
        env = dict(os.environ, SWNFT_STATE="/run/swnft-state")
        r = subprocess.run(["ip", "netns", "exec", "fw", "sh",
                            os.path.realpath(path), "start"],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"firewall script failed:\n{r.stdout}\n{r.stderr}")
    else:
        sys.exit(f"unknown load mode: {mode}")


def start_listeners(case):
    procs = []
    bind = "::" if case.get("family", 4) == 6 else "0.0.0.0"
    wanted = {(p["to"], p.get("listen_port", p["port"]), p["proto"])
              for p in case.get("probes", []) if p["proto"] in ("tcp", "udp")}
    for node, port, proto in sorted(wanted):
        script = LISTENER if proto == "tcp" else LISTENER_UDP
        procs.append(subprocess.Popen(
            ["ip", "netns", "exec", node, "python3", "-c", script, str(port),
             bind],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL))
    time.sleep(0.4)
    return procs


def run_probes(case):
    verdicts = []
    for p in case.get("probes", []):
        entry = {"id": p["id"], "verdict": None, "peer": None, "detail": None}
        if p["proto"] == "rawtcp":
            # Start a raw sniffer on the destination, send the crafted
            # segment, read what arrived. The firewall verdict is
            # arrived vs drop, from the far side's view.
            sniff = subprocess.Popen(
                ["ip", "netns", "exec", p["to"], "python3", "-c", RAWSNIFF,
                 str(p["port"]), "3"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            time.sleep(0.3)
            ns(p["from"], "python3", "-c", RAWTCP, p["addr"], str(p["port"]),
               str(p.get("flags", "0x02")), p["source"],
               str(p.get("sport", 40000)), str(p.get("mss", 0)), check=False,
               capture_output=True, text=True)
            out, _ = sniff.communicate(timeout=5)
            try:
                res = json.loads(out)
                entry["verdict"] = res["verdict"]
                entry["peer"] = res["peer"]
                entry["detail"] = res.get("detail")
            except (json.JSONDecodeError, KeyError):
                entry["verdict"] = "snifferror"
        elif p["proto"] in ("tcp", "udp"):
            script = CONNECT if p["proto"] == "tcp" else CONNECT_UDP
            args = [p["addr"], str(p["port"])]
            if p.get("source"):
                args.append(p["source"])
            out = ns(p["from"], "python3", "-c", script, *args,
                     capture_output=True, text=True)
            entry.update(json.loads(out.stdout))
        elif p["proto"] == "icmp":
            src = ["-I", p["source"]] if p.get("source") else []
            rc = ns(p["from"], "ping", "-c1", "-W2", *src, p["addr"],
                    check=False, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
            entry["verdict"] = "allow" if rc.returncode == 0 else "blocked"
        else:
            entry["verdict"] = "unsupported-proto"
        verdicts.append(entry)
    return verdicts


def teardown(nodes, procs):
    for proc in procs:
        proc.kill()
    for node in nodes:
        pids = sh("ip", "netns", "pids", node, check=False,
                  capture_output=True, text=True).stdout.split()
        for pid in pids:
            sh("kill", "-9", pid, check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case_dir")
    ap.add_argument("--load", required=True, help="ipt:FILE or nft:FILE")
    args = ap.parse_args()

    if not os.environ.get("SWNFT_SANDBOX"):
        env = dict(os.environ, SWNFT_SANDBOX="1",
                   PATH="/usr/sbin:/sbin:" + os.environ.get("PATH", ""))
        os.execvpe("unshare", ["unshare", "-r", "-n", "-m",
                               sys.executable, os.path.realpath(__file__),
                               os.path.realpath(args.case_dir),
                               "--load", args.load], env)

    sh("mount", "-t", "tmpfs", "tmpfs", "/run")
    sh("mount", "-t", "tmpfs", "tmpfs", "/var/log", check=False)
    os.environ["XTABLES_LOCKFILE"] = "/run/xtables.lock"
    # Upstream compiled scripts write state under the staged VARDIR.
    # Give each sandbox its own copy-free view.
    stage_var = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             ".stage", "var", "lib")
    if os.path.isdir(stage_var):
        sh("mount", "-t", "tmpfs", "tmpfs", stage_var, check=False)
        os.makedirs(os.path.join(stage_var, "shorewall"), exist_ok=True)

    with open(os.path.join(args.case_dir, "case.toml"), "rb") as f:
        case = tomllib.load(f)

    nodes = build(case)
    load_ruleset(args.load)
    # Seed geoip country sets, standing in for `shorewall geoip-update`.
    for cc, cidrs in case.get("geoip", {}).items():
        ns("fw", "nft", "add", "element", "inet", "shorewall",
           f"geoip_{cc}", "{ " + ", ".join(cidrs) + " }")
    procs = start_listeners(case)
    try:
        verdicts = run_probes(case)
        ip_rules = ""
        if case.get("ip_rules"):
            ip_rules = ns("fw", "ip", "-4", "rule", "show",
                          capture_output=True, text=True).stdout
        tc_state = {}
        for dev in case.get("tc_devices", []):
            q = ns("fw", "tc", "qdisc", "show", "dev", dev,
                   capture_output=True, text=True).stdout
            c = ns("fw", "tc", "class", "show", "dev", dev,
                   capture_output=True, text=True).stdout
            f = ns("fw", "tc", "filter", "show", "dev", dev,
                   capture_output=True, text=True).stdout
            tc_state[dev] = q + c + f
    finally:
        teardown(nodes, procs)
    json.dump({"load": args.load, "verdicts": verdicts, "tc": tc_state,
               "ip_rules": ip_rules}, sys.stdout)
    print()


if __name__ == "__main__":
    main()
