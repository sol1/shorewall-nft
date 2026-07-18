#!/usr/bin/env python3
"""Parser and compiler regression tests for legacy NETMAP compatibility."""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft.compile import load  # noqa: E402
from shorewall_nft.emit import render  # noqa: E402
from shorewall_nft.errors import ConfigError  # noqa: E402

REPO = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")
BASE4 = os.path.join(REPO, "tests/corpus/0043-netmap/config")
BASE6 = os.path.join(REPO, "tests/corpus/0044-netmap6/config")
fails = 0


def check(name, condition):
    global fails
    print("PASS" if condition else "FAIL", name)
    if not condition:
        fails += 1


def compile_with(family, netmap=None, remove=False, interfaces=None):
    tmp = tempfile.mkdtemp(prefix="shorewall-nft-netmap-")
    shutil.copytree(BASE6 if family == 6 else BASE4, tmp, dirs_exist_ok=True)
    path = os.path.join(tmp, "netmap")
    if remove:
        os.unlink(path)
    elif netmap is not None:
        with open(path, "w") as f:
            f.write(netmap)
    if interfaces is not None:
        with open(os.path.join(tmp, "interfaces"), "w") as f:
            f.write(interfaces)
    try:
        cfg = load(tmp, family)
        return cfg, render(cfg), None
    except ConfigError as e:
        return None, "", str(e)
    finally:
        shutil.rmtree(tmp)


for family in (4, 6):
    cfg, text, error = compile_with(family, remove=True)
    check(f"IPv{family} missing netmap is disabled", not error and not cfg.netmap)
    cfg, text, error = compile_with(family, "# comments and blank lines\n\n")
    check(f"IPv{family} empty netmap is valid", not error and not cfg.netmap)

v4 = ("SNAT 192.168.1.0/24 NET_IF 10.10.11.0/24\n"
      "DNAT 10.10.11.0/24 NET_IF 192.168.1.0/24\n")
cfg, text, error = compile_with(4, v4)
check("original IPv4 example parses", not error and len(cfg.netmap) == 2)
check("IPv4 SNAT preserves the host portion with prefix NAT",
      "oifname \"eth0\" ip saddr 192.168.1.0/24 snat ip prefix to ip saddr map { 192.168.1.0/24 : 10.10.11.0/24 }" in text)
check("IPv4 DNAT preserves the host portion with prefix NAT",
      "iifname \"eth0\" ip daddr 10.10.11.0/24 dnat ip prefix to ip daddr map { 10.10.11.0/24 : 192.168.1.0/24 }" in text)

v6 = ("SNAT:T fd00:470:b:227::/64 HE_IF 2001:470:b:227::/64\n"
      "DNAT:P 2001:470:b:227::/64!2001:470:b:227::/112\\\n"
      " HE_IF fd00:470:b:227::/64\n")
cfg, text, error = compile_with(6, v6)
check("documented IPv6 continuation parses", not error and len(cfg.netmap) == 2)
check("IPv6 SNAT:T emits source prefix NAT",
      "snat ip6 prefix to ip6 saddr map { fd00:470:b:227::/64 : 2001:470:b:227::/64 }" in text)
check("IPv6 DNAT:P exclusion is a separate negative match",
      "ip6 daddr 2001:470:b:227::/64 ip6 daddr != 2001:470:b:227::/112" in text)

many_exclusions = ("DNAT 10.0.0.0/8!10.1.0.0/16,10.2.0.0/16 "
                   "NET_IF 11.0.0.0/8\n")
cfg, text, error = compile_with(4, many_exclusions)
check("multiple NET1 exclusions use an anonymous negative set",
      not error and "ip daddr != { 10.1.0.0/16, 10.2.0.0/16 }" in text)

cfg, text, error = compile_with(
    4, "SNAT 10.0.0.0/8 ppp0 11.0.0.0/8\n",
    interfaces="?FORMAT 2\nnet wan physical=ppp+\nloc LOC_IF physical=eth1\n")
check("concrete interface loosely matches a declared wildcard",
      not error and 'oifname "ppp0"' in text)
cfg, text, error = compile_with(
    4, "SNAT 10.0.0.0/8 wan 11.0.0.0/8\n",
    interfaces="?FORMAT 2\nnet wan physical=ppp+\nloc LOC_IF physical=eth1\n")
check("logical wildcard interface emits an nft name glob",
      not error and 'oifname "ppp*"' in text)

lengths4 = (8, 16, 20, 24, 28, 32)
for length in lengths4:
    base = {8: "10.0.0.0", 16: "10.1.0.0", 20: "10.1.16.0",
            24: "10.1.1.0", 28: "10.1.1.16", 32: "10.1.1.1"}[length]
    dest = {8: "11.0.0.0", 16: "11.1.0.0", 20: "11.1.16.0",
            24: "11.1.1.0", 28: "11.1.1.16", 32: "11.1.1.1"}[length]
    cfg, _, error = compile_with(4, f"SNAT {base}/{length} NET_IF {dest}/{length}\n")
    check(f"IPv4 /{length}", not error)

for length in (32, 40, 48, 56, 60, 64, 96, 112, 128):
    # ipaddress canonicalization verifies all host bits for these all-zero tails.
    cfg, _, error = compile_with(
        6, f"SNAT:T fd00::/{length} HE_IF 2001:db8::/{length}\n")
    check(f"IPv6 /{length}", not error)

qualified = ("SNAT:T fd00:1330:44::/48 HE_IF 2001:db8:1::/48 "
             "2001:db8:feed::/48 tcp https 1024:65535\n"
             "DNAT:P 2001:db8:2::/48 HE_IF fd00:1330:45::/48 "
             "fd00:beef::/48 udp 53 -\n"
             "DNAT:P 2001:db8:3::/48 HE_IF fd00:1330:46::/48 "
             "- tcp http-alt -\n")
cfg, text, error = compile_with(6, qualified)
check("NET3 protocol service and port range parse", not error)
check("SNAT NET3 is a destination match",
      "ip6 daddr 2001:db8:feed::/48 meta l4proto tcp tcp sport 1024-65535 tcp dport https" in text)
check("DNAT NET3 is a source match",
      "ip6 saddr fd00:beef::/48 meta l4proto udp udp dport 53" in text)
check("hyphenated service name parses as a service, not a range",
      "tcp dport http-alt" in text)

cfg, text, error = compile_with(
    4, "SNAT 100.64.0.0/10 NET_IF 100.128.0.0/10 - tcp,udp 443 -\n"
       "DNAT 192.0.2.0/24 NET_IF 192.0.3.0/24 - !gre - -\n")
check("protocol list reuses the generic transport-header port match",
      not error and "meta l4proto { tcp, udp } th dport 443" in text)
check("protocol complement emits a negative l4proto match",
      not error and "meta l4proto != gre" in text)

icmp = "DNAT 10.1.0.0/16 NET_IF 192.168.0.0/16 - icmp 3/4 -\n"
cfg, text, error = compile_with(4, icmp)
check("ICMP type/code qualifier", not error and "icmp type 3 icmp code 4" in text)

multi = ("SNAT:T fd00:1330:44::/48 HE_IF 2405:800:1000::/48\n"
         "SNAT:T fd00:1330:44::/48 LOC_IF 2403:f000:2000::/48\n"
         "DNAT:P 2405:800:1000::/48 HE_IF fd00:1330:44::/48\n"
         "DNAT:P 2403:f000:2000::/48 LOC_IF fd00:1330:44::/48\n")
cfg, text, error = compile_with(6, multi)
check("same prefix on different providers is not a conflict", not error)
check("multi-provider rules use resolved ingress and egress interfaces",
      all(s in text for s in ('oifname "eth0"', 'oifname "eth1"',
                              'iifname "eth0"', 'iifname "eth1"')))

invalid = {
    "invalid TYPE": "MAP 10.0.0.0/24 NET_IF 11.0.0.0/24\n",
    "missing CIDR": "SNAT 10.0.0.0 NET_IF 11.0.0.0/24\n",
    "host bits": "SNAT 10.0.0.1/24 NET_IF 11.0.0.0/24\n",
    "mismatched lengths": "SNAT 10.0.0.0/24 NET_IF 11.0.0.0/16\n",
    "wrong family": "SNAT fd00::/64 NET_IF 2001:db8::/64\n",
    "outside exclusion": "SNAT 10.0.0.0/24!10.0.1.0/24 NET_IF 11.0.0.0/24\n",
    "unknown interface": "SNAT 10.0.0.0/24 missing 11.0.0.0/24\n",
    "too few columns": "SNAT 10.0.0.0/24 NET_IF\n",
    "too many columns": "SNAT 10.0.0.0/24 NET_IF 11.0.0.0/24 - tcp 80 - extra\n",
    "invalid port protocol": "SNAT 10.0.0.0/24 NET_IF 11.0.0.0/24 - gre 80\n",
    "zero prefix": "SNAT 0.0.0.0/0 NET_IF 0.0.0.0/0\n",
}
for name, entry in invalid.items():
    _, _, error = compile_with(4, entry)
    check(name + " rejected with file and line", bool(error and "netmap:1:" in error))

_, _, error = compile_with(6,
    "SNAT:T 10.0.0.0/24 HE_IF 11.0.0.0/24\n")
check("IPv4 in IPv6 file rejected with file and line",
      bool(error and "netmap:1:" in error))

for token in ("SNAT:P", "DNAT:T"):
    _, _, error = compile_with(
        4, f"{token} 10.0.0.0/24 NET_IF 11.0.0.0/24\n")
    check(token + " rejected explicitly", bool(error and
          "cross-hook stateless NETMAP" in error and "nftables backend" in error))

duplicate = ("SNAT 10.0.0.0/24 NET_IF 11.0.0.0/24\n"
             "SNAT:T 10.0.0.0/24 NET_IF 11.0.0.0/24\n")
_, _, error = compile_with(4, duplicate)
check("effective duplicate rejected", bool(error and "duplicate" in error))
conflict = ("SNAT 10.0.0.0/24 NET_IF 11.0.0.0/24\n"
            "SNAT 10.0.0.0/25 NET_IF 12.0.0.0/25\n")
_, _, error = compile_with(4, conflict)
check("overlapping contradictory mapping rejected", bool(error and "conflicting" in error))

sys.exit(1 if fails else 0)
