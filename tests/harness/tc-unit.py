#!/usr/bin/env python3
# Simple traffic shaping picks the ingress classifier by the BASIC_FILTER
# capability: the tc 'basic' classifier where the kernel has it, and a u32
# match-all fallback where it does not. RHEL, Rocky and AlmaLinux 9 ship
# kernels without cls_basic, so a basic filter fails there with "TC classifier
# not found" (#32). Pure, so it runs without a live kernel.
import os
import sys
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import capabilities        # noqa: E402
from shorewall_nft.script import _simple_tc    # noqa: E402

fails = 0

TcIf = namedtuple("TcIf", "interface in_bw out_bw origin")
Cfg = namedtuple("Cfg", "tcinterfaces")


def ingress_line(basic_filter):
    """The generated ingress filter line with BASIC_FILTER forced on or off."""
    saved = capabilities.CAPABILITIES["BASIC_FILTER"]
    capabilities.enable_probe(False)   # static defaults, no live probe
    capabilities.CAPABILITIES["BASIC_FILTER"] = basic_filter
    try:
        up, _ = _simple_tc(Cfg([TcIf("eth0", "20mbit", "10mbit",
                                     "tcinterfaces:1")]))
    finally:
        capabilities.CAPABILITIES["BASIC_FILTER"] = saved
    return next(l for l in up.splitlines() if "ffff:" in l and "filter" in l)


def check(name, cond):
    global fails
    if cond:
        print("PASS", name)
    else:
        print("FAIL", name)
        fails += 1


yes = ingress_line(True)
check("basic classifier when BASIC_FILTER is available",
      "basic police" in yes and "u32" not in yes)

no = ingress_line(False)
check("u32 fallback when BASIC_FILTER is absent",
      "u32 match u32 0 0 police" in no and "basic" not in no)

# The fallback keeps the same policer: rate, burst, mpu and drop.
for part in ("rate 20000kbit", "burst 10kb", "mpu 64", "drop"):
    check(f"fallback keeps {part}", part in no)


# tcfilters: u32 filters that classify into a leaf class (#32 follow-on).
from shorewall_nft.model import TcClass, TcDevice, TcFilter  # noqa: E402
from shorewall_nft.script import _tc_filters                 # noqa: E402
from shorewall_nft.errors import ConfigError                 # noqa: E402

CfgTc = namedtuple("CfgTc", "family tcfilters")
DEV = TcDevice(interface="eth0", number=1)
# class marks 1 and 2 give classid minors 11 and 12.
CLASSES = [TcClass(interface="eth0", num=1, mark=1),
           TcClass(interface="eth0", num=2, mark=2)]


def filt(**kw):
    kw.setdefault("origin", "tcfilters:1")
    return TcFilter(**kw)


def flines(family, *filters):
    return _tc_filters(CfgTc(family, list(filters)), DEV, CLASSES)


def has(lines, text):
    return any(text in line for line in lines)


# A protocol-only filter is a single u32 rule to the class minor.
out = flines(4, filt(device="eth0", minor=11, proto="icmp"))
check("tcfilters proto-only u32 to the class",
      has(out, "protocol ip parent 1:0 prio 1 u32 match ip protocol 1 0xff "
               "flowid 1:11"))

# A ported filter builds a hash table, links to it, and matches the port.
out = flines(4, filt(device="eth0", minor=12, source="10.0.1.0/24",
                     proto="tcp", dport="80"))
check("tcfilters port: hash table", has(out, "handle 001: u32 divisor 1"))
check("tcfilters port: link to table",
      has(out, "link 001:0 offset at 0 mask 0x0F00 shift 6 plus 0 eat"))
check("tcfilters port: dst match in the table",
      has(out, "u32 ht 001:0 match tcp dst 80 0xffff flowid 1:12"))
check("tcfilters port: source match on the base rule",
      has(out, "match ip src 10.0.1.0/24"))

# IPv6 uses the ip6 match keyword and the fixed-header link form.
out = flines(6, filt(device="eth0", minor=11, source="2001:db8::/32",
                     proto="udp", dport="53"))
check("tcfilters v6 match keyword", has(out, "match ip6 src 2001:db8::/32"))
check("tcfilters v6 link form", has(out, "link 001:0 offset plus 40 eat"))
check("tcfilters v6 udp dst", has(out, "match udp dst 53 0xffff"))


def raises(fn):
    try:
        fn()
        return False
    except ConfigError:
        return True


check("tcfilters unknown class is an error",
      raises(lambda: flines(4, filt(device="eth0", minor=99, proto="icmp"))))
check("tcfilters ports need tcp or udp",
      raises(lambda: flines(4, filt(device="eth0", minor=11, proto="icmp",
                                    dport="80"))))

sys.exit(1 if fails else 0)
