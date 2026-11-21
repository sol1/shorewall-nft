#!/usr/bin/env python3
# Traffic shaping units. Pure, so it runs without a live kernel.
#
# IN-BANDWIDTH, in tcinterfaces and tcdevices alike, is read the way
# upstream's process_in_bandwidth reads it (rate[:burst], or the estimated
# ~rate[:interval:decay] form) and emitted the way handle_in_bandwidth emits
# it: the tc basic classifier where the kernel has it, and a pair of u32
# match-all policers where it does not. RHEL, Rocky and AlmaLinux 9 ship
# kernels without cls_basic (#32). The burst defaults to 10kb, too small at
# gigabit rates, so it must be settable (#46).
import os
import sys
from collections import namedtuple
from contextlib import contextmanager

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import capabilities                    # noqa: E402
from shorewall_nft.errors import ConfigError              # noqa: E402
from shorewall_nft.model import TcInterface               # noqa: E402
from shorewall_nft.parsers import parse_in_bandwidth      # noqa: E402
from shorewall_nft.reader import Line                     # noqa: E402
from shorewall_nft.script import _ingress_police, _simple_tc  # noqa: E402

fails = 0

Cfg = namedtuple("Cfg", "tcinterfaces")
LINE = Line("tcinterfaces", 1, "")


def check(name, cond):
    global fails
    if cond:
        print("PASS", name)
    else:
        print("FAIL", name)
        fails += 1


def raises(fn):
    try:
        fn()
        return False
    except ConfigError:
        return True


@contextmanager
def basic_filter(present):
    """Force BASIC_FILTER on or off, with probing off."""
    saved = capabilities.CAPABILITIES["BASIC_FILTER"]
    capabilities.enable_probe(False)
    capabilities.CAPABILITIES["BASIC_FILTER"] = present
    try:
        yield
    finally:
        capabilities.CAPABILITIES["BASIC_FILTER"] = saved


def police(spec, present=True):
    """The ingress lines for an IN-BANDWIDTH spec."""
    with basic_filter(present):
        return _ingress_police("eth0", parse_in_bandwidth(spec, LINE))


HEAD = "tc filter add dev eth0 parent ffff: protocol all prio 10"
QDISC = "    tc qdisc add dev eth0 handle ffff: ingress"

# '-', 0 and an empty column mean no ingress policing.
for spec in ("-", "0", ""):
    check(f"IN-BANDWIDTH {spec!r} polices nothing", police(spec) == [])

# The rate/burst form with the basic classifier, burst defaulting to 10kb.
check("rate: basic policer with the 10kb default burst",
      police("20mbit") == [QDISC, f"    {HEAD} basic police mpu 64 rate "
                                  "20000kbit burst 10kb drop"])
check("rate:burst: the given burst (#46)",
      police("1gbit:256kb")[1] == f"    {HEAD} basic police mpu 64 rate "
                                  "1000000kbit burst 256kb drop")

# The estimated form.
check("~rate: estimator with the 250ms/4sec defaults",
      police("~20mbit")[1] == f"    {HEAD} estimator 250ms 4sec basic police "
                              "avrate 20000kbit drop")
check("~rate:interval:decay",
      police("~20mbit:500ms:8sec")[1] == f"    {HEAD} estimator 500ms 8sec "
                                         "basic police avrate 20000kbit drop")

# Without the basic classifier: upstream's two u32 match-all policers, one
# keyed on an IPv4 source and one on IPv6, with flowid :1 and no mpu.
no = police("20mbit:32kb", present=False)
check("no basic: ingress qdisc then two u32 policers", len(no) == 3)
check("no basic: IPv4 u32 policer",
      no[1] == f"    {HEAD} u32 match ip src 0.0.0.0/0 police rate 20000kbit "
               "burst 32kb drop flowid :1")
check("no basic: IPv6 u32 policer",
      no[2] == f"    {HEAD} u32 match ip6 src ::/0 police rate 20000kbit "
               "burst 32kb drop flowid :1")
with basic_filter(False):
    check("no basic: the estimated form is refused",
          raises(lambda: parse_in_bandwidth("~20mbit", LINE)))

# Rates convert as upstream's rate_to_kbit does. A bare number, or bps, is
# bytes per second. Fractions print the way Perl prints them.
for spec, kbit in (("20Mbit", "20000"), ("1.5mbps", "12000"),
                   ("125000", "1000"), ("1000bps", "8"), ("100", "0.8"),
                   ("2gbps", "16000000"), ("512kbps", "4096")):
    got = parse_in_bandwidth(spec, LINE).rate
    check(f"rate {spec} is {kbit}kbit", got == kbit)

# Upstream's validation errors.
for spec in ("1gbit:bogus", "1gbit:10kb;reboot", "fast", "1tbit",
             "~20mbit:500ms", "~20mbit:300ms:8sec", "~20mbit:250ms:3sec",
             "~20mbit:500ms:500ms", "~20mbit:4sec:4sec"):
    check(f"IN-BANDWIDTH {spec!r} is an error",
          raises(lambda: parse_in_bandwidth(spec, LINE)))
# decay in ms is fine only against a 250ms interval.
check("~ with 250ms/500ms is accepted",
      parse_in_bandwidth("~20mbit:250ms:500ms", LINE).decay == "500ms")

# Simple shaping wires the policer in after the egress tree.
with basic_filter(True):
    up, _ = _simple_tc(Cfg([TcInterface(
        interface="eth0", ingress=parse_in_bandwidth("1gbit:256kb", LINE),
        out_bw="10mbit", origin="tcinterfaces:1")]))
check("simple shaping carries the IN-BANDWIDTH burst",
      "basic police mpu 64 rate 1000000kbit burst 256kb drop" in up)


# tcfilters: u32 filters that classify into a leaf class (#32 follow-on).
from shorewall_nft.model import TcClass, TcDevice, TcFilter  # noqa: E402
from shorewall_nft.script import _tc_filters                 # noqa: E402

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


check("tcfilters unknown class is an error",
      raises(lambda: flines(4, filt(device="eth0", minor=99, proto="icmp"))))
check("tcfilters ports need tcp or udp",
      raises(lambda: flines(4, filt(device="eth0", minor=11, proto="icmp",
                                    dport="80"))))

sys.exit(1 if fails else 0)
