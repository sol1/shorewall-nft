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
#
# The egress side follows process_simple_device too (#48): the prio qdisc is
# the root when there is no OUT-BANDWIDTH, TYPE picks the flow-hash key,
# each interface's handles come from its number in the file, and
# OUT-BANDWIDTH takes rate[:burst[:latency[:peak[:minburst]]]].
import os
import sys
import tempfile
from collections import namedtuple
from contextlib import contextmanager

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import capabilities                    # noqa: E402
from shorewall_nft.compile import TC_PRIOMAP_DEFAULT, tc_priomap  # noqa: E402
from shorewall_nft.errors import ConfigError              # noqa: E402
from shorewall_nft.model import TcInterface               # noqa: E402
from shorewall_nft.parsers import (parse_in_bandwidth, parse_out_bandwidth,  # noqa: E402
                                   parse_tcinterfaces)
from shorewall_nft.reader import Line                     # noqa: E402
from shorewall_nft.script import _ingress_police, _simple_tc  # noqa: E402

fails = 0

Cfg = namedtuple("Cfg", "tcinterfaces tc_priomap")
Cfg.__new__.__defaults__ = (TC_PRIOMAP_DEFAULT,)
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
        egress=parse_out_bandwidth("10mbit", LINE), origin="tcinterfaces:1")]))
check("simple shaping carries the IN-BANDWIDTH burst",
      "basic police mpu 64 rate 1000000kbit burst 256kb drop" in up)


# The egress side, as upstream's process_simple_device emits it (#48).
def tcinterfaces(text):
    """Parse a tcinterfaces file body."""
    with tempfile.NamedTemporaryFile("w", suffix=".tcinterfaces",
                                     delete=False) as f:
        f.write(text)
    try:
        return parse_tcinterfaces(f.name, {}, [])
    finally:
        os.unlink(f.name)


def egress(text, flow_filter=True):
    """The setup_tc lines for a tcinterfaces file body, stripped."""
    saved = capabilities.CAPABILITIES["FLOW_FILTER"]
    capabilities.CAPABILITIES["FLOW_FILTER"] = flow_filter
    try:
        with basic_filter(True):
            up, _ = _simple_tc(Cfg(tcinterfaces(text)))
    finally:
        capabilities.CAPABILITIES["FLOW_FILTER"] = saved
    return [line.strip() for line in up.splitlines()]


PRIO = "prio bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1"
SFQ = "sfq quantum 1875 limit 127 perturb 10"

one = egress("eth0 external 20mbit 10mbit\n")
check("one interface: tbf 1:, prio 101:, sfq 1011: to 1013:",
      "tc qdisc add dev eth0 root handle 1: tbf rate 10000kbit burst 10kb "
      "latency 200ms mpu 64" in one
      and f"tc qdisc add dev eth0 parent 1: handle 101: {PRIO}" in one
      and f"tc qdisc add dev eth0 parent 101:3 handle 1013: {SFQ}" in one
      and "tc filter add dev eth0 protocol all prio 19 parent 101: handle 3 "
          "fw classid 101:3" in one)
check("external hashes flows on nfct-src",
      "tc filter add dev eth0 protocol all prio 1 parent 1011: handle 4 flow "
      "hash keys nfct-src divisor 1024" in one)

two = egress("eth0 external 20mbit 10mbit\neth1 internal - -\n")
check("second interface without OUT-BANDWIDTH: prio is the root at 2:",
      f"tc qdisc add dev eth1 root handle 2: {PRIO}" in two
      and f"tc qdisc add dev eth1 parent 2:1 handle 21: {SFQ}" in two
      and "tc filter add dev eth1 protocol all prio 17 parent 2: handle 1 "
          "fw classid 2:1" in two
      and any(line.startswith("tc filter add dev eth1 parent 2:0")
              and line.endswith("flowid 2:1") for line in two))
check("second interface: no tbf and no ingress qdisc",
      not any("dev eth1" in line and ("tbf" in line or "ingress" in line)
              for line in two if "add" in line))
# TYPE internal is checked here and not in the corpus: cls_flow refuses the
# src and dst keys from a non-initial user namespace, which is where the
# sandbox runs, so neither compiler's script loads there with it.
check("internal hashes flows on dst",
      "tc filter add dev eth1 protocol all prio 1 parent 21: handle 4 flow "
      "hash keys dst divisor 1024" in two)
check("TYPE - adds no flow filter",
      not any("flow hash" in line
              for line in egress("eth0 - 20mbit 10mbit\n")))
check("without FLOW_FILTER there is no flow filter",
      not any("flow hash" in line
              for line in egress("eth0 external 20mbit 10mbit\n",
                                 flow_filter=False)))

# Handles are hex, as upstream's in_hexp prints them: the tenth interface
# is a:, its prio 10a: and its leaves 10a1: to 10a3:.
many = egress("".join(f"eth{k} external - 10mbit\n" for k in range(12)))
check("tenth interface: handles a:, 10a:, 10a1:",
      "tc qdisc add dev eth9 root handle a: tbf rate 10000kbit burst 10kb "
      "latency 200ms mpu 64" in many
      and f"tc qdisc add dev eth9 parent a: handle 10a: {PRIO}" in many
      and f"tc qdisc add dev eth9 parent 10a:1 handle 10a1: {SFQ}" in many)


def tbf(spec):
    """The tbf line for an OUT-BANDWIDTH spec."""
    return next(line for line in egress(f"eth0 external - {spec}\n")
                if " tbf " in line)


TBF = "tc qdisc add dev eth0 root handle 1: tbf rate 10000kbit"
check("OUT-BANDWIDTH rate: 10kb burst and 200ms latency by default",
      tbf("10mbit") == f"{TBF} burst 10kb latency 200ms mpu 64")
check("OUT-BANDWIDTH rate:burst:latency:peak:minburst",
      tbf("10mbit:20kb:100ms:12mbit:1500")
      == f"{TBF} burst 20kb latency 100ms mpu 64 peakrate 12mbit "
         "minburst 1500")
check("OUT-BANDWIDTH empty fields keep their defaults",
      tbf("10mbit::100ms") == f"{TBF} burst 10kb latency 100ms mpu 64")
check("OUT-BANDWIDTH bare number is bytes per second",
      "tbf rate 8000kbit " in tbf("1000000"))
check("OUT-BANDWIDTH - limits nothing",
      parse_out_bandwidth("-", LINE) is None)
for spec in (":10kb", "10mbit:bogus", "10mbit:10kb:fast",
             "10mbit:10kb:100ms:bogus", "10mbit:10kb:100ms:12mbit:bogus",
             "10mbit:10kb:100ms:12mbit:1500:extra", "10mbit;reboot",
             "1tbit", "fast"):
    check(f"OUT-BANDWIDTH {spec!r} is an error",
          raises(lambda: parse_out_bandwidth(spec, LINE)))

# Upstream's tcinterfaces errors: a missing or duplicate INTERFACE, a name
# with : or +, and an unknown TYPE.
for text in ("- external - 10mbit\n", "eth0 fast - 10mbit\n",
             "eth0 external - 10mbit\neth0 internal - -\n",
             "eth0:1 external - 10mbit\n", "eth+ external - 10mbit\n"):
    check(f"tcinterfaces {text.strip()!r} is an error",
          raises(lambda: tcinterfaces(text)))
check("TYPE is case-insensitive",
      tcinterfaces("eth0 External - 10mbit\n")[0].flow == "nfct-src")
check("a missing TYPE column is -",
      tcinterfaces("eth0\n")[0].flow == "")

# Each device is wrapped in upstream's up-state guard: a device that is
# down at start is skipped with upstream's warning.
check("a down device is skipped with upstream's warning",
      "if interface_is_up eth0; then" in one
      and 'echo "WARNING: Device eth0 is not in the UP state -- '
          'traffic-shaping configuration skipped" >&2' in one
      and one.index("if interface_is_up eth0; then")
          < one.index("tc qdisc del dev eth0 root 2>/dev/null || :"))
check("the second device has its own guard",
      "if interface_is_up eth1; then" in two)

# TC_PRIOMAP is read as upstream reads it: 16 bands, 1 to 3, made
# zero-based for tc. Empty is upstream's default.
DEFAULT_MAP = "1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1"
check("TC_PRIOMAP unset is upstream's default", tc_priomap({}) == DEFAULT_MAP)
check("TC_PRIOMAP at upstream's shipped value gives the same map",
      tc_priomap({"TC_PRIOMAP": '"2 3 3 3 2 3 1 1 2 2 2 2 2 2 2 2"'})
      == DEFAULT_MAP)
check("TC_PRIOMAP bands are one-based",
      tc_priomap({"TC_PRIOMAP": "1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1"})
      == "0 1 2 0 1 2 0 1 2 0 1 2 0 1 2 0")
for value in ("1 2 3", "1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2", "4 " * 16,
              "0 " * 16, "x " * 16):
    check(f"TC_PRIOMAP {value.strip()!r} is an error",
          raises(lambda: tc_priomap({"TC_PRIOMAP": value})))
with basic_filter(True):
    up, _ = _simple_tc(Cfg(tcinterfaces("eth0 external - 10mbit\n"),
                           tc_priomap({"TC_PRIOMAP": "3 " * 16})))
check("the prio qdisc takes TC_PRIOMAP",
      "prio bands 3 priomap 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2" in up)


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
