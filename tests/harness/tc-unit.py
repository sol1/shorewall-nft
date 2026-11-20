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

sys.exit(1 if fails else 0)
