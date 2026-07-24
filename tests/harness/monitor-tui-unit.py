#!/usr/bin/env python3
# Render test for the fancy monitor. rich is an optional dependency, so this
# skips green where it is not installed and runs the headless render where it
# is. The render is a pure function of the sample, captured with a recording
# Console.
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
try:
    import rich  # noqa: F401
except ImportError:
    print("SKIP monitor-tui-unit: rich not installed (optional dependency)")
    sys.exit(0)

from rich.console import Console  # noqa: E402
from shorewall_nft import monitor_tui as m  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print("PASS" if cond else "FAIL", name)
    if not cond:
        fails += 1


hdr = {"product": "Shorewall", "host": "fw1", "state": "Started",
       "when": "12:00:00"}
data = {"ifaces": [{"iface": "eth0", "zone": "net",
                    "rx_bps": 42e6, "tx_bps": 8e6}],
        "zones": [{"pair": "net2loc", "bytes": 42_000_000,
                   "pkts": 31000, "bps": 30e6}],
        "denies": [{"pair": "net2fw", "pkts": 128, "bytes": 9000}],
        "counters_on": True}
c = Console(record=True, width=90)
c.print(m.render_frame(data, hdr))
text = c.export_text()
for want in ("Interfaces", "eth0", "net", "Zone traffic", "net2loc",
             "Denied", "net2fw", "/s"):
    check(f"render shows {want!r}", want in text)

# COUNTERS off: the note, and no zone table.
c = Console(record=True, width=90)
c.print(m.render_frame({"ifaces": [], "zones": [], "denies": [],
                        "counters_on": False}, hdr))
off = c.export_text()
check("counters-off note shown", "COUNTERS=Yes" in off)
check("no zone table when off", "since load" not in off)

# Human-readable helpers.
check("bps unit", m._human_bps(42_000_000) == "42.0 Mb/s")
check("bytes unit", m._human_bytes(1536).endswith("KB"))

sys.exit(1 if fails else 0)
