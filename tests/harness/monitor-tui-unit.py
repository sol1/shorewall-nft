#!/usr/bin/env python3
# Unit tests for the fancy monitor. rich and textual are optional
# dependencies, so the rich block skips green where rich is absent and the
# textual pilot block skips where textual is absent. The renderers are pure
# functions of the sample; zone_flows is tested with the counter readers
# stubbed, so no nft or configuration is needed.
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))

fails = 0


def check(name, cond):
    global fails
    print("PASS" if cond else "FAIL", name)
    if not cond:
        fails += 1


try:
    import rich  # noqa: F401
except ImportError:
    print("SKIP monitor-tui-unit: rich not installed (optional dependency)")
    sys.exit(0)

from rich.console import Console  # noqa: E402
from shorewall_nft import monitor_tui as m  # noqa: E402


def render(renderable, width=90):
    c = Console(record=True, width=width)
    c.print(renderable)
    return c.export_text()


# --- render_flow: a hub with one spoke per zone ---
D2 = {"zones": ["net", "loc"],
      "flows": {"net": (85e6, 12e6), "loc": (12e6, 85e6)},
      "counters_on": True}
t2 = render(m.render_flow(D2))
for want in ("fw", "firewall", "net", "loc", "↓85M", "↑12M"):
    check(f"two-zone diagram shows {want!r}", want in t2)

D4 = {"zones": ["net", "loc", "dmz", "wg"],
      "flows": {"net": (85e6, 12e6), "loc": (3e6, 40e6),
                "dmz": (5e5, 9e5), "wg": (25e4, 25e4)},
      "counters_on": True}
t4 = render(m.render_flow(D4))
for want in ("net", "loc", "dmz", "wg", "fw"):
    check(f"four-zone diagram shows {want!r}", want in t4)

# selection filter: only net + dmz, the others gone
tf = render(m.render_flow(D4, selected={"net", "dmz"}))
check("filter keeps net and dmz", "net" in tf and "dmz" in tf)
check("filter drops loc and wg", "loc" not in tf and "wg" not in tf)

# empty selection prompts for options rather than crashing
check("empty selection prompts",
      "options" in render(m.render_flow(D4, selected=set())).lower())

# more than four zones falls back to a bar list
D5 = {"zones": list("abcde"), "flows": {z: (1e6, 1e6) for z in "abcde"},
      "counters_on": True}
check("five zones fall back to a bar list",
      "zone traffic" in render(m.render_flow(D5)).lower())

# COUNTERS off carries the note in the title
off = render(m.render_flow({"zones": ["net", "loc"],
                            "flows": {"net": (0, 0), "loc": (0, 0)},
                            "counters_on": False}))
check("counters-off note shown", "COUNTERS=Yes" in off)

# narrow width still renders (sidebar open, small terminal)
check("narrow render does not crash",
      "fw" in render(m.render_flow(D2, width=56), width=56))

# --- render_status: interfaces and denied ---
st = render(m.render_status({"ifaces": [("eth0", "net", 42e6, 8e6)],
                             "denies": [("net→fw", 128)]}))
for want in ("eth0", "net", "denied", "net→fw", "/s"):
    check(f"status shows {want!r}", want in st)

# --- compact helpers ---
check("compact rate 85M", m._short(85e6) == "85M")
check("compact rate 500K", m._short(5e5) == "500K")
check("bps unit", m._human_bps(42_000_000) == "42 Mb/s")

# --- zone_flows aggregation with the counter readers stubbed ---
m._zones_and_pairs = lambda fam: (
    ["net", "loc"],
    {"net2loc": ("net", "loc"), "loc2net": ("loc", "net"),
     "net2fw": ("net", "fw")})
_cseq = iter([{"t_net2loc": (10, 1000), "d_net2fw": (5, 500)},
              {"t_net2loc": (20, 9000), "d_net2fw": (9, 900)}])
m._read_counters = lambda fam: next(_cseq)
m._iface_bytes = lambda: {}
m._zone_map = lambda fam: {}

d1, p1 = m.zone_flows(4, {}, 1)
check("first sample has zero rates", d1["flows"]["net"] == (0.0, 0.0))
check("denies picked up on first sample",
      bool(d1["denies"]) and d1["denies"][0][0] == "net→fw")
d2, p2 = m.zone_flows(4, p1, 1)
check("net out rate over the interval", d2["flows"]["net"][1] == (9000 - 1000) * 8)
check("loc in rate over the interval", d2["flows"]["loc"][0] == (9000 - 1000) * 8)

# --- the interactive app, driven by the textual test pilot ---
try:
    import textual  # noqa: F401
    have_textual = True
except ImportError:
    have_textual = False
    print("SKIP monitor-tui pilot: textual not installed (optional dependency)")

if have_textual:
    import asyncio
    SAMPLE = {"zones": ["net", "loc", "dmz"],
              "flows": {"net": (85e6, 12e6), "loc": (3e6, 40e6),
                        "dmz": (5e5, 9e5)},
              "counters_on": True, "denies": [], "ifaces": []}
    m.zone_flows = lambda fam, prev, interval: (SAMPLE, {})

    async def _pilot():
        from textual.widgets import SelectionList
        app = m.build_app(4, 5)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            start_all = app._selected == {"net", "loc", "dmz"}
            zl = app.query_one("#zones", SelectionList)
            hidden = not zl.has_class("shown")
            await pilot.press("o")
            await pilot.pause()
            shown = zl.has_class("shown")
            await pilot.press("space")           # toggle the first zone off
            await pilot.pause()
            toggled = app._selected == {"loc", "dmz"}
            await pilot.press("a")               # select all again
            await pilot.pause()
            all_again = app._selected == {"net", "loc", "dmz"}
            await pilot.press("o")
            await pilot.pause()
            hidden_again = not zl.has_class("shown")
        return (start_all, hidden, shown, toggled, all_again, hidden_again)

    r = asyncio.run(_pilot())
    check("pilot: starts with all zones selected", r[0])
    check("pilot: sidebar hidden at start", r[1])
    check("pilot: o shows the zones sidebar", r[2])
    check("pilot: space toggles a zone off live", r[3])
    check("pilot: a re-selects all zones", r[4])
    check("pilot: o hides the sidebar again", r[5])

sys.exit(1 if fails else 0)
