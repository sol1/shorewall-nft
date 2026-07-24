"""The fancy monitor, `shorewall monitor fancy`, rendered with rich.

Imported only when rich is installed, so the package never depends on it. All
data gathering lives in cli (pure stdlib and testable); this module is
presentation only. render_frame is a pure function of the sample, so it can be
rendered headlessly in a test with Console(record=True).
"""
import os
import socket
import time

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from . import __version__

_UNITS = ["b", "Kb", "Mb", "Gb", "Tb"]


def _human_bps(bps):
    v = float(bps)
    for u in _UNITS:
        if v < 1000 or u == _UNITS[-1]:
            return f"{v:,.1f} {u}/s"
        v /= 1000


def _human_bytes(n):
    v = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or u == "TB":
            return f"{v:,.1f} {u}"
        v /= 1024


def _bar(value, top, width=16):
    """A block-character bar, value scaled to top."""
    if top <= 0:
        return " " * width
    filled = int(round(width * min(value, top) / top))
    return "█" * filled + "░" * (width - filled)


def _header_panel(header):
    up = header["state"] == "Started"
    dot = Text("● ", style="bold green" if up else "bold red")
    line = Text.assemble(
        dot, (f"{header['product']}-nft {__version__}", "bold"),
        (f"  {header['host']}", "cyan"),
        (f"   {'running' if up else header['state']}",
         "green" if up else "red"),
        (f"   {header['when']}", "dim"))
    return Panel(line, box=box.ROUNDED, style="blue")


def _iface_table(ifaces):
    t = Table(title="Interfaces", box=box.SIMPLE_HEAVY, expand=True,
              title_style="bold")
    t.add_column("interface", style="cyan", no_wrap=True)
    t.add_column("zone", style="magenta", no_wrap=True)
    t.add_column("down", justify="right")
    t.add_column("", justify="left")
    t.add_column("up", justify="right")
    top = max([1] + [max(i["rx_bps"], i["tx_bps"]) for i in ifaces])
    for i in ifaces:
        t.add_row(i["iface"], i["zone"],
                  Text(_human_bps(i["rx_bps"]), style="green"),
                  Text(_bar(max(i["rx_bps"], i["tx_bps"]), top), style="green"),
                  Text(_human_bps(i["tx_bps"]), style="yellow"))
    return t


def _zone_table(zones):
    t = Table(title="Zone traffic (since load)", box=box.SIMPLE_HEAVY,
              expand=True, title_style="bold")
    t.add_column("pair", style="cyan", no_wrap=True)
    t.add_column("rate", justify="right")
    t.add_column("total", justify="right")
    t.add_column("packets", justify="right")
    for z in zones:
        t.add_row(z["pair"], _human_bps(z["bps"]), _human_bytes(z["bytes"]),
                  f"{z['pkts']:,}")
    return t


def _deny_table(denies):
    t = Table(title="Denied", box=box.SIMPLE_HEAVY, expand=True,
              title_style="bold red")
    t.add_column("pair", style="cyan", no_wrap=True)
    t.add_column("packets", justify="right", style="red")
    t.add_column("bytes", justify="right", style="red")
    for d in denies:
        t.add_row(d["pair"], f"{d['pkts']:,}", _human_bytes(d["bytes"]))
    return t


def render_frame(data, header):
    """Build the renderable for one frame. Pure function of the sample."""
    parts = [_header_panel(header), _iface_table(data["ifaces"])]
    if data["counters_on"]:
        parts.append(_zone_table(data["zones"]))
        if data["denies"]:
            parts.append(_deny_table(data["denies"]))
    else:
        parts.append(Panel(
            Text("Zone traffic and deny figures need COUNTERS=Yes in "
                 "shorewall.conf, then reload.", style="dim"),
            box=box.ROUNDED))
    parts.append(Text("q or Ctrl-C to quit", style="dim"))
    return Group(*parts)


def _header(family):
    product = "Shorewall6" if family == 6 else "Shorewall"
    vardir = ("/var/lib/shorewall6-nft" if family == 6
              else "/var/lib/shorewall-nft")
    vardir = os.environ.get("SWNFT_VARDIR", vardir)
    try:
        with open(os.path.join(vardir, "state")) as f:
            state = (f.read().split() or ["Cleared"])[0]
    except OSError:
        state = "Cleared"
    return {"product": product, "host": socket.gethostname(),
            "state": state, "when": time.strftime("%H:%M:%S")}


def run(family, interval, once=False):
    """The live loop. once renders a single frame and returns, for scripting
    and tests."""
    from .cli import _monitor_sample
    console = Console()
    prev = {}
    if once:
        data, _ = _monitor_sample(family, prev, interval)
        console.print(render_frame(data, _header(family)))
        return 0
    from rich.live import Live
    empty = {"ifaces": [], "zones": [], "denies": [], "counters_on": False}
    with Live(render_frame(empty, _header(family)), console=console,
              screen=True, refresh_per_second=4) as live:
        try:
            while True:
                data, prev = _monitor_sample(family, prev, interval)
                live.update(render_frame(data, _header(family)))
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
    return 0
