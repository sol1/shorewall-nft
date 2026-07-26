"""The fancy monitor, `shorewall monitor fancy`, an interactive textual app.

Imported only when textual is installed, so the package never depends on it
(textual bundles rich). It shows a zone-flow diagram, a hub with one spoke per
zone weighted by that zone's traffic, and an options menu to choose which zones
appear. All data comes from the COUNTERS counters and /proc/net/dev, no
sniffing. The diagram render is a pure function of the sample, so it renders
headlessly for --once and for tests.
"""
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.console import Group
from rich import box as rbox

from .cli import _read_counters, _confdir, _iface_bytes, _zone_map

_COLORS = ["orange3", "deep_pink3", "cyan", "green", "yellow1",
           "magenta", "blue", "red", "spring_green1", "gold1"]


# --- data: per-zone traffic from the pair counters -----------------------

def _zones_and_pairs(family):
    """(zone names, {(z1, z2): chain}) from the config, so a counter chain
    name like net2loc can be split back into its zones."""
    try:
        from .compile import load
        cfg = load(_confdir(family), family)
        zones = [z.name for z in cfg.zones if z.type != "firewall"]
        allz = [z.name for z in cfg.zones]
    except Exception:                              # noqa: BLE001
        return [], {}
    pairs = {}
    # A chain is z1 "2" z2; disambiguate with the known zone set.
    for a in allz:
        for b in allz:
            pairs[f"{a}2{b}"] = (a, b)
    return zones, pairs


def zone_flows(family, prev, interval):
    """One sample: per-zone in/out byte rates from the t_ counters, the zone
    list, per-interface rates from /proc/net/dev, and the top denied chains
    from the d_ counters. All rates are differenced against prev. Returns
    (data, next_prev)."""
    zones, pairs = prev.get("zp") or _zones_and_pairs(family)
    zmap = prev.get("zmap") or _zone_map(family)
    cur = _read_counters(family)
    cur_if = _iface_bytes()
    span = max(interval, 1)
    prevc, previf = prev.get("c", {}), prev.get("if", {})

    def crate(name):
        cbytes = cur.get(name, (0, 0))[1]
        pbytes = prevc.get(name, (0, 0))[1] if name in prevc else cbytes
        return max(0, cbytes - pbytes) * 8 / span

    flows = {z: [0.0, 0.0] for z in zones}          # [in_bps, out_bps]
    denies = []
    for name, (packets, _b) in cur.items():
        if name.startswith("t_"):
            z1, z2 = pairs.get(name[2:], (None, None))
            r = crate(name)
            if z1 in flows:
                flows[z1][1] += r                   # z1 -> z2 is z1 out
            if z2 in flows:
                flows[z2][0] += r                   # ... and z2 in
        elif name.startswith("d_") and packets:
            z1, z2 = pairs.get(name[2:], (name[2:], None))
            denies.append((f"{z1}→{z2}" if z2 else name[2:], packets))
    denies.sort(key=lambda t: -t[1])

    ifaces = []
    for name in sorted(cur_if):
        if name == "lo" or (zmap and name not in zmap):
            continue
        rx, tx = cur_if[name]
        prx, ptx = previf.get(name, (None, None))
        rxb = max(0, rx - prx) * 8 / span if prx is not None else 0.0
        txb = max(0, tx - ptx) * 8 / span if ptx is not None else 0.0
        ifaces.append((name, zmap.get(name, "-"), rxb, txb))

    data = {"zones": zones,
            "flows": {z: tuple(v) for z, v in flows.items()},
            "counters_on": bool(cur), "denies": denies[:5], "ifaces": ifaces}
    return data, {"c": cur, "if": cur_if, "zp": (zones, pairs), "zmap": zmap}


# --- diagram render (rich renderable), pure function of the data ---------

def _human_bps(bps):
    v = float(bps)
    for u in ("b", "Kb", "Mb", "Gb", "Tb"):
        if v < 1000 or u == "Tb":
            return f"{v:,.0f} {u}/s"
        v /= 1000


def _short(bps):
    """Compact rate for a node label: 85M, 500K, 0."""
    v = float(bps)
    for u in ("", "K", "M", "G", "T"):
        if v < 1000 or u == "T":
            return f"{v:.0f}{u}"
        v /= 1000


def _weight(bps):
    """Line weight by rate: heavy, medium, light."""
    mb = bps / 1e6
    if mb >= 20:
        return "┃", "━"
    if mb >= 2:
        return "│", "─"
    return "╎", "┄"


# cardinal placement for up to four zones
_LAYOUT = {1: ["N"], 2: ["W", "E"], 3: ["N", "W", "E"],
           4: ["N", "S", "W", "E"]}


def render_flow(data, selected=None, width=74):
    """The zone-flow diagram as a rich renderable. A central fw hub with one
    spoke per zone, each spoke weighted by that zone's traffic. selected
    filters which zones appear (default all). width lets the diagram shrink
    when a sidebar is open or the terminal is narrow."""
    zones = [z for z in data["zones"]
             if selected is None or z in selected]
    if not zones:
        return Panel(Text("No zones selected. Press o for options.",
                          style="dim"), box=rbox.ROUNDED)
    if len(zones) > 4:
        return _bar_list(data, zones)

    W, H = max(52, min(96, width)), 21
    cx, cy = W // 2, H // 2
    grid = [[(" ", None) for _ in range(W)] for _ in range(H)]

    def put(x, y, ch, st=None):
        if 0 <= x < W and 0 <= y < H:
            grid[y][x] = (ch, st)

    def txt(x, y, s, st=None):
        for i, ch in enumerate(s):
            put(x + i, y, ch, st)

    def node(ncx, ncy, name, label, st):
        """Draw a two-line box centred on (ncx, ncy). Return its outer
        extent (x0, y0, width, height)."""
        w = max(len(name), len(label)) + 2       # inner width
        x0, y0 = ncx - (w + 2) // 2, ncy - 2
        txt(x0, y0, "╭" + "─" * w + "╮", st)
        txt(x0, y0 + 1, "│" + name.center(w) + "│", st)
        txt(x0, y0 + 2, "│" + label.center(w) + "│", st)
        txt(x0, y0 + 3, "╰" + "─" * w + "╯", st)
        return x0, y0, w + 2, 4

    fx0, fy0, fbw, fbh = node(cx, cy, "fw", "firewall", "bold white")
    for zone, side in zip(zones, _LAYOUT[len(zones)]):
        color = _COLORS[data["zones"].index(zone) % len(_COLORS)]
        inb, outb = data["flows"].get(zone, (0, 0))
        vh, hh = _weight(max(inb, outb))
        label = f"↓{_short(inb)} ↑{_short(outb)}"
        bw = max(len(zone), len(label)) + 4          # outer width
        if side == "N":
            _, zy0, _, zbh = node(cx, 3, zone, label, color)
            for y in range(zy0 + zbh, fy0):
                put(cx, y, vh, color)
        elif side == "S":
            zx0, zy0, _, _ = node(cx, H - 3, zone, label, color)
            for y in range(fy0 + fbh, zy0):
                put(cx, y, vh, color)
        elif side == "W":
            zx0, _, _, _ = node(2 + bw // 2, cy, zone, label, color)
            for x in range(zx0 + bw, fx0):
                put(x, cy, hh, color)
        elif side == "E":
            ecx = W - 3 - bw + bw // 2
            zx0, _, _, _ = node(ecx, cy, zone, label, color)
            for x in range(fx0 + fbw, zx0):
                put(x, cy, hh, color)

    body = Text()
    for row in grid:
        for ch, st in row:
            body.append(ch, style=st)
        body.append("\n")
    note = "" if data["counters_on"] else \
        "  (set COUNTERS=Yes and reload for live figures)"
    return Panel(body, title=f"zone traffic flow{note}",
                 box=rbox.ROUNDED, border_style="blue")


def _bar_list(data, zones):
    t = Text()
    top = max([1.0] + [max(data["flows"].get(z, (0, 0))) for z in zones])
    for z in zones:
        inb, outb = data["flows"].get(z, (0, 0))
        color = _COLORS[data["zones"].index(z) % len(_COLORS)]
        bar = "█" * int(round(20 * max(inb, outb) / top))
        t.append(f"{z:>10} ", style=color)
        t.append(f"{bar:<20} ", style=color)
        t.append(f"↓{_human_bps(inb)}  ↑{_human_bps(outb)}\n", style="dim")
    return Panel(t, title="zone traffic", box=rbox.ROUNDED,
                 border_style="blue")


def render_status(data):
    """A compact strip below the diagram: per-interface rates and the top
    denied chains. Interface rates come from /proc/net/dev, so they show even
    when COUNTERS is off."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="left")
    grid.add_column(justify="left")
    grid.add_column(justify="right")
    grid.add_column(justify="right")
    grid.add_row("interface", "zone", "in", "out", style="bold")
    for name, zone, rxb, txb in data.get("ifaces", [])[:6]:
        grid.add_row(name, zone, _human_bps(rxb), _human_bps(txb))
    if len(data.get("ifaces", [])) == 0:
        grid.add_row("(no interfaces)", "", "", "", style="dim")
    parts = [grid]
    if data.get("denies"):
        line = Text("denied  ", style="bold red")
        line.append("   ".join(f"{lbl} {pk:,}" for lbl, pk in data["denies"]),
                    style="red")
        parts.append(line)
    return Panel(Group(*parts), title="interfaces / denied",
                 box=rbox.ROUNDED, border_style="grey37")


# --- the interactive app -------------------------------------------------

def build_app(family, interval):
    """Construct the textual app. Textual is imported here so the module
    still imports (for --once, which needs only rich) when textual is
    absent."""
    from textual.app import App, ComposeResult
    from textual.widgets import Static, Footer, SelectionList
    from textual.widgets.selection_list import Selection
    from textual.containers import Horizontal, Vertical

    class MonitorApp(App):
        CSS = """
        #top { height: 1fr; }
        #flow { width: 1fr; padding: 0 1; content-align: center middle; }
        #status { height: auto; padding: 0 1; }
        #zones { width: 30; border: round $accent; display: none; }
        #zones.shown { display: block; }
        """
        BINDINGS = [("q", "quit", "Quit"), ("o", "options", "Zones"),
                    ("a", "all_zones", "All")]

        def __init__(self):
            super().__init__()
            self._family = family
            self._interval = interval
            self._prev = {}
            self._data = {"zones": [], "flows": {}, "counters_on": False,
                          "denies": [], "ifaces": []}
            self._selected = None

        def compose(self) -> ComposeResult:
            with Vertical():
                with Horizontal(id="top"):
                    yield Static(id="flow")
                    yield SelectionList(id="zones")
                yield Static(id="status")
            yield Footer()

        def on_mount(self):
            self._refresh()
            zl = self.query_one("#zones", SelectionList)
            zl.border_title = "zones"
            if self._data["zones"]:
                zl.add_options(
                    [Selection(z, z, True) for z in self._data["zones"]])
            self.set_interval(self._interval, self._refresh)

        def _flow_width(self):
            try:
                w = self.query_one("#flow", Static).size.width - 2
            except Exception:                       # noqa: BLE001
                w = 0
            return w if w > 20 else 74

        def _draw(self):
            self.query_one("#flow", Static).update(
                render_flow(self._data, self._selected, self._flow_width()))
            self.query_one("#status", Static).update(render_status(self._data))

        def _refresh(self):
            data, self._prev = zone_flows(self._family, self._prev,
                                          self._interval)
            self._data = data
            if self._selected is None:
                self._selected = set(data["zones"])
            self._draw()

        def on_resize(self, _event):
            self._draw()

        def action_options(self):
            zl = self.query_one("#zones", SelectionList)
            zl.toggle_class("shown")
            if zl.has_class("shown"):
                if zl.highlighted is None and zl.option_count:
                    zl.highlighted = 0
                zl.focus()
            else:
                self.set_focus(None)

        def action_all_zones(self):
            zl = self.query_one("#zones", SelectionList)
            zl.select_all()

        def on_selection_list_selected_changed(self, event):
            self._selected = set(event.selection_list.selected)
            self._draw()

    return MonitorApp()


def run(family, interval, once=False):
    """Launch the interactive monitor, or render one frame for --once."""
    if once:
        from rich.console import Console
        data, _ = zone_flows(family, {}, interval)
        con = Console()
        con.print(render_flow(data))
        con.print(render_status(data))
        return 0
    build_app(family, interval).run()
    return 0
