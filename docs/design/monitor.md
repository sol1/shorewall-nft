# shorewall monitor: a live view of the firewall

## The goal

Bring back `shorewall monitor`, and add a second gear.

- `shorewall monitor` is the classic view, the equivalent of upstream's: a
  screen that refreshes on an interval, showing the firewall state and the
  recent log hits. Pure stdlib, always available.
- `shorewall monitor fancy` is a modern interactive TUI. The centre is a
  zone-flow diagram: the firewall as a hub with one spoke per zone, each spoke
  weighted by that zone's traffic, in the spirit of a home energy-flow widget.
  Below it, a strip of per-interface throughput and the top denied chains.
  Press `o` to open a zone selector and the diagram re-lays-out around the
  zones you pick. It uses a real TUI library, but the package never depends on
  one.

Both run on the firewall host, where the Python `shorewall` command already
lives. The generated firewall wrapper, which stays Python-free, is untouched.

## No sniffing

Everything is read from what the kernel already counts:

- Per-interface throughput from /proc/net/dev, differenced over the refresh
  interval. Interfaces are labelled with their zone from the configuration.
- Zone-to-zone traffic and deny counts from netfilter counters, read with
  `nft -j list ...` and parsed as JSON.
- The recent log hits from the kernel log, matching our
  `shorewall:<chain>:<disposition>:` prefixes.

No packet capture, no libpcap, no conntrack dump.

## Counters, gated by a setting

The ruleset carries no counters today except on accounting rules. So the
zone-to-zone and deny figures need the compiler to emit counters, and that is
opt-in, off by default, so a box that never monitors pays nothing.

`COUNTERS=Yes` in shorewall.conf turns it on. When set, the emitter adds:

- A named counter at the head of each zone-pair chain (net2loc, fw2net, ...),
  counting everything that zone pair passes. This is the traffic figure.
- A named counter on each policy DROP and REJECT, counting what a zone pair
  denies. This is the deny figure.

Named counters, declared in the table, so monitor reads them by name with
`nft -j list counters table ...` without walking the whole ruleset. They reset
on a reload, since the table is replaced; monitor shows counts since the last
load, which is what an operator expects.

Without `COUNTERS=Yes`, monitor still shows per-interface throughput, state and
the log, and notes that zone figures need the setting.

## The fancy TUI, optional and install-on-demand

The package must not grow a dependency for a feature most installs will not
use. So `monitor fancy` imports the TUI library lazily. If it is not installed,
it does not fail obscurely: it prints what to install and how, and points at
plain `shorewall monitor` in the meantime. Once the admin installs the library,
fancy lights up. The hint is printed, never run for the admin.

The interactive app uses textual. A menu that selects zones and re-lays-out
the diagram needs input handling, screens and widgets, which rich alone does
not do; textual does, and it renders rich content inside its widgets, so the
diagram is a rich renderable painted into a textual `Static`. textual is not
always distro-packaged, so the hint leads with `pipx install textual`. textual
pulls in rich as a dependency.

There is one lighter path. `monitor fancy --once`, and any non-tty stdout,
prints a single static snapshot of the diagram and the interface strip. That
needs only rich, not textual, so a scripted snapshot works with the smaller,
distro-packaged library, and the frame renders headlessly into a string, so it
is testable. So the import gate is: interactive needs textual, `--once` needs
rich.

## The zone-flow diagram

The diagram is a character grid drawn with box-drawing lines, a pure function
of one data sample so it renders headlessly for tests and for `--once`.

- The firewall is a box in the centre. Each selected zone is a box placed
  north, south, west or east, with a spoke to the hub. Two zones sit east and
  west, three add north, four fill all four sides. More than four falls back to
  a labelled bar list, since a hub diagram gets crossed and unreadable, and few
  firewalls have that many zones in view at once.
- A spoke's weight shows the zone's traffic: heavy line above 20 Mb/s, medium
  above 2 Mb/s, light below. Each zone box carries `↓in ↑out` compact rates.
  The zone's in is the sum of the counters into it, its out the sum out of it.
- The zone selector (`o`) is a checkbox list in a side panel. Toggling a zone
  redraws the diagram live. `a` selects all. The diagram width adapts, so the
  side panel does not clip it.

## Classic monitor

A refresh loop, stdlib only:

- Clear the screen, print a header (product, host, state, compiled-from), the
  rule counts, and the multi-ISP posture if any, the same data `shorewall
  status` prints.
- Below it, the last N log lines matching our prefixes, newest at the bottom,
  read from journalctl if present, else /var/log, else dmesg.
- If COUNTERS is on, a short zone-traffic and deny summary.
- Sleep the interval, repeat. Ctrl-C exits cleanly.

`--once` prints a single frame and exits, and a non-tty stdout implies `--once`,
so the command is scriptable and testable.

## Testing

- COUNTERS: a corpus or forms case compiled with COUNTERS=Yes has a counter on
  the zone-pair chains and the policy drops, the ruleset still loads with
  nft -c, and the counters are absent with the setting off. Byte-identical
  corpus output when off.
- Classic: `monitor --once` against a scratch state and a fake log source
  prints the header and the log lines, and exits 0.
- Fancy: with textual absent, `monitor fancy` prints the install hint and exits
  without a traceback; with rich absent, `monitor fancy --once` prints the rich
  hint. The renderers (render_flow, render_status) are pure functions of the
  sample, tested headlessly where rich is present. The interactive behaviour,
  the zone selector toggling zones and the diagram redrawing, is tested with the
  textual test pilot where textual is present (monitor-tui-unit).

## Phasing

- Phase 1. The COUNTERS setting and emission. The classic `monitor` command,
  the verb registration, tests. A working `shorewall monitor` and the counter
  foundation.
- Phase 2. Done. The first fancy TUI (monitor_tui.py, rich) with a header, a
  per-interface throughput table with rate bars, a zone-traffic table and a
  deny table, reading /proc/net/dev and the COUNTERS counters, rendered
  headlessly and tested where rich is present.
- Phase 3. Done. The interactive fancy TUI (textual). The zone-flow diagram
  (render_flow) as the centre, the interface and deny strip (render_status)
  below, and the `o` zone selector that redraws the diagram live. textual is
  imported lazily for the interactive path; `monitor fancy --once` keeps the
  rich-only static snapshot. Data is aggregated per zone in zone_flows from the
  same COUNTERS counters. Tested with the textual test pilot where textual is
  present, headless renders where only rich is, and the install hints where
  neither is.
