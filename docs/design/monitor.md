# shorewall monitor: a live view of the firewall

## The goal

Bring back `shorewall monitor`, and add a second gear.

- `shorewall monitor` is the classic view, the equivalent of upstream's: a
  screen that refreshes on an interval, showing the firewall state and the
  recent log hits. Pure stdlib, always available.
- `shorewall monitor fancy` is a modern TUI, panels of live per-interface
  throughput, a zone-to-zone traffic matrix and a deny counter, in the spirit
  of btop. It uses a real TUI library, but the package never depends on one.

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
fancy lights up. The library is textual (or rich); the import is behind a small
shim so the choice can change without touching the command.

The library is rich. It renders a genuinely nice dashboard (panels, coloured
rate bars, a zone matrix), it is packaged by the distros (python3-rich), so the
install hint is a clean `apt`/`dnf install`, and it renders headlessly into a
string, so the frame is testable. The import sits behind a shim, so the choice
can change (textual for a full interactive app) without touching the command.
The hint is printed, never run for the admin. A full interactive TUI (textual)
is a possible later upgrade on the same optional-import path.

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
- Fancy: with the TUI library absent, `monitor fancy` prints the install hint
  and exits without a traceback. The render itself is exercised only where the
  library is present.

## Phasing

- Phase 1. The COUNTERS setting and emission. The classic `monitor` command,
  the verb registration, tests. A working `shorewall monitor` and the counter
  foundation.
- Phase 2. Done. The fancy TUI (monitor_tui.py, rich) with a header, a
  per-interface throughput table with rate bars, the zone-traffic table and a
  deny table, reading /proc/net/dev and the COUNTERS counters. rich is imported
  lazily; absent, `monitor fancy` prints the install hint. The data layer is
  pure stdlib in cli (testable without rich); the render is a pure function of
  the sample, tested headlessly where rich is present (monitor-tui-unit) and
  skipped where it is not.
