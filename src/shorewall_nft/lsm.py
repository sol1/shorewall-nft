"""Link status monitor.

A small daemon that probes each provider's gateway (or a target reached
through the link), tracks up and down with hysteresis and a reliability
quorum, and enables or disables the provider through the routing seam on
a state change. Pure stdlib. The state machine is separated from the
probe so it can be tested without sending a packet.

Config is /etc/shorewall/lsm (and /etc/shorewall6/lsm), one block per
monitored provider. The provider's interface and gateway come from the
providers file; this file adds only the monitoring policy. See
docs/design/multi-isp-lsm.md section 10.
"""
import os
import re
import subprocess
import time
from dataclasses import dataclass, field

DEFAULTS = {
    "method": "ping",
    "check": "-",        # target; - means the provider gateway
    "interface": "-",    # - means the provider interface
    "interval": 5,
    "timeout": 3,
    "count": 1,
    "reliability": 1,    # of the targets, how many must answer
    "up": 3,             # consecutive good checks to declare up
    "down": 3,           # consecutive failed checks to declare down
    "max_latency": 0,    # ms, 0 = ignore
    "max_loss": 0,       # percent, 0 = ignore
    "metered": "no",
    "dial": "-",
    "hangup": "-",
}
_INT_KEYS = ("interval", "timeout", "count", "reliability", "up", "down",
             "max_latency", "max_loss")


@dataclass
class MonitorCfg:
    name: str
    interface: str
    targets: list          # ip/host list to probe
    method: str = "ping"
    interval: int = 5
    timeout: int = 3
    count: int = 1
    reliability: int = 1
    up: int = 3
    down: int = 3
    max_latency: int = 0
    max_loss: int = 0
    metered: bool = False
    dial: str = ""
    hangup: str = ""


def parse_lsm(path, providers):
    """Parse /etc/shorewall/lsm into MonitorCfg objects, one per
    ?PROVIDER block. providers maps a provider name to (interface,
    gateway) so check/interface defaults can resolve."""
    blocks = {}
    cur = None
    with open(path) as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("?PROVIDER"):
                cur = line.split()[1]
                blocks[cur] = dict(DEFAULTS)
                continue
            if cur is None:
                raise ValueError(f"lsm: setting before any ?PROVIDER: {line}")
            parts = line.split(None, 1)
            key = parts[0].lower()
            val = parts[1].strip() if len(parts) > 1 else ""
            if key not in DEFAULTS:
                raise ValueError(f"lsm: unknown setting {key}")
            blocks[cur][key] = val
    mons = []
    for name, b in blocks.items():
        iface, gw = providers.get(name, ("", ""))
        interface = iface if b["interface"] == "-" else b["interface"]
        check = b["check"]
        targets = [gw] if check == "-" else [t for t in re.split(r"[,\s]+",
                                                                  check) if t]
        kw = {k: int(b[k]) for k in _INT_KEYS}
        mons.append(MonitorCfg(
            name=name, interface=interface, targets=[t for t in targets if t],
            method=b["method"], metered=b["metered"].lower() in ("yes", "1"),
            dial="" if b["dial"] == "-" else b["dial"],
            hangup="" if b["hangup"] == "-" else b["hangup"], **kw))
    return mons


def probe_once(target, interface, timeout):
    """One ICMP probe bound to the interface. Returns (ok, rtt_ms). rtt
    is None on failure. Uses the ping binary so no raw-socket privilege
    is needed."""
    cmd = ["ping", "-n", "-c", "1", "-W", str(timeout)]
    if interface:
        cmd += ["-I", interface]
    cmd.append(target)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return False, None
    m = re.search(r"time=([\d.]+)", r.stdout)
    return True, (float(m.group(1)) if m else None)


class Monitor:
    """Per-provider up/down state machine. record() is pure; poll() adds
    the probe. Starts up, so a provider is not disabled before its first
    check completes."""

    def __init__(self, cfg, probe=probe_once):
        self.cfg = cfg
        self._probe = probe
        self.state = "up"
        self.ok_run = 0
        self.fail_run = 0
        self.rtt = None
        self.loss = 0

    def record(self, ok):
        """Feed one check result. Returns "up" or "down" on a state
        change, else None."""
        if ok:
            self.ok_run += 1
            self.fail_run = 0
            if self.state == "down" and self.ok_run >= self.cfg.up:
                self.state = "up"
                return "up"
        else:
            self.fail_run += 1
            self.ok_run = 0
            if self.state == "up" and self.fail_run >= self.cfg.down:
                self.state = "down"
                return "down"
        return None

    def check(self):
        """Probe every target, apply the reliability quorum and the
        latency threshold, and feed the result to the state machine."""
        c = self.cfg
        answered = 0
        rtts = []
        for target in c.targets:
            ok, rtt = self._probe(target, c.interface, c.timeout)
            if ok:
                answered += 1
                if rtt is not None:
                    rtts.append(rtt)
        self.rtt = max(rtts) if rtts else None
        total = len(c.targets) or 1
        self.loss = round(100 * (total - answered) / total)
        reachable = answered >= c.reliability
        degraded = bool(c.max_latency and self.rtt and self.rtt > c.max_latency)
        return self.record(reachable and not degraded)


def load_providers(confdir, family):
    from .compile import load
    cfg = load(confdir, family)
    return {p.name: (p.interface, p.gateway) for p in cfg.providers}


def write_status(status_dir, mon, now):
    os.makedirs(status_dir, exist_ok=True)
    rtt = f"{mon.rtt:.1f}ms" if mon.rtt is not None else "-"
    with open(os.path.join(status_dir, mon.cfg.name + ".status"), "w") as f:
        f.write(f"{mon.state} rtt={rtt} loss={mon.loss}% at={int(now)}\n")


def build_monitors(confdir, family, probe=probe_once):
    """Monitors from the lsm file, or [] if there is no lsm file."""
    path = os.path.join(confdir, "lsm")
    if not os.path.isfile(path):
        return []
    providers = load_providers(confdir, family)
    return [Monitor(c, probe) for c in parse_lsm(path, providers)]


def run(monitors, apply, status_dir=None, once=False,
        sleep=time.sleep, clock=time.time):
    """The monitor loop. apply(name, state) drives the seam on a
    transition. Injected sleep/clock/probe keep it testable."""
    if not monitors:
        return
    interval = min(m.cfg.interval for m in monitors)
    while True:
        for m in monitors:
            change = m.check()
            if status_dir:
                write_status(status_dir, m, clock())
            if change:
                apply(m.cfg.name, change)
        if once:
            return
        sleep(interval)
