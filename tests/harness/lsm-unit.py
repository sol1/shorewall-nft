#!/usr/bin/env python3
# Prove the link-monitor state machine and config parser without sending
# a packet: scripted probe results drive the hysteresis, quorum and
# latency logic.
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft.lsm import Monitor, MonitorCfg, parse_lsm, run  # noqa: E402

fails = 0


def ok(name):
    print("PASS", name)


def bad(name):
    global fails
    print("FAIL", name)
    fails += 1


def cfg(**kw):
    base = dict(name="isp1", interface="eth0", targets=["1.1.1.1"])
    base.update(kw)
    return MonitorCfg(**base)


# 1. Down hysteresis: down only after `down` consecutive failures.
m = Monitor(cfg(down=3, up=3), probe=lambda *a: (False, None, 100))
seq = [m.record(False) for _ in range(3)]
(ok if seq == [None, None, "down"] else bad)("down after 3 failures")

# 2. A single success mid-streak resets the fail run.
m = Monitor(cfg(down=3), probe=lambda *a: (False, None, 100))
m.record(False); m.record(False); m.record(True)
(ok if m.record(False) is None and m.state == "up"
 else bad)("one success resets the fail run")

# 3. Up hysteresis: up only after `up` consecutive successes.
m = Monitor(cfg(up=3, down=1))
m.record(False)  # -> down (down=1)
seq = [m.record(True) for _ in range(3)]
(ok if m.state == "up" and seq == [None, None, "up"]
 else bad)("up after 3 successes")

# 4. Reliability quorum: 2 targets, need 2, only 1 answers -> failure.
answers = {"a": True, "b": False}
def probe(t, *a):
    return (answers[t], 5.0 if answers[t] else None, 0 if answers[t] else 100)
c = cfg(targets=["a", "b"], reliability=2, down=1)
m = Monitor(c, probe=probe)
(ok if m.check() == "down" else bad)("quorum: 1 of 2 is a failure")

c = cfg(targets=["a", "b"], reliability=1, down=1)
m = Monitor(c, probe=probe)
(ok if m.check() is None and m.state == "up"
 else bad)("quorum: 1 of 2 meets reliability 1")

# 5. Latency degradation: reachable but over the threshold counts as down.
c = cfg(targets=["a"], max_latency=100, down=1)
m = Monitor(c, probe=lambda *a: (True, 250.0, 0))
(ok if m.check() == "down" else bad)("high latency trips failover")

m = Monitor(cfg(targets=["a"], max_latency=100, down=1),
            probe=lambda *a: (True, 20.0, 0))
(ok if m.check() is None else bad)("latency under the threshold stays up")

# 5b. Loss degradation: reachable but over the loss threshold counts down.
m = Monitor(cfg(targets=["a"], max_loss=50, down=1),
            probe=lambda *a: (True, 5.0, 60))
(ok if m.check() == "down" else bad)("high loss trips failover")

# 6. Config parse: defaults, gateway fallback, interface fallback.
import tempfile  # noqa: E402
with tempfile.NamedTemporaryFile("w", suffix=".lsm", delete=False) as f:
    f.write("?PROVIDER isp1\ncheck -\ninterval 10\ndown 5\n"
            "?PROVIDER lte\ncheck 1.1.1.1 8.8.8.8\nmetered yes\n")
    path = f.name
mons = {m.name: m for m in parse_lsm(
    path, {"isp1": ("eth0", "203.0.113.1"), "lte": ("wwan0", "")})}
os.unlink(path)
(ok if mons["isp1"].targets == ["203.0.113.1"] and mons["isp1"].interval == 10
 and mons["isp1"].down == 5 and mons["isp1"].interface == "eth0"
 else bad)("parse: gateway and interface defaults")
(ok if mons["lte"].targets == ["1.1.1.1", "8.8.8.8"] and mons["lte"].metered
 else bad)("parse: explicit targets and metered flag")

# 7. run() logs a startup line and a per-provider heartbeat even when no
# state changes, so the journal shows the monitor is alive.
logs = []
hb = Monitor(cfg(name="isp1", targets=["a"]), probe=lambda *a: (True, 5.0, 0))
run([hb], apply=lambda name, state: None, once=True, clock=lambda: 0.0,
    log=logs.append)
(ok if any("monitoring isp1" in m for m in logs)
 and any("isp1 up" in m for m in logs)
 else bad)("run: logs a startup line and a heartbeat")

sys.exit(1 if fails else 0)
