#!/usr/bin/env python3
# The `shorewall automate` JSON contract: every verb must print one parseable
# JSON object to stdout and nothing else, carry the common envelope, use the
# documented exit codes, and honour --check without changing anything. Verbs
# are run as a subprocess so the stdout-is-pure-JSON guarantee is tested for
# real. See docs/design/automate.md.
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")
SRC = os.path.join(REPO, "src")
BASE = os.path.join(REPO, "tests/corpus/0002-one-interface/config")

fails = 0
work = tempfile.mkdtemp(prefix="shorewall-nft-automate-")
confdir = os.path.join(work, "conf")
vardir = os.path.join(work, "var")
shutil.copytree(BASE, confdir)
os.makedirs(vardir)


def check(name, cond):
    global fails
    print("PASS" if cond else "FAIL", name)
    if not cond:
        fails += 1


def run(*verb, confdir=confdir, extra_env=None):
    """Run `shorewall automate <verb>`; return (exit_code, parsed_json).
    Fails the test if stdout is not a single JSON object."""
    env = dict(os.environ, PYTHONPATH=SRC, SWNFT_CONFDIR=confdir,
               SWNFT_VARDIR=vardir, SHOREWALL_NFT_STATIC_CAPS="1")
    if extra_env:
        env.update(extra_env)
    r = subprocess.run([sys.executable, "-m", "shorewall_nft", "automate",
                        *verb], capture_output=True, text=True, env=env)
    try:
        return r.returncode, json.loads(r.stdout)
    except json.JSONDecodeError:
        return r.returncode, None


def envelope_ok(obj):
    return isinstance(obj, dict) and all(
        k in obj for k in ("schema", "command", "ok", "changed", "family",
                            "result", "warnings", "errors"))


# check: a good config compiles and the ruleset loads.
code, o = run("check")
check("check: stdout is one JSON object", o is not None)
check("check: envelope present", o is not None and envelope_ok(o))
check("check: good config ok and exit 0",
      o is not None and o["ok"] is True and code == 0)
check("check: reports compiles and nft_accepts",
      o is not None and o["result"]["compiles"] and o["result"]["nft_accepts"])

# check: a broken config fails with exit 1 and a located error.
bad = os.path.join(work, "bad")
shutil.copytree(BASE, bad)
with open(os.path.join(bad, "rules"), "a") as f:
    f.write("BOGUSACTION net fw\n")
code, o = run("check", confdir=bad)
check("check: broken config exit 1", code == 1)
check("check: broken config not ok, has an error",
      o is not None and o["ok"] is False and len(o["errors"]) >= 1)
check("check: error carries file and line keys",
      o is not None and o["errors"] and "file" in o["errors"][0]
      and "line" in o["errors"][0])

# status: nothing started, so stopped and exit 3.
code, o = run("status")
check("status: stopped exit 3", code == 3)
check("status: not running, stack nft",
      o is not None and o["result"]["running"] is False
      and o["result"]["stack"] == "nft")

# capabilities: the probed map, static here, so a known helper is present.
code, o = run("capabilities")
check("capabilities: map present with a known helper",
      o is not None and o["result"]["capabilities"].get("FTP_HELPER") is True)

# doctor: readiness with per-check critical flags.
code, o = run("doctor")
check("doctor: envelope and checks list",
      o is not None and isinstance(o["result"]["checks"], list)
      and o["result"]["checks"])
check("doctor: each check has the documented shape",
      o is not None and all(
          set(("name", "ok", "critical", "detail")) <= set(c)
          for c in o["result"]["checks"]))
check("doctor: ready is a bool and matches exit",
      o is not None and isinstance(o["result"]["ready"], bool)
      and code == (0 if o["result"]["ready"] else 3))

# diff: no current ruleset yet, so it is all additions and changed.
code, o = run("diff")
check("diff: changed with additions against no current",
      o is not None and o["changed"] is True
      and o["result"]["summary"]["added"] > 0
      and o["result"]["has_current"] is False)

# apply --check: reports it would change but writes nothing.
code, o = run("apply", "--check")
check("apply --check: would change, applied false, exit 0",
      o is not None and o["changed"] is True
      and o["result"]["applied"] is False and code == 0)
check("apply --check: a hash is reported",
      o is not None and len(o["result"]["ruleset_sha256"]) == 64)
check("apply --check: nothing was applied to the vardir",
      not os.path.exists(os.path.join(vardir, "firewall")))

# versioncheck: offline is a success with a null latest and a warning.
code, o = run("versioncheck",
              extra_env={"SWNFT_GITHUB_LATEST_URL": "http://127.0.0.1:9/x"})
check("versioncheck: offline is ok with a warning",
      o is not None and o["ok"] is True and o["result"]["latest"] is None
      and len(o["warnings"]) >= 1)
installed = o["result"]["installed"] if o else "0"

# versioncheck: a newer published release is flagged as an update.
rel = os.path.join(work, "newer.json")
with open(rel, "w") as f:
    json.dump({"tag_name": "v99.0.0"}, f)
code, o = run("versioncheck",
              extra_env={"SWNFT_GITHUB_LATEST_URL": "file://" + rel})
check("versioncheck: a newer release is an available update",
      o is not None and o["result"]["update_available"] is True
      and o["result"]["up_to_date"] is False)

# versioncheck: the installed version is up to date.
rel = os.path.join(work, "same.json")
with open(rel, "w") as f:
    json.dump({"tag_name": "v" + installed}, f)
code, o = run("versioncheck",
              extra_env={"SWNFT_GITHUB_LATEST_URL": "file://" + rel})
check("versioncheck: the installed version is up to date",
      o is not None and o["result"]["update_available"] is False
      and o["result"]["up_to_date"] is True)

# migrate --check: reports it would hand over, changes nothing.
code, o = run("migrate", "--check")
check("migrate --check: would hand over, changed, exit 0",
      o is not None and o["changed"] is True
      and o["result"].get("would_hand_over") is True
      and o["result"].get("already_migrated") is False and code == 0)

# migrate refuses a config with an unsupported file.
uns = os.path.join(work, "unsup")
shutil.copytree(BASE, uns)
with open(os.path.join(uns, "routestopped"), "w") as f:
    f.write("eth0\n")
code, o = run("migrate", confdir=uns)
check("migrate: unsupported file is a located refusal, exit 1",
      code == 1 and o is not None and o["ok"] is False
      and o["result"]["unsupported"] == ["routestopped"])

# safe-apply --check: would change, arms nothing.
code, o = run("safe-apply", "--check")
check("safe-apply --check: changed, not applied, not armed, exit 0",
      o is not None and o["changed"] is True
      and o["result"]["applied"] is False
      and o["result"]["rollback"]["armed"] is False and code == 0)

# safe-apply --commit with nothing armed is a no-op success.
code, o = run("safe-apply", "--commit")
check("safe-apply --commit: nothing armed is committed false, exit 0",
      o is not None and o["result"]["committed"] is False and code == 0)

# rollback with nothing armed still reports the revert it performed.
code, o = run("rollback")
check("rollback: reports was_armed false and a revert",
      o is not None and o["result"]["was_armed"] is False
      and "reverted" in o["result"])

# The stdout guard must hide subprocess output at the fd level, so the
# firewall wrapper's chatter during a real apply cannot corrupt the JSON.
sys.path.insert(0, SRC)
from shorewall_nft import automate as _A  # noqa: E402
capfile = os.path.join(work, "stdout.cap")
with open(capfile, "w") as _cf:
    sys.stdout.flush()          # do not let buffered PASS lines land in capfile
    _saved = os.dup(1)
    try:
        os.dup2(_cf.fileno(), 1)
        with _A._quiet_stdout():
            subprocess.run(["sh", "-c", "echo SUBPROC_NOISE"])
        os.write(1, b"REAL_STDOUT\n")
    finally:
        os.dup2(_saved, 1)
        os.close(_saved)
with open(capfile) as f:
    _cap = f.read()
check("stdout guard hides subprocess output at the fd level",
      "SUBPROC_NOISE" not in _cap and "REAL_STDOUT" in _cap)

# an unknown verb is a usage error listing the verbs.
code, o = run("frobnicate")
check("unknown verb: exit 2, lists verbs",
      code == 2 and o is not None and o["ok"] is False
      and "check" in o["result"]["verbs"])

shutil.rmtree(work, ignore_errors=True)
sys.exit(1 if fails else 0)
