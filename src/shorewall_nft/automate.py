"""JSON automation interface: `shorewall automate <verb>`.

A stable, machine-readable contract for tools like Ansible. Every verb
prints one JSON object to stdout and nothing else; human progress and
errors go to stderr. Mutating verbs take --check to report what would
change without changing it, and never prompt. See docs/design/automate.md.
"""
import contextlib
import difflib
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from . import __version__, capabilities, cli
from .errors import ConfigError

SCHEMA = 1
GITHUB_LATEST = os.environ.get(
    "SWNFT_GITHUB_LATEST_URL",
    "https://api.github.com/repos/sol1/shorewall-nft/releases/latest")


def _fam(family):
    return "ipv6" if family == 6 else "ipv4"


def _emit(command, family, ok, changed, result,
          warnings=None, errors=None, exit_code=0):
    """Write the one JSON object this verb produces and return its exit code."""
    print(json.dumps({
        "schema": SCHEMA,
        "command": command,
        "ok": ok,
        "changed": changed,
        "family": _fam(family),
        "result": result,
        "warnings": warnings or [],
        "errors": errors or [],
    }))
    return exit_code


def _cfgerr(e):
    return {"file": getattr(e, "path", None),
            "line": getattr(e, "lineno", None),
            "message": str(e)}


@contextlib.contextmanager
def _quiet_stdout():
    """Keep stdout pure JSON. Redirect at the file-descriptor level, not just
    sys.stdout, so output from the firewall wrapper, systemctl and other
    subprocesses (which inherit fd 1) also goes to stderr."""
    sys.stdout.flush()
    saved_fd = os.dup(1)
    os.dup2(2, 1)
    saved = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout.flush()
        sys.stdout = saved
        os.dup2(saved_fd, 1)
        os.close(saved_fd)


def _compile_temp(confdir, family):
    """Compile confdir to a temporary ruleset. Returns (path, None) or
    (None, ConfigError). The caller unlinks the path."""
    fd, path = tempfile.mkstemp(suffix=".nft")
    os.close(fd)
    try:
        with _quiet_stdout():
            cli.compile_config(confdir, path, family)
    except ConfigError as e:
        os.unlink(path)
        return None, e
    return path, None


def _vtuple(version):
    parts = []
    for piece in str(version).split("."):
        digits = "".join(c for c in piece if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _newer(candidate, installed):
    return _vtuple(candidate) > _vtuple(installed)


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


# Verbs ------------------------------------------------------------------

def _v_check(family, confdir, check_mode, rest):
    del check_mode, rest
    errors = []
    compiles = False
    nft_ok = False
    path, err = _compile_temp(confdir, family)
    if err:
        errors.append(_cfgerr(err))
    else:
        compiles = True
        try:
            nft = cli._check_ruleset(path, family)
            nft_ok = nft.returncode == 0
            if not nft_ok:
                errors.append({"file": None, "line": None,
                               "message": "nft rejected the generated "
                               "ruleset: " + nft.stderr.strip()[-500:]})
        finally:
            os.unlink(path)
    ok = compiles and nft_ok
    result = {"confdir": confdir, "compiles": compiles, "nft_accepts": nft_ok}
    return _emit("check", family, ok, False, result,
                 errors=errors, exit_code=0 if ok else 1)


def _v_status(family, confdir, check_mode, rest):
    del check_mode, rest
    vardir = cli._vardir(family)
    try:
        with open(os.path.join(vardir, "state")) as f:
            raw = f.read().strip()
    except OSError:
        raw = "Cleared"
    state = raw.split()[0] if raw else "Cleared"
    counts = cli._rule_counts(family)
    loaded = counts is not None
    running = state == "Started" and loaded
    rules = None
    if counts is not None:
        total, nat = counts
        rules = {"total": total, "filter": total - nat, "nat": nat}
    result = {
        "running": running,
        "state": state,
        "stack": "nft",
        "version": __version__,
        "confdir": confdir,
        "loaded": loaded,
        "rules": rules,
    }
    return _emit("status", family, True, False, result,
                 exit_code=0 if running else 3)


def _v_capabilities(family, confdir, check_mode, rest):
    del confdir, check_mode, rest
    capabilities.enable_probe()
    caps = {name: bool(capabilities.lookup(name))
            for name in capabilities.CAPABILITIES}
    return _emit("capabilities", family, True, False, {"capabilities": caps})


def _v_versioncheck(family, confdir, check_mode, rest):
    del confdir, check_mode, rest
    installed = __version__
    latest = None
    warnings = []
    try:
        req = urllib.request.Request(
            GITHUB_LATEST,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "shorewall-nft"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        latest = (data.get("tag_name") or "").lstrip("v") or None
    except (urllib.error.URLError, OSError, ValueError) as e:
        warnings.append({"file": None, "line": None,
                         "message": f"could not reach {GITHUB_LATEST}: {e}"})
    update_available = latest is not None and _newer(latest, installed)
    result = {
        "installed": installed,
        "latest": latest,
        "source": "github",
        "update_available": update_available,
        "up_to_date": latest is not None and not update_available,
        "migration_needed": cli._iptables_has_rules(family),
    }
    return _emit("versioncheck", family, True, False, result,
                 warnings=warnings)


def _v_doctor(family, confdir, check_mode, rest):
    del check_mode, rest
    checks = []

    ver = subprocess.run([cli._nft(), "--version"],
                         capture_output=True, text=True)
    checks.append({"name": "nft", "ok": ver.returncode == 0, "critical": True,
                   "detail": (ver.stdout or ver.stderr).strip()})

    checks.append({"name": "kernel", "ok": True, "critical": False,
                   "detail": os.uname().release})

    sandbox = capabilities._sandbox()
    checks.append({"name": "probe_sandbox", "ok": bool(sandbox),
                   "critical": False,
                   "detail": "conntrack helper probing available" if sandbox
                   else "no user namespace; capabilities use the defaults"})

    legacy = cli._iptables_has_rules(family)
    checks.append({"name": "no_legacy_iptables", "ok": not legacy,
                   "critical": False,
                   "detail": "a classic iptables Shorewall ruleset is present"
                   if legacy else "clean"})

    if os.path.isdir(confdir):
        path, err = _compile_temp(confdir, family)
        if err:
            checks.append({"name": "config_compiles", "ok": False,
                           "critical": True, "detail": str(err)})
        else:
            os.unlink(path)
            checks.append({"name": "config_compiles", "ok": True,
                           "critical": True, "detail": "ok"})
    else:
        checks.append({"name": "config_compiles", "ok": False,
                       "critical": True,
                       "detail": f"no configuration at {confdir}"})

    ready = all(c["ok"] for c in checks if c["critical"])
    return _emit("doctor", family, True, False,
                 {"ready": ready, "checks": checks},
                 exit_code=0 if ready else 3)


def _v_diff(family, confdir, check_mode, rest):
    del check_mode, rest
    vardir = cli._vardir(family)
    current_path = cli._script_path(vardir) + ".nft"
    new_path, err = _compile_temp(confdir, family)
    if err:
        return _emit("diff", family, False, False, {}, errors=[_cfgerr(err)],
                     exit_code=1)
    try:
        with open(new_path) as f:
            new = f.read()
    finally:
        os.unlink(new_path)
    old = ""
    if os.path.exists(current_path):
        with open(current_path) as f:
            old = f.read()
    changed = new != old
    delta = list(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile="current", tofile="compiled"))
    added = sum(1 for ln in delta if ln.startswith("+") and
                not ln.startswith("+++"))
    removed = sum(1 for ln in delta if ln.startswith("-") and
                  not ln.startswith("---"))
    result = {
        "changed": changed,
        "has_current": bool(old),
        "summary": {"added": added, "removed": removed},
        "diff": "".join(delta)[:20000],
    }
    return _emit("diff", family, True, changed, result)


def _v_apply(family, confdir, check_mode, rest):
    del rest
    vardir = cli._vardir(family)
    current_path = cli._script_path(vardir) + ".nft"
    new_path, err = _compile_temp(confdir, family)
    if err:
        return _emit("apply", family, False, False, {}, errors=[_cfgerr(err)],
                     exit_code=1)
    try:
        with open(new_path) as f:
            new = f.read()
    finally:
        os.unlink(new_path)
    new_hash = _sha(new)
    previous_hash = None
    if os.path.exists(current_path):
        with open(current_path) as f:
            previous_hash = _sha(f.read())
    running = cli._rule_counts(family) is not None
    changed = new_hash != previous_hash or not running

    if check_mode:
        result = {"changed": changed, "applied": False,
                  "ruleset_sha256": new_hash, "previous_sha256": previous_hash,
                  "running": running}
        return _emit("apply", family, True, changed, result)
    if not changed:
        result = {"changed": False, "applied": False,
                  "ruleset_sha256": new_hash, "previous_sha256": previous_hash,
                  "running": running}
        return _emit("apply", family, True, False, result)

    with _quiet_stdout():
        try:
            rc = cli._apply(confdir, family, vardir)
        except ConfigError as e:
            return _emit("apply", family, False, False, {},
                         errors=[_cfgerr(e)], exit_code=1)
    ok = rc == 0
    result = {"changed": True, "applied": ok, "ruleset_sha256": new_hash,
              "previous_sha256": previous_hash}
    return _emit("apply", family, ok, True, result, exit_code=0 if ok else 3)


# Detached timer: sleep, then revert only if the rollback marker still exists.
# safe-apply --commit removes the marker (and kills this process) to cancel it.
_TIMER = ("import os,sys,time,subprocess;"
          "t=float(sys.argv[1]);marker=sys.argv[2];revert=sys.argv[3:];"
          "time.sleep(t);"
          "os.path.exists(marker) and subprocess.run(revert)")


def _int_flag(rest, name, default):
    if name in rest:
        i = rest.index(name)
        if i + 1 < len(rest) and rest[i + 1].isdigit():
            return int(rest[i + 1])
    return default


def _service_enabled(service):
    try:
        r = subprocess.run(["systemctl", "is-enabled", service],
                           capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _v_rollback(family, confdir, check_mode, rest):
    del confdir, check_mode, rest
    vardir = cli._vardir(family)
    marker = os.path.join(vardir, "rollback")
    armed = os.path.exists(marker)
    if armed:
        os.unlink(marker)
    with _quiet_stdout():
        rc = cli._revert(vardir, family)
    ok = rc == 0
    return _emit("rollback", family, ok, True,
                 {"reverted": ok, "was_armed": armed},
                 exit_code=0 if ok else 3)


def _v_safe_apply(family, confdir, check_mode, rest):
    vardir = cli._vardir(family)
    marker = os.path.join(vardir, "rollback")

    if "--commit" in rest:
        armed = os.path.exists(marker)
        if armed:
            pid = None
            try:
                with open(marker) as f:
                    pid = json.load(f).get("pid")
            except (OSError, ValueError):
                pid = None
            os.unlink(marker)
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
        return _emit("safe-apply", family, True, False, {"committed": armed})

    timeout = _int_flag(rest, "--timeout", 60)
    new_path, err = _compile_temp(confdir, family)
    if err:
        return _emit("safe-apply", family, False, False, {},
                     errors=[_cfgerr(err)], exit_code=1)
    try:
        with open(new_path) as f:
            new = f.read()
    finally:
        os.unlink(new_path)
    new_hash = _sha(new)
    current_path = cli._script_path(vardir) + ".nft"
    previous_hash = None
    if os.path.exists(current_path):
        with open(current_path) as f:
            previous_hash = _sha(f.read())
    running = cli._rule_counts(family) is not None
    changed = new_hash != previous_hash or not running

    if check_mode or not changed:
        return _emit("safe-apply", family, True, changed,
                     {"changed": changed, "applied": False,
                      "rollback": {"armed": False, "timeout": timeout}})

    with _quiet_stdout():
        try:
            rc = cli._apply(confdir, family, vardir)
        except ConfigError as e:
            return _emit("safe-apply", family, False, False, {},
                         errors=[_cfgerr(e)], exit_code=1)
        if rc != 0:
            cli._revert(vardir, family)
    if rc != 0:
        return _emit("safe-apply", family, False, True,
                     {"changed": True, "applied": False},
                     errors=[{"file": None, "line": None,
                              "message": "the ruleset did not load; reverted"}],
                     exit_code=3)

    deadline = time.time() + timeout
    timer = subprocess.Popen(
        [sys.executable, "-c", _TIMER, str(timeout), marker,
         sys.executable, "-m", "shorewall_nft", "automate", "rollback"],
        env=dict(os.environ, SWNFT_FAMILY=str(family), SWNFT_VARDIR=vardir),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True)
    with open(marker, "w") as f:
        json.dump({"pid": timer.pid, "deadline": deadline,
                   "timeout": timeout}, f)
    return _emit("safe-apply", family, True, True,
                 {"changed": True, "applied": True,
                  "ruleset_sha256": new_hash,
                  "rollback": {"armed": True, "timeout": timeout,
                               "deadline": deadline}})


def _v_migrate(family, confdir, check_mode, rest):
    del rest
    if not os.path.isdir(confdir):
        return _emit("migrate", family, False, False,
                     {"already_migrated": False},
                     errors=[{"file": None, "line": None,
                              "message": f"no configuration at {confdir}"}],
                     exit_code=1)
    compat = [ln.strip() for ln in cli._compat_report(confdir)[0]]
    unsupported = cli._compat_report(confdir)[1]

    path, err = _compile_temp(confdir, family)
    if err:
        return _emit("migrate", family, False, False,
                     {"compat": compat, "unsupported": unsupported},
                     errors=[_cfgerr(err)], exit_code=1)
    try:
        nft = cli._check_ruleset(path, family)
    finally:
        os.unlink(path)
    if nft.returncode != 0:
        return _emit("migrate", family, False, False,
                     {"compat": compat, "unsupported": unsupported},
                     errors=[{"file": None, "line": None,
                              "message": "nft rejected the ruleset: "
                              + nft.stderr.strip()[-300:]}], exit_code=1)
    if unsupported:
        return _emit("migrate", family, False, False,
                     {"compat": compat, "unsupported": unsupported,
                      "handed_over": False},
                     errors=[{"file": None, "line": None,
                              "message": "unsupported files present: "
                              + ", ".join(unsupported)}], exit_code=1)

    service = cli._service(family)
    already = _service_enabled(service) and cli._rule_counts(family) is not None
    if already:
        return _emit("migrate", family, True, False,
                     {"already_migrated": True, "from": "shorewall-nft",
                      "to": "shorewall-nft", "compat": compat,
                      "unsupported": [], "handed_over": False})
    if check_mode:
        return _emit("migrate", family, True, True,
                     {"already_migrated": False, "would_hand_over": True,
                      "compat": compat, "unsupported": []})

    with _quiet_stdout():
        cli._sysd("daemon-reload")
        cli._sysd("enable", service)
        rc = cli.cmd_start([], family)
        loaded = subprocess.run(
            [cli._nft(), "list", "table", *cli.table_for(family).split()],
            capture_output=True).returncode == 0
        cleared = cli._clear_legacy_iptables(family) if rc == 0 and loaded \
            else False
    ok = rc == 0 and loaded
    return _emit("migrate", family, ok, True,
                 {"already_migrated": False, "from": "shorewall-iptables",
                  "to": "shorewall-nft", "compat": compat, "unsupported": [],
                  "handed_over": ok, "cleared_legacy": cleared},
                 exit_code=0 if ok else 3)


VERBS = {
    "check": _v_check,
    "status": _v_status,
    "capabilities": _v_capabilities,
    "versioncheck": _v_versioncheck,
    "doctor": _v_doctor,
    "diff": _v_diff,
    "apply": _v_apply,
    "safe-apply": _v_safe_apply,
    "rollback": _v_rollback,
    "migrate": _v_migrate,
}


def run(args, family):
    if not args:
        return _emit("automate", family, False, False,
                     {"verbs": sorted(VERBS)},
                     errors=[{"file": None, "line": None,
                              "message": "automate needs a verb"}],
                     exit_code=2)
    verb, rest = args[0], args[1:]
    if verb not in VERBS:
        return _emit("automate", family, False, False,
                     {"verbs": sorted(VERBS)},
                     errors=[{"file": None, "line": None,
                              "message": f"unknown automate verb {verb!r}"}],
                     exit_code=2)
    check_mode = "--check" in rest or "--dry-run" in rest
    confdir = cli._confdir(family)
    try:
        return VERBS[verb](family, confdir, check_mode, rest)
    except ConfigError as e:
        return _emit(verb, family, False, False, {}, errors=[_cfgerr(e)],
                     exit_code=1)
