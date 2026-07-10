"""The shorewall command surface.

Verbs match shorewall(8) in name, syntax and semantics. stop means the
safe state, clear opens the firewall, try reverts on failure or
timeout. Verbs that are not implemented yet fail with a message naming
the gap. They must never succeed silently or die with a traceback.
"""
import ipaddress
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time

from . import __version__, capabilities
from .compile import compile_config
from .emit import table_for
from .errors import ConfigError


def _family():
    if os.environ.get("SWNFT_FAMILY") == "6":
        return 6
    if os.path.basename(sys.argv[0]).startswith("shorewall6"):
        return 6
    return 4


def _confdir(family):
    default = "/etc/shorewall6" if family == 6 else "/etc/shorewall"
    return os.environ.get("SWNFT_CONFDIR", default)


def _vardir(family):
    default = ("/var/lib/shorewall6-nft" if family == 6
               else "/var/lib/shorewall-nft")
    path = os.environ.get("SWNFT_VARDIR", default)
    os.makedirs(path, exist_ok=True)
    return path


def _nft():
    return "/usr/sbin/nft" if os.path.exists("/usr/sbin/nft") else "nft"


def _state(vardir, value=None):
    path = os.path.join(vardir, "state")
    if value is None:
        try:
            with open(path) as f:
                return f.read().split()[0]
        except (OSError, IndexError):
            return "Cleared"
    with open(path, "w") as f:
        f.write(f"{value} ({time.strftime('%a %b %e %T %Z %Y')})\n")


def _script_path(vardir):
    return os.path.join(vardir, "firewall")


def _compile_to(confdir, family, script_path):
    ruleset = script_path + ".nft"
    compile_config(confdir, ruleset, family, script_path=script_path)


def _run_script(script_path, *verb):
    r = subprocess.run([script_path, *verb])
    return r.returncode


def _apply(confdir, family, vardir, keep_previous=True):
    """Compile and start. Returns 0 on success."""
    script = _script_path(vardir)
    if keep_previous and os.path.exists(script):
        shutil.copy2(script, script + ".prev")
    _compile_to(confdir, family, script)
    rc = _run_script(script, "start")
    if rc == 0:
        _state(vardir, "Started")
    return rc


def _revert(vardir, family):
    prev = _script_path(vardir) + ".prev"
    if os.path.exists(prev):
        rc = _run_script(prev, "start")
        if rc == 0:
            shutil.copy2(prev, _script_path(vardir))
            _state(vardir, "Started")
        return rc
    subprocess.run([_nft(), "destroy", "table", *table_for(family).split()],
                   capture_output=True)
    _state(vardir, "Cleared")
    return 0


def _parse_compile_args(args):
    """Positional [directory] [pathname] plus the harness flags."""
    directory = None
    pathname = None
    family = None
    script = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "--output"):
            pathname = args[i + 1]
            i += 2
        elif a == "--family":
            family = int(args[i + 1])
            i += 2
        elif a == "--script":
            script = args[i + 1]
            i += 2
        elif a in ("-e", "--export"):
            i += 1
        elif directory is None:
            directory = a
            i += 1
        elif pathname is None:
            pathname = a
            i += 1
        else:
            _fatal(f"unexpected argument {a}")
    return directory, pathname, family, script


def _fatal(message):
    print(f"   ERROR: {message}", file=sys.stderr)
    sys.exit(2)


def _confirm_or_revert(vardir, family, timeout=60):
    print("Do you want to accept the new firewall configuration? [y/n] ",
          end="", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    answer = sys.stdin.readline().strip().lower() if ready else ""
    if answer in ("y", "yes"):
        print("New configuration has been accepted")
        return 0
    print("New configuration reverted")
    return _revert(vardir, family)


# Verbs ------------------------------------------------------------------

def cmd_version(args, family):
    print(__version__)
    return 0


def cmd_check(args, family):
    directory, _, fam_flag, _ = _parse_compile_args(args)
    confdir = directory or _confdir(family)
    family = fam_flag or family
    with tempfile.NamedTemporaryFile(suffix=".nft", delete=False) as tmp:
        path = tmp.name
    try:
        compile_config(confdir, path, family)
        nft = subprocess.run(["unshare", "-r", "-n", _nft(), "-c", "-f",
                              path], capture_output=True, text=True)
        if nft.returncode != 0:
            print(nft.stderr, file=sys.stderr)
            print("   ERROR: nft rejected the generated ruleset",
                  file=sys.stderr)
            return 1
        print(f"Shorewall configuration verified in {confdir}")
        return 0
    finally:
        os.unlink(path)


def cmd_compile(args, family):
    directory, pathname, fam_flag, script = _parse_compile_args(args)
    confdir = directory or _confdir(family)
    family = fam_flag or family
    flags_style = "-o" in args or "--output" in args
    if flags_style:
        # Harness style: write only what was asked for.
        compile_config(confdir, pathname, family, script_path=script)
        target = script or pathname
    else:
        # Upstream style: pathname is the firewall script.
        script = pathname or _script_path(_vardir(family))
        compile_config(confdir, script + ".nft", family, script_path=script)
        target = script
    print(f"Shorewall configuration compiled to {target}")
    return 0


def cmd_start(args, family):
    args = [a for a in args if a != "-f"]
    confdir = args[0] if args else _confdir(family)
    return _apply(confdir, family, _vardir(family))


def cmd_reload(args, family):
    return cmd_start(args, family)


def cmd_stop(args, family):
    vardir = _vardir(family)
    script = _script_path(vardir)
    if not os.path.exists(script):
        _compile_to(_confdir(family), family, script)
    rc = _run_script(script, "stop")
    if rc == 0:
        _state(vardir, "Stopped")
    return rc


def cmd_clear(args, family):
    vardir = _vardir(family)
    script = _script_path(vardir)
    if os.path.exists(script):
        rc = _run_script(script, "clear")
    else:
        subprocess.run([_nft(), "destroy", "table", *table_for(family).split()],
                       capture_output=True)
        rc = 0
    if rc == 0:
        _state(vardir, "Cleared")
    return rc


def cmd_try(args, family):
    if not args:
        _fatal("try requires a directory")
    directory = args[0]
    timeout = 0
    if len(args) > 1:
        spec = args[1]
        timeout = int(spec[:-1]) * 60 if spec.endswith("m") else int(spec)
    vardir = _vardir(family)
    try:
        rc = _apply(directory, family, vardir)
    except ConfigError as e:
        print(f"   ERROR: {e}", file=sys.stderr)
        rc = 1
    if rc != 0:
        print("Restoring the previous configuration", file=sys.stderr)
        _revert(vardir, family)
        return rc
    if timeout:
        print(f"New configuration active, reverting in {timeout}s "
              "unless this process is interrupted")
        try:
            time.sleep(timeout)
        except KeyboardInterrupt:
            print("\nNew configuration accepted")
            return 0
        print("Timeout reached, reverting")
        return _revert(vardir, family)
    return 0


def cmd_safe_start(args, family):
    vardir = _vardir(family)
    rc = cmd_start(args, family)
    if rc != 0:
        _revert(vardir, family)
        return rc
    return _confirm_or_revert(vardir, family)


def cmd_restart(args, family):
    return cmd_start(args, family)


def cmd_safe_restart(args, family):
    return cmd_safe_start(args, family)


def _rule_counts(family):
    """Total and nat rule counts from the live table, or None if it is
    not loaded."""
    import json
    r = subprocess.run([_nft(), "-j", "list", "table", *table_for(family).split()],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        items = json.loads(r.stdout).get("nftables", [])
    except json.JSONDecodeError:
        return None
    nat_chains = {o["chain"]["name"] for o in items
                  if "chain" in o and o["chain"].get("type") == "nat"}
    rules = [o["rule"] for o in items if "rule" in o]
    nat = sum(1 for ru in rules if ru.get("chain") in nat_chains)
    return len(rules), nat


def cmd_status(args, family):
    import socket
    vardir = _vardir(family)
    product = "Shorewall6" if family == 6 else "Shorewall"
    now = time.strftime("%a %d %b %Y %H:%M:%S %Z")
    print(f"{product}-nft {__version__} Status at {socket.gethostname()} "
          f"- {now}\n")
    try:
        with open(os.path.join(vardir, "state")) as f:
            raw = f.read().strip()
    except OSError:
        raw = "Cleared"
    state = raw.split()[0] if raw else "Cleared"

    if state != "Started":
        print(f"{product} is stopped")
        print(f"State:{raw}")
        return 3

    print(f"{product} is running")
    when = raw[len("Started"):].strip().strip("()")
    artifact = _script_path(vardir)
    compiled = ""
    if os.path.exists(artifact):
        compiled = time.strftime("%a %d %b %Y %H:%M:%S %Z",
                                 time.localtime(os.path.getmtime(artifact)))
    print(f"State:Started {when} from {_confdir(family)}/ "
          f"({artifact} compiled {compiled} by shorewall-nft {__version__})")

    counts = _rule_counts(family)
    if counts is None:
        print("\nWarning: the state says started but the ruleset is not "
              "loaded.", file=sys.stderr)
    else:
        total, nat = counts
        print(f"\n{total} filter rules, {nat} nat rules")
    return 0


def cmd_show(args, family):
    what = args[0] if args else "filter"
    if what in ("filter", "nat", "mangle", "raw", "rules"):
        return subprocess.run([_nft(), "list", "table",
                               *table_for(family).split()]).returncode
    if what == "capabilities":
        for name, value in sorted(capabilities.CAPABILITIES.items()):
            print(f"   {name}: {'Yes' if value else 'Not available'}")
        return 0
    if what == "macros":
        from . import macros
        for f in sorted(os.listdir(macros.MACRO_DIR)):
            print(f[6:])
        return 0
    if what in ("zones", "policies"):
        from .compile import load
        cfg = load(_confdir(family), family)
        if what == "zones":
            for z in cfg.zones:
                print(f"{z.name} ({z.type})")
        else:
            for p in cfg.policies:
                level = f" {p.loglevel}" if p.loglevel else ""
                print(f"{p.source}\t{p.dest}\t{p.policy}{level}")
        return 0
    print(f"shorewall-nft: 'show {what}' is not implemented yet",
          file=sys.stderr)
    return 1


def cmd_save(args, family):
    vardir = _vardir(family)
    name = args[0] if args else "restore"
    script = _script_path(vardir)
    if not os.path.exists(script):
        _fatal("no compiled firewall to save; start the firewall first")
    shutil.copy2(script, os.path.join(vardir, name))
    print(f"Configuration saved to {os.path.join(vardir, name)}")
    return 0


def cmd_restore(args, family):
    vardir = _vardir(family)
    name = args[0] if args else "restore"
    saved = os.path.join(vardir, name)
    if not os.path.exists(saved):
        _fatal(f"restore file {saved} does not exist")
    rc = _run_script(saved, "start")
    if rc == 0:
        shutil.copy2(saved, _script_path(vardir))
        _state(vardir, "Started")
    return rc


def cmd_forget(args, family):
    vardir = _vardir(family)
    name = args[0] if args else "restore"
    saved = os.path.join(vardir, name)
    if os.path.exists(saved):
        os.unlink(saved)
        print(f"{saved} removed")
    return 0


def cmd_ipcalc(args, family):
    if len(args) == 1:
        spec = args[0]
    elif len(args) == 2:
        spec = f"{args[0]}/{args[1]}"
    else:
        _fatal("usage: ipcalc address mask | address/vlsm")
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError as e:
        _fatal(str(e))
    print(f"   CIDR={net.with_prefixlen}")
    print(f"   NETMASK={net.netmask}")
    print(f"   NETWORK={net.network_address}")
    print(f"   BROADCAST={net.broadcast_address}")
    return 0


def cmd_iprange(args, family):
    if not args or "-" not in args[0]:
        _fatal("usage: iprange low.address-high.address")
    low, high = args[0].split("-", 1)
    try:
        nets = ipaddress.summarize_address_range(
            ipaddress.ip_address(low), ipaddress.ip_address(high))
    except ValueError as e:
        _fatal(str(e))
    for net in nets:
        print(f"   {net.with_prefixlen}")
    return 0


def cmd_savesets(args, family):
    """Snapshot the runtime contents of externally-filled sets, so they
    survive a reload or a reboot restore."""
    script = _script_path(_vardir(family))
    if not os.path.exists(script):
        print("shorewall-nft: nothing running to save sets from")
        return 0
    return _run_script(script, "savesets")


def _compat_report(confdir):
    """List the config files present and their support state. Returns
    (lines, unsupported_present)."""
    from . import compile as _c
    lines = []
    unsupported = []
    for name in sorted(os.listdir(confdir)):
        path = os.path.join(confdir, name)
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            continue
        if name.startswith("action.") or name.startswith("macro."):
            state = "supported (user action or macro)"
        elif name in _c.HANDLED or name in _c.VARIABLE_FILES:
            state = "supported"
        elif name in _c.DEPRECATED:
            state = "deprecated upstream, ignored (use the mangle file)"
        elif name in _c.UNSUPPORTED:
            state = "NOT SUPPORTED"
            unsupported.append(name)
        elif name in _c.EXTENSIONS:
            state = "extension script"
        else:
            state = "site file, ignored"
        lines.append(f"  {name:20} {state}")
    return lines, unsupported


def _service(family):
    return "shorewall6.service" if family == 6 else "shorewall.service"


def cmd_migrate(args, family):
    """Validate an existing Shorewall configuration under nftables,
    report the compatibility state, then hand the firewall over. Never
    changes the running firewall without confirmation, and refuses a
    config that does not compile. Handles one stack: `shorewall migrate`
    for IPv4, `shorewall6 migrate` for IPv6. It warns when the other
    stack still needs migrating."""
    undo = "--undo" in args
    assume_yes = "--yes" in args or "-y" in args
    confdir = _confdir(family)
    label = "IPv6" if family == 6 else "IPv4"

    if undo:
        print("Reversing the service handover.")
        _sysd("disable", "--now", _service(family))
        print("shorewall-nft stopped and disabled. Re-enable the previous "
              "firewall to finish rolling back.")
        return 0

    if not os.path.isdir(confdir):
        _fatal(f"no configuration at {confdir}")

    print(f"Checking {confdir} ({label}) against nftables.\n")
    lines, unsupported = _compat_report(confdir)
    print("\n".join(lines))
    print()

    # The real test: does it compile and does the kernel accept it.
    with tempfile.NamedTemporaryFile(suffix=".nft", delete=False) as tmp:
        path = tmp.name
    try:
        try:
            compile_config(confdir, path, family)
        except ConfigError as e:
            _fatal(f"configuration does not compile: {e}\n"
                   "Nothing changed. Resolve the above and run migrate again.")
        nft = subprocess.run(["unshare", "-r", "-n", _nft(), "-c", "-f", path],
                             capture_output=True, text=True)
        if nft.returncode != 0:
            print(nft.stderr, file=sys.stderr)
            _fatal("the generated ruleset was rejected by nft. Nothing "
                   "changed.")
    finally:
        os.unlink(path)

    print("The configuration compiles to a valid nftables ruleset.")
    if unsupported:
        print(f"\nUnsupported files present: {', '.join(unsupported)}.")
        print("These would not carry over. Remove or replace them first.")
        return 1

    print(f"\nReady to hand over ({label}). This enables shorewall-nft at")
    print("boot and starts it now, taking over from the previous Shorewall.")
    if not assume_yes:
        print("Proceed? [y/n] ", end="", flush=True)
        if sys.stdin.readline().strip().lower() not in ("y", "yes"):
            print("No changes made.")
            return 0

    # Enable for boot. daemon-reload first, since the unit may have just
    # been installed. Start by loading the ruleset directly rather than
    # through systemctl: a leftover SysV init script can make systemd
    # resolve a stale unit, so a direct start is reliable.
    _sysd("daemon-reload")
    _sysd("enable", _service(family))
    print(f"Starting shorewall-nft ({label}).")
    rc = cmd_start([], family)
    loaded = subprocess.run([_nft(), "list", "table", *table_for(family).split()],
                            capture_output=True).returncode == 0
    if rc == 0 and loaded:
        # Tear down only this family's old iptables ruleset. The other
        # family keeps its firewall until its own migrate runs.
        if _clear_legacy_iptables(family):
            print(f"Cleared the previous Shorewall's "
                  f"{_iptables_cmd(family)} ruleset.")
        print("shorewall-nft is running and enabled at boot. "
              "Verify with 'shorewall status'.")
        _other_stack_note(family)
        return 0
    print("shorewall-nft is enabled but the ruleset did not load. "
          "Run 'shorewall start' and check the output.", file=sys.stderr)
    return 1


def _iptables_cmd(family):
    return "ip6tables" if family == 6 else "iptables"


def _iptables_has_rules(family):
    """True if this family's classic iptables ruleset has anything beyond
    the bare built-in chains."""
    import shutil
    cmd = _iptables_cmd(family)
    path = shutil.which(cmd) or f"/usr/sbin/{cmd}"
    if not os.path.exists(path):
        return False
    r = subprocess.run([path, "-S"], capture_output=True, text=True)
    return r.returncode == 0 and any(
        ln.strip() and not ln.startswith("-P ")
        for ln in r.stdout.splitlines())


def _clear_legacy_iptables(family):
    """Tear down this family's classic Shorewall iptables ruleset left in
    the kernel. Set the built-in policies to ACCEPT, flush every chain and
    delete the non-built-in chains. Mirrors what `shorewall clear` did.
    The other family's ruleset is left alone, so migrating one stack does
    not drop the firewall on the other. Returns True if there was a
    ruleset to clear."""
    import shutil
    cmd = _iptables_cmd(family)
    path = shutil.which(cmd) or f"/usr/sbin/{cmd}"
    if not os.path.exists(path):
        return False
    cleared = _iptables_has_rules(family)
    for table in ("raw", "mangle", "nat", "filter"):
        for chain in ("PREROUTING", "INPUT", "FORWARD", "OUTPUT",
                      "POSTROUTING"):
            subprocess.run([path, "-t", table, "-P", chain, "ACCEPT"],
                           capture_output=True)
        subprocess.run([path, "-t", table, "-F"], capture_output=True)
        subprocess.run([path, "-t", table, "-X"], capture_output=True)
    return cleared


def _other_stack_note(family):
    """Warn if the other family still has a config or a live iptables
    ruleset, so migrating one stack points the way to the other. Silent
    if the other stack is already on shorewall-nft."""
    other = 4 if family == 6 else 6
    already = subprocess.run(
        [_nft(), "list", "table", *table_for(other).split()],
        capture_output=True).returncode == 0
    if already:
        return
    conf = "/etc/shorewall" if other == 4 else "/etc/shorewall6"
    cmd = "shorewall" if other == 4 else "shorewall6"
    label = "IPv4" if other == 4 else "IPv6"
    reasons = []
    if os.path.isdir(conf):
        reasons.append(f"a configuration at {conf}")
    if _iptables_has_rules(other):
        reasons.append(f"a live {_iptables_cmd(other)} ruleset")
    if reasons:
        print(f"\nNote: {' and '.join(reasons)} still present. {label} is "
              f"not handled yet. Run '{cmd} migrate' to hand it over too.")


def _sysd(*args):
    """Run systemctl, returning its exit code. Absent systemctl is not
    fatal; the handover just reports it."""
    try:
        return subprocess.run(["systemctl", *args]).returncode
    except FileNotFoundError:
        print("systemctl not found; do the service change by hand",
              file=sys.stderr)
        return 1


def cmd_geoip_update(args, family):
    """Fill the geoip country sets from CIDR data. Reads a local
    directory of <cc>.zone files with --from, otherwise downloads the
    ipdeny aggregated zones. Extra arguments limit it to those country
    codes."""
    from . import geoip
    source_dir = None
    only = []
    it = iter(args)
    for a in it:
        if a in ("--from", "-f"):
            source_dir = next(it, None)
            if not source_dir:
                _fatal("--from needs a directory")
        else:
            only.append(a.lower())
    geodir = os.path.join(_vardir(family), "geoip")
    results = geoip.update(_nft(), geodir, family, source_dir, only or None)
    if not results:
        print("shorewall-nft: no geoip sets in the running firewall")
        return 0
    rc = 0
    for setname, count, error in results:
        if error:
            print(f"   ERROR: {setname}: {error}", file=sys.stderr)
            rc = 1
        else:
            print(f"{setname}: {count} ranges loaded")
    return rc


NOT_IMPLEMENTED = {
    "allow": "dynamic blacklisting",
    "drop": "dynamic blacklisting",
    "reject": "dynamic blacklisting",
    "blacklist": "dynamic blacklisting",
    "logdrop": "dynamic blacklisting",
    "logreject": "dynamic blacklisting",
    "logwatch": "log analysis",
    "hits": "log analysis",
    "dump": "diagnostic dump",
    "iptrace": "packet tracing (use nft monitor trace)",
    "noiptrace": "packet tracing",
    "refresh": "chain refresh",
    "update": "configuration update",
    "export": "remote export",
    "call": "script function calls",
    "run": "script function calls",
    "add": "dynamic zones",
    "delete": "dynamic zones",
    "open": "dynamic open",
    "close": "dynamic open",
    "remote-start": "remote administration",
    "remote-reload": "remote administration",
    "remote-restart": "remote administration",
    "remote-getcaps": "remote administration",
}

def _state_dir():
    # The wrapper's runtime state, where provider .state files live. This
    # is the wrapper's $STATE, distinct from the compiled-artifact vardir.
    return os.environ.get("SWNFT_STATE", "/var/run/shorewall-nft")


def _provider_disabled(name):
    path = os.path.join(_state_dir(), "providers", name + ".state")
    try:
        return open(path).read().strip() == "down"
    except OSError:
        return False


def _provider_names(family):
    from .compile import load
    return [p.name for p in load(_confdir(family), family).providers]


def _set_provider(args, family, verb):
    if not args:
        _fatal(f"{verb} requires a provider name")
    name = args[0]
    names = _provider_names(family)
    if name not in names:
        _fatal(f"no provider named {name}")
    if verb == "disable":
        enabled = [n for n in names if not _provider_disabled(n)]
        if enabled == [name]:
            _fatal(f"{name} is the only enabled provider; refusing to "
                   "disable it")
    script = _script_path(_vardir(family))
    if not os.path.exists(script):
        _fatal("no running firewall; run 'shorewall start' first")
    rc = _run_script(script, verb, name)
    if rc == 0:
        print(f"Provider {name} {verb}d.")
    return rc


def cmd_disable(args, family):
    """Take a provider out of service without a reload: mark it down and
    recompute routing over the providers that remain."""
    return _set_provider(args, family, "disable")


def cmd_enable(args, family):
    """Return a provider to service and recompute routing."""
    return _set_provider(args, family, "enable")


def cmd_reenable(args, family):
    """Reset a provider to enabled, as upstream's reenable does."""
    return _set_provider(args, family, "enable")


VERBS = {
    "version": cmd_version,
    "enable": cmd_enable,
    "disable": cmd_disable,
    "reenable": cmd_reenable,
    "check": cmd_check,
    "compile": cmd_compile,
    "start": cmd_start,
    "reload": cmd_reload,
    "restart": cmd_restart,
    "stop": cmd_stop,
    "clear": cmd_clear,
    "try": cmd_try,
    "safe-start": cmd_safe_start,
    "safe-restart": cmd_safe_restart,
    "status": cmd_status,
    "show": cmd_show,
    "list": cmd_show,
    "ls": cmd_show,
    "save": cmd_save,
    "restore": cmd_restore,
    "forget": cmd_forget,
    "ipcalc": cmd_ipcalc,
    "iprange": cmd_iprange,
    "savesets": cmd_savesets,
    "geoip-update": cmd_geoip_update,
    "migrate": cmd_migrate,
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    family = _family()
    while argv and argv[0] in ("trace", "debug", "-q", "-v"):
        argv.pop(0)
    if not argv:
        print("usage: shorewall-nft COMMAND [ARGS]", file=sys.stderr)
        print("commands: " + " ".join(sorted(VERBS)), file=sys.stderr)
        return 2
    verb, args = argv[0], argv[1:]
    if verb in VERBS:
        try:
            return VERBS[verb](args, family)
        except ConfigError as e:
            print(f"   ERROR: {e}", file=sys.stderr)
            return 1
    if verb in NOT_IMPLEMENTED:
        print(f"shorewall-nft: '{verb}' ({NOT_IMPLEMENTED[verb]}) is not "
              "implemented yet", file=sys.stderr)
        return 1
    print(f"shorewall-nft: unknown command {verb}", file=sys.stderr)
    return 2
