"""The shorewall command surface.

Verbs match shorewall(8) in name, syntax and semantics. stop means the
safe state, clear opens the firewall, try reverts on failure or
timeout. Verbs that are not implemented yet fail with a message naming
the gap. They must never succeed silently or die with a traceback.
"""
import ipaddress
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time

from . import __version__, capabilities, chunk
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


def _check_ruleset(path, family):
    """Ask the kernel to validate a ruleset in a disposable netns.

    Prefer one check-only transaction.  Large rulesets can exceed the
    netlink send buffer, so on E2BIG validate the same fail-closed skeleton
    and chunks the runtime loader uses.  The chunked pass applies rules in
    the private namespace because separate ``nft -c`` calls would not retain
    the skeleton needed by later chunks.
    """
    nft_path = _nft()
    result = subprocess.run(
        ["unshare", "-r", "-n", nft_path, "-c", "-f", path],
        capture_output=True, text=True)
    if result.returncode == 0 or "Message too long" not in result.stderr:
        return result

    with open(path) as ruleset_file:
        ruleset = ruleset_file.read()
    skeleton, chunks = chunk.split(ruleset, table_for(family))
    with tempfile.TemporaryDirectory(prefix="shorewall-nft-check-") as tmpdir:
        paths = []
        for number, text in enumerate([skeleton] + chunks):
            chunk_path = os.path.join(tmpdir, f"{number:05d}.nft")
            with open(chunk_path, "w") as chunk_file:
                chunk_file.write(text)
            paths.append(chunk_path)
        # One unshare invocation keeps all chunk loads in the same disposable
        # namespace. Arguments carry paths without interpolating them into sh.
        command = (
            'nft=$1; shift; for file do "$nft" -f "$file" || exit; done'
        )
        return subprocess.run(
            ["unshare", "-r", "-n", "sh", "-c", command,
             "shorewall-nft-check", nft_path] + paths,
            capture_output=True, text=True)


def cmd_check(args, family):
    directory, _, fam_flag, _ = _parse_compile_args(args)
    confdir = directory or _confdir(family)
    family = fam_flag or family
    with tempfile.NamedTemporaryFile(suffix=".nft", delete=False) as tmp:
        path = tmp.name
    try:
        compile_config(confdir, path, family)
        nft = _check_ruleset(path, family)
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
    # A package upgrade can change stopped-state lifecycle semantics while an
    # older generated wrapper remains in /var/lib. Compile a fresh wrapper
    # before stopping so `stop` uses the installed implementation just as
    # start/reload/restart do. Build beside the live artifact and replace it
    # only after a complete successful compile; an invalid current config can
    # therefore still be stopped with its last valid wrapper.
    fd, candidate = tempfile.mkstemp(prefix="firewall.stop-", dir=vardir)
    os.close(fd)
    try:
        try:
            _compile_to(_confdir(family), family, candidate)
        except (ConfigError, OSError) as error:
            if not os.path.exists(script):
                raise
            print(f"shorewall-nft: could not refresh the stop artifact; "
                  f"using the last compiled one: {error}", file=sys.stderr)
        else:
            os.replace(candidate + ".nft", script + ".nft")
            os.replace(candidate, script)
    finally:
        for pathname in (candidate, candidate + ".nft"):
            try:
                os.unlink(pathname)
            except OSError:
                pass
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
    loaded = counts is not None
    if not loaded:
        print("\nWarning: the state says started but the ruleset is not "
              "loaded.", file=sys.stderr)
    else:
        total, nat = counts
        print(f"\n{total} filter rules, {nat} nat rules")

    # Provider and link-monitor state, if this box does multi-ISP.
    try:
        names = _provider_names(family)
    except (ConfigError, OSError) as e:
        names = []
        if isinstance(e, ConfigError):
            print(f"\nWarning: the provider configuration does not parse, so "
                  f"provider status is unavailable: {e}", file=sys.stderr)
    if names:
        print("\nProviders:")
        lsm_dir = os.path.join(_state_dir(), "lsm")
        for name in names:
            state = "disabled" if _provider_disabled(name) else "enabled"
            mon = ""
            try:
                with open(os.path.join(lsm_dir, name + ".status")) as f:
                    mon = "  monitor: " + f.read().strip()
            except OSError:
                pass
            print(f"  {name}: {state}{mon}")
    # Started but the table is gone is a real problem: return non-zero so a
    # monitor keyed on the exit code alerts on an unprotected box.
    return 0 if loaded else 1


def _accounting_listing(text):
    """Extract live accounting objects from an ``nft list table`` result."""
    objects = []
    current = []
    depth = 0
    start = re.compile(
        r"^\s*(?:counter\s+acct_|set\s+acct_|chain\s+(?:accounting|acct_chain_))"
        r"[^\n{]*\{")
    for line in text.splitlines():
        if not current:
            if not start.match(line):
                continue
            current = [line]
            depth = line.count("{") - line.count("}")
        else:
            current.append(line)
            depth += line.count("{") - line.count("}")
        if current and depth == 0:
            objects.append("\n".join(current))
            current = []
    return objects


def _show_accounting(family):
    table = table_for(family).split()
    result = subprocess.run(
        [_nft(), "list", "table", *table], capture_output=True, text=True)
    if result.returncode:
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    objects = _accounting_listing(result.stdout)
    chains = [obj for obj in objects
              if obj.lstrip().startswith("chain ")]
    if not objects:
        print(f"No accounting objects in table {' '.join(table)}")
        return 0
    import socket
    product = "Shorewall6" if family == 6 else "Shorewall"
    now = time.strftime("%a %d %b %Y %H:%M:%S %Z")
    print(f"{product}-nft {__version__} Accounting at {socket.gethostname()} "
          f"- {now}")
    # The counters are zeroed whenever the ruleset is loaded, since start,
    # reload and restart recreate the table. That is exactly when the state
    # file was last written, so its mtime is the last clear. Report how long
    # the counters have been accumulating.
    try:
        cleared = os.path.getmtime(os.path.join(_vardir(family), "state"))
    except OSError:
        cleared = None
    if cleared is not None:
        import datetime
        stamp = time.strftime("%a %d %b %Y %H:%M:%S %Z",
                              time.localtime(cleared))
        ago = datetime.timedelta(seconds=int(time.time() - cleared))
        print(f"Counters cleared {stamp} ({ago} ago)")
    print()

    named = {}
    for obj in objects:
        match = re.search(
            r"^\s*counter\s+(acct_[\w.-]+)\s*\{.*?"
            r"packets\s+(\d+)\s+bytes\s+(\d+)", obj, re.S)
        if match:
            named[match.group(1)] = (int(match.group(2)), int(match.group(3)))

    references = {}
    chains.sort(key=lambda obj: 0 if re.search(
        r"^\s*chain\s+accounting\b", obj) else 1)
    for obj in chains:
        for target in re.findall(r"\bjump\s+acct_chain_([\w.-]+)", obj):
            references[target] = references.get(target, 0) + 1
    default_addr = "::/0" if family == 6 else "0.0.0.0/0"
    printed = False
    for obj in chains:
        first = obj.splitlines()[0]
        match = re.search(r"\bchain\s+(\S+)", first)
        if not match:
            continue
        nft_chain = match.group(1)
        chain = (nft_chain[len("acct_chain_"):] if
                 nft_chain.startswith("acct_chain_") else nft_chain)
        rows = []
        for line in obj.splitlines()[1:-1]:
            if "counter" not in line or line.strip().startswith("type "):
                continue
            packets = bytes_ = 0
            count = re.search(r"\bcounter\s+packets\s+(\d+)\s+bytes\s+(\d+)",
                              line)
            named_count = re.search(r'\bcounter\s+name\s+"([^"]+)"', line)
            if count:
                packets, bytes_ = int(count.group(1)), int(count.group(2))
            elif named_count:
                packets, bytes_ = named.get(named_count.group(1), (0, 0))

            jump = re.search(r"\bjump\s+acct_chain_([\w.-]+)", line)
            update = re.search(r"\bupdate\s+@(acct_[\w.-]+)", line)
            if jump:
                target = jump.group(1)
                detail = ""
            elif update:
                target = "ACCOUNT"
                set_name = update.group(1)
                table_name = re.sub(r"_\d+$", "", set_name[len("acct_"):])
                address = re.search(r"\bip6?\s+[sd]addr\s+(\S+)", line)
                detail = (f" ACCOUNT addr {address.group(1)} "
                          f"tname {table_name}" if address else
                          f" ACCOUNT tname {table_name}")
            elif " return" in line:
                target, detail = "DONE", ""
            elif named_count:
                target = named_count.group(1)[len("acct_"):]
                target = re.sub(r"_\d+$", "", target)
                detail = ""
            else:
                target, detail = "COUNT", ""

            incoming = re.search(r'\biifname\s+"([^"]+)"', line)
            outgoing = re.search(r'\boifname\s+"([^"]+)"', line)
            source = re.search(r"\bip6?\s+saddr\s+(\S+)", line)
            dest = re.search(r"\bip6?\s+daddr\s+(\S+)", line)
            comment = re.search(r'\bcomment\s+"([^"]+)"', line)
            rows.append((packets, bytes_, target,
                         incoming.group(1) if incoming else "*",
                         outgoing.group(1) if outgoing else "*",
                         source.group(1) if source else default_addr,
                         dest.group(1) if dest else default_addr,
                         comment.group(1) if comment else "", detail))
        if not rows:
            continue
        printed = True
        refs = references.get(chain, 0)
        suffix = f" ({refs} reference{'s' if refs != 1 else ''})" \
            if nft_chain != "accounting" else ""
        print(f"Chain {chain}{suffix}")
        print(" pkts bytes target       prot opt in         out        "
              "source               destination")
        for packets, bytes_, target, incoming, outgoing, source, dest, \
                comment, detail in rows:
            note = f" /* {comment} */" if comment else ""
            print(f"{_metric(packets):>5} {_metric(bytes_):>5} "
                  f"{target:<12} all  --  {incoming:<10} {outgoing:<10} "
                  f"{source:<20} {dest:<20}{note}{detail}")
        print()
    if not printed:
        print("Accounting objects exist, but no live accounting rules were found.")
    return 0


def _metric(value):
    """iptables-style compact packet/byte counter."""
    units = ("", "K", "M", "G", "T", "P")
    number = float(value)
    unit = units[0]
    for unit in units:
        if number < 1000 or unit == units[-1]:
            break
        number /= 1000.0
    if not unit:
        return str(value)
    return f"{number:.0f}{unit}" if number >= 10 else f"{number:.1f}{unit}"


def _show_routing(family):
    """Show live policy rules and every relevant route table."""
    import socket
    ip = _ip()
    flag = "-6" if family == 6 else "-4"
    product = "Shorewall6" if family == 6 else "Shorewall"
    now = time.strftime("%a %d %b %Y %H:%M:%S %Z")
    print(f"{product}-nft {__version__} Routing at {socket.gethostname()} "
          f"- {now}\n")
    print("Routing Rules\n")
    rules = subprocess.run([ip, flag, "rule", "show"],
                           capture_output=True, text=True)
    if rules.stdout:
        print(rules.stdout.rstrip())
    if rules.returncode:
        if rules.stderr:
            print(rules.stderr, end="", file=sys.stderr)
        return rules.returncode

    # label -> kernel table selector. Provider names are the useful labels,
    # while their numbers work even when /etc/iproute2/rt_tables lacks them.
    tables = {"default": "253", "local": "255", "main": "254"}
    number_labels = {"253": "default", "254": "main", "255": "local"}
    try:
        from .compile import load
        cfg = load(_confdir(family), family)
    except (ConfigError, OSError):
        cfg = None
    if cfg is not None:
        for provider in cfg.providers:
            tables[provider.name] = str(provider.number)
            number_labels[str(provider.number)] = provider.name
        if any(provider.balance for provider in cfg.providers):
            tables["balance"] = "250"
            number_labels["250"] = "balance"
        for route in cfg.routes:
            selector = str(route["table"])
            label = number_labels.get(selector, selector)
            tables.setdefault(label, selector)

    # Include tables introduced outside Shorewall or by a stale/live rule.
    for selector in re.findall(r"\b(?:lookup|table)\s+(\S+)", rules.stdout):
        selector = selector.rstrip()
        standard = {"local": "255", "main": "254", "default": "253",
                    "balance": "250"}
        query = standard.get(selector, selector)
        label = number_labels.get(query, selector)
        tables.setdefault(label, query)

    for label in sorted(tables):
        print(f"\nTable {label}:\n")
        routes = subprocess.run(
            [ip, flag, "route", "show", "table", tables[label]],
            capture_output=True, text=True)
        if routes.stdout:
            print(routes.stdout.rstrip())
        if routes.stderr:
            print(routes.stderr.rstrip())
        if not routes.stdout and not routes.stderr:
            print("(empty)")
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
    if what in ("providers", "provider"):
        return _show_providers(family)
    if what == "accounting":
        return _show_accounting(family)
    if what == "routing":
        return _show_routing(family)
    print(f"shorewall-nft: 'show {what}' is not implemented yet",
          file=sys.stderr)
    return 1


def _ip():
    return "/usr/sbin/ip" if os.path.exists("/usr/sbin/ip") else "ip"


def _interface_up(iface):
    r = subprocess.run([_ip(), "-o", "link", "show", iface, "up"],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def _monitor_status(name):
    """Live monitor line for a provider, or "" if the monitor has not
    written one."""
    path = os.path.join(_state_dir(), "lsm", name + ".status")
    try:
        return open(path).read().strip()
    except OSError:
        return ""


def _active_profile():
    try:
        return open(os.path.join(_state_dir(), "profile")).read().strip()
    except OSError:
        return "default (no /etc/shorewall/profiles)"


def _rtrule_source(r):
    if r.runtime_iface:
        return f"&{r.runtime_iface}"
    if r.iif:
        return f"iif {r.iif}"
    return r.source or "any"


def _show_providers(family):
    """The provider and link-monitor posture, and what happens to each
    routed network when a provider is lost. Read-only."""
    from .compile import load
    from . import lsm
    cfg = load(_confdir(family), family)
    if not cfg.providers:
        print("No providers configured.")
        return 0

    mons = {}
    lsm_path = os.path.join(_confdir(family), "lsm")
    if os.path.isfile(lsm_path):
        pmap = {p.name: (p.interface, p.gateway) for p in cfg.providers}
        for m in lsm.parse_lsm(lsm_path, pmap):
            mons[m.name] = m

    print(f"shorewall-nft providers   ({table_for(family)})\n")
    for p in cfg.providers:
        up = "up" if _interface_up(p.interface) else "down"
        state = "disabled" if _provider_disabled(p.name) else "enabled"
        opts = []
        if p.track:
            opts.append("track")
        if p.balance:
            opts.append(f"balance={p.balance}")
        if p.fallback:
            opts.append("fallback" + (f"={p.fallback_weight}"
                                      if p.fallback_weight else ""))
        for name, flag in (("loose", p.loose), ("optional", p.optional),
                           ("persistent", p.persistent)):
            if flag:
                opts.append(name)
        mark = f"mark {p.mark}" if p.mark else "no mark"
        print(f"  {p.name}   {p.interface}   gw {p.gateway or '-'}   "
              f"{mark}   {', '.join(opts) or 'no options'}   [{up} · {state}]")
        m = mons.get(p.name)
        if m:
            live = _monitor_status(p.name)
            print(f"         monitor   {m.method} {', '.join(m.targets) or '-'}"
                  f"   every {m.interval}s, down after {m.down}"
                  f"{'   ' + live if live else ''}")
        else:
            print("         monitor   (none)")
        # rtrules that route to this provider, and whether each is the
        # preferred rule or a lower-priority fallback for its source.
        mine = [r for r in cfg.rtrules
                if r.provider in (p.name, str(p.number))]
        for r in mine:
            same = sorted((x for x in cfg.rtrules
                           if (x.source, x.dest, x.iif)
                           == (r.source, r.dest, r.iif)),
                          key=lambda x: x.priority)
            tag = "   fallback" if same and same[0] is not r else ""
            print(f"         rtrules   from {_rtrule_source(r)} to "
                  f"{r.dest or 'any'}   pref {r.priority}{tag}")

    bals = [p for p in cfg.providers if p.balance]
    if bals:
        print("\n  balanced default (table 250):  "
              + ", ".join(f"{p.name} ×{p.balance}" for p in bals))
    print(f"  active profile: {_active_profile()}")

    # What happens when a provider is lost: ordered rtrule fall-through,
    # and the balance set shrinking.
    flows = []
    for p in cfg.providers:
        for r in cfg.rtrules:
            if r.provider not in (p.name, str(p.number)):
                continue
            same = sorted((x for x in cfg.rtrules
                           if (x.source, x.dest, x.iif)
                           == (r.source, r.dest, r.iif)),
                          key=lambda x: x.priority)
            idx = same.index(r)
            if same[0] is r and idx + 1 < len(same):
                nxt = same[idx + 1].provider
                flows.append(f"    {p.name} lost: from {_rtrule_source(r)} "
                             f"falls through to {nxt}")
    if len(bals) > 1:
        flows.append("    a balanced provider lost: balance continues over "
                     "the rest")
    fbs = [p for p in cfg.providers if p.fallback]
    if bals and fbs:
        flows.append("    all balanced providers lost: traffic falls to the "
                     "fallback via " + ", ".join(p.name for p in fbs))
    if flows:
        print("\n  on failure:")
        for line in flows:
            print(line)
    return 0


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
        nft = _check_ruleset(path, family)
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


def _lsm_marker(name):
    # Marks a disable as the link monitor's own. The monitor re-enables only
    # the providers it disabled, so an operator 'disable' is never undone by
    # a link flap. An operator action (enable/disable/reenable) clears it.
    return os.path.join(_state_dir(), "lsm", name + ".owned")


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
        # An operator action takes ownership away from the monitor, so a
        # later link flap will not override it.
        try:
            os.remove(_lsm_marker(name))
        except OSError:
            pass
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


def cmd_lsm(args, family):
    """Run the link monitor. Probe each provider and enable or disable it
    through the seam on a state change. The monitor re-enables only the
    providers it disabled itself, so an operator 'disable' is never undone
    by a link flap. --once runs a single check cycle, for scripting and
    tests; it reloads the saved counters so the up/down hysteresis
    accumulates across separate invocations."""
    from . import lsm
    once = "--once" in args
    # systemd captures stdout as a pipe, where Python block-buffers by
    # default, so log lines would sit unseen in the journal for a long
    # time. Line-buffer so each line is flushed as it is written.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    script = _script_path(_vardir(family))
    if not os.path.exists(script):
        _fatal("no running firewall; run 'shorewall start' first")
    monitors = lsm.build_monitors(_confdir(family), family)
    if not monitors:
        print("shorewall-nft: no lsm configuration; nothing to monitor")
        return 0
    names = _provider_names(family)
    status_dir = os.path.join(_state_dir(), "lsm")
    if once:
        lsm.restore_state(status_dir, monitors)
    # Providers the monitor wanted down but left up because they were the
    # last usable link. Retried once another provider is usable again.
    pending = set()

    def _own(name):
        try:
            os.makedirs(status_dir, exist_ok=True)
            open(_lsm_marker(name), "w").close()
        except OSError:
            pass

    def _flush_pending():
        for name in list(pending):
            live = [n for n in names if not _provider_disabled(n)]
            if name in live and len(live) > 1:
                _run_script(script, "disable", name)
                _own(name)
                pending.discard(name)
                print(f"lsm: {name} down (deferred), disabled")

    def apply(name, state):
        if state == "down":
            if _provider_disabled(name):
                # Already down, by the operator or an earlier cycle. Do not
                # claim ownership of a disable that is not the monitor's.
                pending.discard(name)
                return
            live = [n for n in names if not _provider_disabled(n)]
            if live == [name]:
                pending.add(name)
                print(f"lsm: {name} is down but is the last usable provider; "
                      "leaving it up", file=sys.stderr)
                return
            _run_script(script, "disable", name)
            _own(name)
            pending.discard(name)
            print(f"lsm: {name} down, disabled")
        else:
            pending.discard(name)
            if not os.path.exists(_lsm_marker(name)):
                # Not the monitor's disable (operator disable, or never
                # disabled). Leave the operator's decision alone.
                return
            _run_script(script, "enable", name)
            try:
                os.remove(_lsm_marker(name))
            except OSError:
                pass
            print(f"lsm: {name} up, enabled")
        _flush_pending()

    lsm.run(monitors, apply, status_dir=status_dir, once=once)
    return 0


VERBS = {
    "version": cmd_version,
    "enable": cmd_enable,
    "disable": cmd_disable,
    "reenable": cmd_reenable,
    "lsm": cmd_lsm,
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
