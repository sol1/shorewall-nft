"""Compile a Shorewall configuration directory to an nft ruleset."""
import os
import stat
import sys

from . import emit, ipsets, macros, parsers, script
from .errors import ConfigError
from .reader import read_file, read_simple_vars

# Files consumed as variables or deliberately not part of the start
# ruleset. stoppedrules only matters for the stopped state.
HANDLED = {"zones", "interfaces", "policy", "rules", "snat", "masq",
           "stoppedrules", "conntrack", "accounting", "providers",
           "rtrules", "tunnels", "hosts", "tcdevices", "tcclasses",
           "mangle", "netmap", "blrules", "nat", "actions", "ecn",
           "proxyarp", "proxyndp", "routes", "maclist",
           "tcinterfaces", "tcpri"}
VARIABLE_FILES = {"shorewall.conf", "shorewall6.conf", "params"}

# shorewall.conf settings that change how packets are handled and that
# we do not honor yet. Their shipped default matches our behavior, so a
# config at the default is fine. A non-default value would silently
# change the firewall, so we reject it rather than ignore it. Everything
# else in shorewall.conf is either acted on elsewhere or a safe no-op
# (paths, logging format, optimization, tooling). See docs/settings.md.
BEHAVIORAL_DEFAULTS = {
    "INVALID_DISPOSITION": "continue",
    "RELATED_DISPOSITION": "accept",
    "UNTRACKED_DISPOSITION": "continue",
    "SMURF_DISPOSITION": "drop",
    "TCP_FLAGS_DISPOSITION": "drop",
    "SFILTER_DISPOSITION": "drop",
    "RPFILTER_DISPOSITION": "drop",
    "MACLIST_TABLE": "filter",
    "ACCOUNTING_TABLE": "filter",
    "MANGLE_ENABLED": "yes",
    "IMPLICIT_CONTINUE": "no",
    "MULTICAST": "no",
    "MARK_IN_FORWARD_CHAIN": "no",
    "BASIC_FILTERS": "no",
    "REJECT_ACTION": "",
    "TC_PRIOMAP": "2 3 3 3 2 3 1 1 2 2 2 2 2 2 2 2",
}


def _check_behavioral_settings(variables):
    """Reject a behavioral setting set to a value we do not implement.
    Silently ignoring it would change the firewall. The default is
    always accepted."""
    for name, default in BEHAVIORAL_DEFAULTS.items():
        if name not in variables:
            continue
        value = variables[name].strip().strip('"').strip("'").strip()
        norm = " ".join(value.lower().split())
        if norm != default:
            raise ConfigError(
                f"{name}={variables[name].strip()} is not supported yet; "
                f"only the default ({default or 'empty'}) is honored")

# Known upstream config files we do not implement yet. Content in one
# of these is a hard error: silently ignoring it would change firewall
# behavior. Anything else in the directory is a site file and upstream
# ignores it too.
UNSUPPORTED = {"tcrules",
               "secmarks", "arprules", "tcfilters",
               "routestopped", "vardir", "initdone"}

# Files upstream itself removed. Warn and ignore, as upstream does,
# rather than failing. The capability moved elsewhere.
DEPRECATED = {"tos": "the tos file is no longer supported, "
              "use the TOS action in the mangle file instead"}

# Lifecycle extension scripts embedded into the generated wrapper and
# run at the matching point. These are POSIX shell fragments the admin
# owns, exactly as upstream.
EXTENSIONS_LIFECYCLE = ("init", "start", "started", "stop", "stopped",
                        "clear")
# Other wired hooks. lib.private is a function library sourced into the
# wrapper so the lifecycle scripts can call its functions; findgw
# overrides gateway detection for a provider.
EXTENSIONS_WIRED_OTHER = ("lib.private", "findgw")
# Extension scripts we recognize but do not run yet. Warn, do not fail.
EXTENSIONS_UNWIRED = {"restored", "refresh", "refreshed", "isusable",
                      "continue", "maclog", "postcompile", "scfilter"}
EXTENSIONS = (set(EXTENSIONS_LIFECYCLE) | set(EXTENSIONS_WIRED_OTHER)
              | EXTENSIONS_UNWIRED)


class Config:
    def __init__(self, confdir, family=4):
        self.confdir = confdir
        self.family = family
        self.zones = []
        self.interfaces = []
        self.policies = []
        self.rules = []
        self.snat = []
        self.dnat = []
        self.stoppedrules = []
        self.helpers = []
        self.accounting = []
        self.ipsets = {}
        self.providers = []
        self.rtrules = []
        self.zone_hosts = []
        self.tcdevices = []
        self.tcclasses = []
        self.mangle = []
        self.netmap = []
        self.blrules = []
        self.nat = []
        self.ecn = []
        self.proxyarp = []
        self.routes = []
        self.maclist = []
        self.tcinterfaces = []
        self.tcpri = []
        self.fw_zone = None
        self.variables = {}
        self.docker = False       # DOCKER=Yes coexistence enabled
        self.docker_bridge = "docker0"
        self.clampmss = ""        # "pmtu", a fixed MSS value, or ""
        self.extensions = {}      # lifecycle extension script bodies


def _path(confdir, name):
    return os.path.join(confdir, name)


def _has_content(path, variables):
    try:
        return any(True for _ in read_file(path, variables))
    except ConfigError:
        return True


def load(confdir, family=4):
    cfg = Config(confdir, family)
    variables = {}
    conf = "shorewall6.conf" if family == 6 else "shorewall.conf"
    variables.update(read_simple_vars(_path(confdir, conf)))
    variables.update(read_simple_vars(_path(confdir, "params")))

    cfg.zones = parsers.parse_zones(_path(confdir, "zones"), variables)
    fw = [z.name for z in cfg.zones if z.type == "firewall"]
    if len(fw) != 1:
        raise ConfigError("exactly one firewall zone required")
    cfg.fw_zone = fw[0]
    variables.setdefault("FW", cfg.fw_zone)
    cfg.variables = variables

    docker = variables.get("DOCKER", "").lower()
    if docker in ("yes", "1", "on"):
        cfg.docker = True
    elif docker not in ("", "no", "0", "off"):
        raise ConfigError(f"DOCKER must be Yes or No, not {docker}")
    if variables.get("DOCKER_BRIDGE"):
        cfg.docker_bridge = variables["DOCKER_BRIDGE"]

    _check_behavioral_settings(variables)

    clampmss = variables.get("CLAMPMSS", "").strip()
    if clampmss.lower() in ("yes", "1", "on"):
        cfg.clampmss = "pmtu"
    elif clampmss and clampmss.lower() not in ("no", "0", "off", ""):
        cfg.clampmss = clampmss   # a fixed MSS value

    # Register user-defined actions so the rule parser can expand them
    # like macros. Declared in the actions file, defined in action.<name>.
    macros.set_user_actions(confdir,
                            parsers.parse_actions(_path(confdir, "actions"),
                                                  variables))

    cfg.interfaces = parsers.parse_interfaces(_path(confdir, "interfaces"),
                                              variables)
    if os.path.exists(_path(confdir, "hosts")):
        cfg.zone_hosts = parsers.parse_hosts(_path(confdir, "hosts"),
                                             variables, cfg.interfaces,
                                             cfg.zones)
    cfg.policies = parsers.parse_policy(_path(confdir, "policy"), variables)
    cfg.rules, cfg.dnat = parsers.parse_rules(_path(confdir, "rules"),
                                              variables, cfg.fw_zone,
                                              family)
    if os.path.exists(_path(confdir, "tunnels")):
        cfg.rules += parsers.parse_tunnels(_path(confdir, "tunnels"),
                                           variables, cfg.fw_zone)
    if os.path.exists(_path(confdir, "snat")):
        cfg.snat = parsers.parse_snat(_path(confdir, "snat"), variables,
                                      cfg.interfaces)
    if os.path.exists(_path(confdir, "masq")):
        cfg.snat += parsers.parse_masq(_path(confdir, "masq"), variables,
                                       cfg.interfaces)
    if os.path.exists(_path(confdir, "stoppedrules")):
        cfg.stoppedrules = parsers.parse_stoppedrules(
            _path(confdir, "stoppedrules"), variables, cfg.interfaces)
    if os.path.exists(_path(confdir, "conntrack")):
        cfg.helpers = parsers.parse_conntrack(
            _path(confdir, "conntrack"), variables, cfg.interfaces)
    if os.path.exists(_path(confdir, "accounting")):
        cfg.accounting = parsers.parse_accounting(
            _path(confdir, "accounting"), variables, cfg.interfaces)
    # REQUIRE_IPSETS=No downgrades an unsupported ipset from a hard error
    # to a warning, so one odd set does not fail the whole compile.
    strict_ipsets = variables.get("REQUIRE_IPSETS", "Yes").lower() \
        not in ("no", "0", "off")
    cfg.ipsets = ipsets.load_for(confdir, strict_ipsets)
    if os.path.exists(_path(confdir, "providers")):
        cfg.providers = parsers.parse_providers(
            _path(confdir, "providers"), variables, cfg.interfaces)
    if os.path.exists(_path(confdir, "rtrules")):
        cfg.rtrules = parsers.parse_rtrules(
            _path(confdir, "rtrules"), variables, cfg.interfaces,
            cfg.providers)
    if variables.get("TC_ENABLED", "").lower() not in ("no", ""):
        if os.path.exists(_path(confdir, "tcdevices")):
            cfg.tcdevices = parsers.parse_tcdevices(
                _path(confdir, "tcdevices"), variables, cfg.interfaces)
        if os.path.exists(_path(confdir, "tcclasses")):
            cfg.tcclasses = parsers.parse_tcclasses(
                _path(confdir, "tcclasses"), variables, cfg.interfaces)
        # Simple traffic shaping, an alternative to the classful pair.
        if os.path.exists(_path(confdir, "tcinterfaces")):
            cfg.tcinterfaces = parsers.parse_tcinterfaces(
                _path(confdir, "tcinterfaces"), variables, cfg.interfaces)
        if os.path.exists(_path(confdir, "tcpri")):
            cfg.tcpri = parsers.parse_tcpri(
                _path(confdir, "tcpri"), variables, cfg.interfaces)
    if os.path.exists(_path(confdir, "mangle")):
        cfg.mangle = parsers.parse_mangle(
            _path(confdir, "mangle"), variables, cfg.interfaces, family)
    if os.path.exists(_path(confdir, "netmap")):
        cfg.netmap = parsers.parse_netmap(
            _path(confdir, "netmap"), variables, cfg.interfaces)
    if os.path.exists(_path(confdir, "blrules")):
        cfg.blrules = parsers.parse_blrules(
            _path(confdir, "blrules"), variables, cfg.fw_zone, family)
    if os.path.exists(_path(confdir, "nat")):
        cfg.nat = parsers.parse_nat(
            _path(confdir, "nat"), variables, cfg.interfaces)
    if os.path.exists(_path(confdir, "ecn")):
        cfg.ecn = parsers.parse_ecn(
            _path(confdir, "ecn"), variables, cfg.interfaces)
    # proxyarp is an IPv4 file, proxyndp its IPv6 twin. Read the one
    # that matches this compile, mirroring shorewall and shorewall6.
    pfile = "proxyndp" if family == 6 else "proxyarp"
    if os.path.exists(_path(confdir, pfile)):
        cfg.proxyarp = parsers.parse_proxyarp(
            _path(confdir, pfile), variables, cfg.interfaces)
    if os.path.exists(_path(confdir, "routes")):
        cfg.routes = parsers.parse_routes(
            _path(confdir, "routes"), variables, cfg.interfaces,
            cfg.providers)
    if os.path.exists(_path(confdir, "maclist")):
        cfg.maclist = parsers.parse_maclist(
            _path(confdir, "maclist"), variables, cfg.interfaces)

    for name in sorted(os.listdir(confdir)):
        path = _path(confdir, name)
        if not os.path.isfile(path) or name in HANDLED | VARIABLE_FILES:
            continue
        if name in DEPRECATED and _has_content(path, variables):
            print(f"warning: {DEPRECATED[name]}", file=sys.stderr)
            continue
        if name in UNSUPPORTED and _has_content(path, variables):
            raise ConfigError(f"config file {name} is not supported yet")
        if (name in EXTENSIONS_LIFECYCLE or name in EXTENSIONS_WIRED_OTHER) \
                and os.path.getsize(path):
            with open(path) as f:
                cfg.extensions[name] = f.read()
        elif name in EXTENSIONS_UNWIRED and os.path.getsize(path):
            print(f"warning: extension script {name} is not run yet",
                  file=sys.stderr)
    return cfg


def compile_config(confdir, out_path, family=4, script_path=None):
    cfg = load(confdir, family)
    text = emit.render(cfg)
    with open(out_path, "w") as f:
        f.write(text)
    if script_path:
        stop_text = emit.render_stop(cfg)
        with open(script_path, "w") as f:
            f.write(script.render_script(cfg, text, stop_text))
        os.chmod(script_path, os.stat(script_path).st_mode
                 | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return cfg
