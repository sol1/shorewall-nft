"""Macro expansion from real Shorewall macro files.

The macro files under data/macros are copies of upstream's Macros
directory. A macro line is ACTION SOURCE DEST PROTO DPORT SPORT.

ACTION is PARAM (replaced by the invocation parameter), a terminal
action, an audit variant (A_ACCEPT, A_DROP, A_REJECT), or another
macro name, which expands recursively.

SOURCE and DEST columns take '-' (inherit), 'SOURCE' or 'DEST'
(select an invocation side, enabling bidirectional macros), either
keyword with ':address', or a bare address which restricts the
inherited side. Swaps compose through nested macros.
"""
import os
import re
from dataclasses import dataclass

from .errors import ConfigError
from .reader import read_file, split_columns

MACRO_DIR = os.path.join(os.path.dirname(__file__), "data", "macros")
MACRO_DIR6 = os.path.join(os.path.dirname(__file__), "data", "macros6")
TERMINAL = {"ACCEPT", "DROP", "REJECT"}
AUDIT = {"A_ACCEPT": "ACCEPT", "A_DROP": "DROP", "A_REJECT": "REJECT"}
MAX_DEPTH = 10

# The ACTION column grammar shared by rules-file lines and action-file body
# lines: a name, an optional -/+/! modifier, an optional (param) or /sparam,
# and an optional :loglevel[:tag] suffix. parsers.py uses this one rather
# than defining its own, since macros.py has no dependency the other way.
ACTION_RE = re.compile(r"^(?P<name>[A-Za-z]\w*)(?P<mod>[-+!])?"
                       r"(\((?P<param>[^)]*)\)|/(?P<sparam>[\w!]+))?"
                       r"(:(?P<loglevel>\w+)(:(?P<logtag>[\w.-]+))?)?$")

# SetEvent/ResetEvent/IfEvent, the native event actions. Upstream spells
# them mixed-case; the uppercase form is also accepted, matching how
# KNOCK/KNOCKSEQUENCE are spelled.
EVENT_ACTIONS = {
    "SetEvent": "set", "SETEVENT": "set",
    "ResetEvent": "reset", "RESETEVENT": "reset",
    "IfEvent": "if", "IFEVENT": "if",
}
_EVENT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,28}$")
_EVENT_DISPOSITIONS = {"ACCEPT", "DROP", "REJECT", "COUNT"}
_EVENT_AUDIT = {"A_ACCEPT": "ACCEPT", "A_DROP": "DROP", "A_REJECT": "REJECT"}

# User-defined actions declared in the actions file, defined in
# action.<name> in the config directory. Set per compile.
_ACTION_DIR = None
_ACTION_NAMES = set()

# Directories searched for a site macro.<name> or action.<name>, from
# CONFIG_PATH plus the config directory. A site file shadows the shipped
# macros, matching upstream, which finds them through CONFIG_PATH. Set per
# compile.
_CONFIG_PATH = []


def set_user_actions(action_dir, names):
    global _ACTION_DIR, _ACTION_NAMES
    _ACTION_DIR = action_dir
    _ACTION_NAMES = set(names)


def set_config_path(dirs):
    global _CONFIG_PATH
    _CONFIG_PATH = list(dirs)


@dataclass
class MacroRule:
    action: str               # terminal action
    audit: bool
    proto: str
    dport: str
    sport: str
    src: tuple                # (side, addr): side is 'SOURCE' or 'DEST'
    dst: tuple
    event: tuple = ()         # SetEvent/ResetEvent/IfEvent payload, or ()


def _find(name, family):
    """Resolve a macro or action name to a file. A declared user action is
    found as action.<name> in the config directory, then in the CONFIG_PATH
    directories. A macro is found as macro.<name> in the CONFIG_PATH
    directories, so a site macro shadows a shipped one, matching upstream, then
    as the shipped family-6 override, then the shared shipped macro."""
    if name in _ACTION_NAMES:
        for d in ([_ACTION_DIR] if _ACTION_DIR else []) + _CONFIG_PATH:
            path = os.path.join(d, f"action.{name}")
            if os.path.isfile(path):
                return path
    for d in _CONFIG_PATH:
        path = os.path.join(d, f"macro.{name}")
        if os.path.isfile(path):
            return path
    if family == 6:
        path = os.path.join(MACRO_DIR6, f"macro.{name}")
        if os.path.isfile(path):
            return path
    path = os.path.join(MACRO_DIR, f"macro.{name}")
    return path if os.path.isfile(path) else None


def exists(name, family=4):
    return _find(name, family) is not None


def _parse_side(col, own, line, name):
    """Parse a SOURCE or DEST column into (side, addr)."""
    if col in ("-", ""):
        return (own, "")
    if "{" in col or "=" in col:
        raise line.error(f"macro {name}: column pairs not supported yet")
    base, _, addr = col.partition(":")
    if base in ("SOURCE", "DEST"):
        return (base, addr)
    return (own, col)


def _err(line, message):
    """A ConfigError carrying the invoking line's file:line when known."""
    return line.error(message) if line is not None else ConfigError(message)


def _compose(inner, outer_src, outer_dst, line=None):
    """Resolve an inner (side, addr) against the outer invocation."""
    side, addr = inner
    outer = outer_src if side == "SOURCE" else outer_dst
    if addr and outer[1]:
        raise _err(line, "nested macro address restrictions collide")
    return (outer[0], addr or outer[1])


def rate_for(count, interval):
    """The nft rate for count events in interval seconds. Clean intervals
    map to an nft unit; others are scaled to per-minute with a burst so the
    window is still honoured. Shared by AutoBL and IfEvent rate tests."""
    units = {1: "second", 60: "minute", 3600: "hour", 86400: "day"}
    if interval in units:
        return f"{count}/{units[interval]}"
    per_min = max(1, round(count * 60 / interval))
    return f"{per_min}/minute burst {count} packets"


def _parse_event_action_param(text, default, line, label):
    """Parse an event action sub-parameter: DISP[:loglevel[:tag]]. DISP is
    ACCEPT/DROP/REJECT, COUNT or LOG (both a no-op, matching upstream's
    plain-log/counter event actions), or an A_ audit variant. A nested
    action or macro name here is not supported yet; only a rule's own
    ACTION column expands those."""
    text = text.strip() or default
    disp, _, rest = text.partition(":")
    loglevel, _, logtag = rest.partition(":")
    audit = False
    if disp == "LOG":
        disp = "COUNT"
    if disp in _EVENT_AUDIT:
        audit = True
        disp = _EVENT_AUDIT[disp]
    if disp not in _EVENT_DISPOSITIONS:
        raise _err(line, f"{label} action must be ACCEPT, DROP, REJECT, "
                   f"COUNT, LOG or an A_ audit variant, not {disp!r} (a "
                   "nested action or macro name is not supported yet)")
    return disp, audit, loglevel.lower(), logtag


def parse_event(name, param, line):
    """Parse a SetEvent/ResetEvent/IfEvent invocation into the Rule.event
    tuple: (kind, event, disposition, audit, loglevel, logtag, side,
    duration, hitcount, rate, command, reap, logword).

    kind is 'set', 'reset' or 'if'. duration/hitcount are 0/1 when the
    doc's own default ('not time-constrained' / '1 packet') applies.
    rate is the precomputed nft meter rate ('5/minute'), set only when
    hitcount > 1. command is only meaningful for 'if' ('check', 'reset'
    or 'update'). logword optionally overrides the disposition word in
    the log prefix.
    """
    kind = EVENT_ACTIONS[name]
    parts = [p.strip() for p in param.split(",")] if param else []

    def col(i, default=""):
        return parts[i] if i < len(parts) and parts[i] not in ("", "-") \
            else default

    event = col(0)
    if not event:
        raise _err(line, f"{name} needs an event name")
    if not _EVENT_NAME_RE.match(event):
        raise _err(line, f"invalid event name {event!r}: must start with a "
                   "letter, hold only letters, digits, '_' or '-', and be "
                   "at most 29 characters")

    duration = hitcount = 0
    command = ""
    reap = False
    rate = ""
    if kind == "if":
        disp, audit, loglevel, logtag = _parse_event_action_param(
            col(1), "ACCEPT", line, name)
        duration_s = col(2)
        if duration_s:
            if not duration_s.isdigit() or int(duration_s) <= 0:
                raise _err(line, f"{name} duration must be a positive number")
            duration = int(duration_s)
        hitcount_s = col(3)
        hitcount = 1
        if hitcount_s:
            if not hitcount_s.isdigit() or int(hitcount_s) <= 0:
                raise _err(line, f"{name} hitcount must be a positive number")
            hitcount = int(hitcount_s)
        if hitcount > 1:
            # A rate test needs a time window; xt_recent's unconstrained
            # hitcount-only form has no nft meter equivalent.
            if not duration:
                raise _err(line, f"{name}: hitcount > 1 needs an explicit "
                           "duration; an unconstrained hitcount test is not "
                           "supported yet")
            rate = rate_for(hitcount, duration)
        side = col(4, "src")
        cmd_parts = col(5, "check").split(":")
        command = cmd_parts[0] or "check"
        if command not in ("check", "reset", "update"):
            raise _err(line, f"{name} command must be check, reset or "
                       f"update, not {command!r}")
        if command != "check" and hitcount > 1:
            raise _err(line, f"{name}: command {command!r} is only "
                       "supported with hitcount 1 (a rate test always "
                       "samples the current packet, so it cannot also "
                       "reset or force-update)")
        for opt in cmd_parts[1:]:
            if opt == "reap":
                reap = True
            elif opt == "ttl":
                raise _err(line, f"{name} ttl option needs the original "
                           "packet's TTL remembered per event entry, which "
                           "shorewall-nft does not support yet")
            elif opt:
                raise _err(line, f"{name} unsupported command option "
                           f"{opt!r}")
        logword = col(6)
    else:
        default_disp = "COUNT" if kind == "set" else "ACCEPT"
        disp, audit, loglevel, logtag = _parse_event_action_param(
            col(1), default_disp, line, name)
        side = col(2, "src")
        logword = col(3)

    if side not in ("src", "dst"):
        raise _err(line, f"{name} src-dst must be src or dst, not {side!r}")

    return (kind, event, disp, audit, loglevel, logtag, side, duration,
            hitcount, rate, command, reap, logword)


def _load(name, variables, family=4):
    path = _find(name, family)
    entries = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) > 6:
            raise line.error(f"macro {name}: extra columns not supported yet")
        m = ACTION_RE.match(cols[0])
        if not m:
            raise line.error(f"cannot parse action {cols[0]}")
        entries.append((
            m.group("name"),
            m.group("param") or m.group("sparam") or "",
            _parse_side(cols[1] if len(cols) > 1 else "-", "SOURCE",
                        line, name),
            _parse_side(cols[2] if len(cols) > 2 else "-", "DEST",
                        line, name),
            cols[3] if len(cols) > 3 and cols[3] != "-" else "",
            cols[4] if len(cols) > 4 and cols[4] != "-" else "",
            cols[5] if len(cols) > 5 and cols[5] != "-" else "",
        ))
    return entries


def expand(name, param, variables, family=4, src=("SOURCE", ""),
           dst=("DEST", ""), depth=0, line=None):
    """Return a list of MacroRule resolved against the invocation. line is
    the rules line that invoked the macro; it labels any error with the
    file and line the user can act on."""
    if depth > MAX_DEPTH:
        raise _err(line, f"macro {name}: expansion too deep")
    out = []
    default = ""
    for target, tparam, msrc, mdst, proto, dport, sport in _load(
            name, variables, family):
        if target in ("DEFAULT", "DEFAULTS"):
            # The first parameter's default; DEFAULTS may list several.
            default = msrc[1].split(",")[0] if msrc[1] else ""
            continue
        rsrc = _compose(msrc, src, dst, line)
        rdst = _compose(mdst, src, dst, line)
        audit = False
        if target in EVENT_ACTIONS:
            event = parse_event(target, tparam, line)
            out.append(MacroRule(action="ACCEPT", audit=False, proto=proto,
                                 dport=dport, sport=sport, src=rsrc,
                                 dst=rdst, event=event))
            continue
        if target == "PARAM":
            disposition = param or default
            if not disposition:
                raise _err(line, f"macro {name} needs a parameter")
        elif target in TERMINAL:
            disposition = target
        elif target in AUDIT:
            disposition = AUDIT[target]
            audit = True
        elif exists(target, family):
            out.extend(expand(target, param, variables, family, rsrc, rdst,
                              depth + 1, line))
            continue
        else:
            raise _err(line, f"macro {name}: unsupported target {target}")
        if disposition in AUDIT:
            disposition = AUDIT[disposition]
            audit = True
        if disposition not in TERMINAL:
            raise _err(line, f"macro {name}: unsupported disposition "
                       f"{disposition}")
        out.append(MacroRule(action=disposition, audit=audit, proto=proto,
                             dport=dport, sport=sport, src=rsrc, dst=rdst))
    return out
