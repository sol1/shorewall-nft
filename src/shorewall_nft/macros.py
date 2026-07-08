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
from dataclasses import dataclass

from .errors import ConfigError
from .reader import read_file, split_columns

MACRO_DIR = os.path.join(os.path.dirname(__file__), "data", "macros")
MACRO_DIR6 = os.path.join(os.path.dirname(__file__), "data", "macros6")
TERMINAL = {"ACCEPT", "DROP", "REJECT"}
AUDIT = {"A_ACCEPT": "ACCEPT", "A_DROP": "DROP", "A_REJECT": "REJECT"}
MAX_DEPTH = 10

# User-defined actions declared in the actions file, defined in
# action.<name> in the config directory. Set per compile.
_ACTION_DIR = None
_ACTION_NAMES = set()


def set_user_actions(action_dir, names):
    global _ACTION_DIR, _ACTION_NAMES
    _ACTION_DIR = action_dir
    _ACTION_NAMES = set(names)


@dataclass
class MacroRule:
    action: str               # terminal action
    audit: bool
    proto: str
    dport: str
    sport: str
    src: tuple                # (side, addr): side is 'SOURCE' or 'DEST'
    dst: tuple


def _find(name, family):
    """A declared user action shadows the shipped macros. Then family 6
    macro overrides, then the shared macros."""
    if name in _ACTION_NAMES and _ACTION_DIR:
        path = os.path.join(_ACTION_DIR, f"action.{name}")
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


def _compose(inner, outer_src, outer_dst):
    """Resolve an inner (side, addr) against the outer invocation."""
    side, addr = inner
    outer = outer_src if side == "SOURCE" else outer_dst
    if addr and outer[1]:
        raise ConfigError("nested macro address restrictions collide")
    return (outer[0], addr or outer[1])


def _load(name, variables, family=4):
    path = _find(name, family)
    entries = []
    for line in read_file(path, variables):
        cols = split_columns(line.text, line.path, line.lineno)
        if len(cols) > 6:
            raise line.error(f"macro {name}: extra columns not supported yet")
        entries.append((
            cols[0],
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
           dst=("DEST", ""), depth=0):
    """Return a list of MacroRule resolved against the invocation."""
    if depth > MAX_DEPTH:
        raise ConfigError(f"macro {name}: expansion too deep")
    out = []
    default = ""
    for target, msrc, mdst, proto, dport, sport in _load(name, variables,
                                                         family):
        if target in ("DEFAULT", "DEFAULTS"):
            # The first parameter's default; DEFAULTS may list several.
            default = msrc[1].split(",")[0] if msrc[1] else ""
            continue
        rsrc = _compose(msrc, src, dst)
        rdst = _compose(mdst, src, dst)
        audit = False
        if target == "PARAM":
            disposition = param or default
            if not disposition:
                raise ConfigError(f"macro {name} needs a parameter")
        elif target in TERMINAL:
            disposition = target
        elif target in AUDIT:
            disposition = AUDIT[target]
            audit = True
        elif exists(target, family):
            out.extend(expand(target, param, variables, family, rsrc, rdst,
                              depth + 1))
            continue
        else:
            raise ConfigError(f"macro {name}: unsupported target {target}")
        if disposition in AUDIT:
            disposition = AUDIT[disposition]
            audit = True
        if disposition not in TERMINAL:
            raise ConfigError(f"macro {name}: unsupported disposition "
                              f"{disposition}")
        out.append(MacroRule(action=disposition, audit=audit, proto=proto,
                             dport=dport, sport=sport, src=rsrc, dst=rdst))
    return out
