"""Config file reader.

Reproduces the parts of Shorewall's line model the corpus needs:
comments, continuation lines, $variable expansion, ?FORMAT and
?SECTION directives, INCLUDE. Unsupported directives raise ConfigError
so nothing is dropped silently.
"""
import os
import re

from . import capabilities
from .errors import ConfigError

VAR_RE = re.compile(r"\$(\{(?P<braced>\w+)\}|(?P<plain>\w+))")

TRUTHY = {"yes", "1", "on"}
FALSY = {"no", "0", "off", ""}


def _truthy(value):
    v = value.strip().lower()
    if v in TRUTHY:
        return True
    if v in FALSY:
        return False
    return True


def evaluate(expr, variables, path, lineno):
    """Evaluate a ?IF expression. Supports variables, __CAPABILITY__
    names, negation, && and || and parentheses. Anything else is an
    error. Upstream evaluates these as Perl; this covers the forms that
    appear in config files and macros."""
    def cap_sub(m):
        return str(capabilities.lookup(m.group(1)))

    def var_sub(m):
        name = m.group("braced") or m.group("plain")
        return str(_truthy(variables.get(name, "")))

    text = re.sub(r"__(\w+)", cap_sub, expr)
    text = VAR_RE.sub(var_sub, text)
    text = text.replace("&&", " and ").replace("||", " or ")
    text = re.sub(r"!(?!=)", " not ", text)
    if not re.fullmatch(r"[\s()]*((True|False|and|or|not)[\s()]*)+", text):
        raise ConfigError(f"cannot evaluate ?IF expression: {expr}",
                          path, lineno)
    return bool(eval(text, {"__builtins__": {}}))  # noqa: S307


class Line:
    def __init__(self, path, lineno, text, section=None, fmt=1):
        self.path = path
        self.lineno = lineno
        self.text = text
        self.section = section
        self.fmt = fmt

    def error(self, message):
        return ConfigError(message, self.path, self.lineno)


def expand(text, variables, path, lineno):
    def sub(m):
        name = m.group("braced") or m.group("plain")
        if name not in variables:
            raise ConfigError(f"undefined variable ${name}", path, lineno)
        return variables[name]
    return VAR_RE.sub(sub, text)


def read_file(path, variables):
    """Yield logical Line objects from one config file."""
    section = None
    fmt = 1
    # Each ?IF pushes [condition, any_branch_taken]. A line is live
    # when every frame's condition is true.
    ifstack = []
    with open(path) as f:
        raw = f.readlines()
    lineno = 0
    buf = ""
    buf_start = 0
    for physical in raw:
        lineno += 1
        line = physical.rstrip("\n")
        if not buf:
            buf_start = lineno
        if line.endswith("\\"):
            buf += line[:-1]
            continue
        buf += line
        text, buf = buf.strip(), ""
        if not text or text.startswith("#"):
            continue
        # Inline comments: a # preceded by whitespace.
        m = re.search(r"\s#", text)
        if m:
            text = text[:m.start()].strip()
            if not text:
                continue
        live = all(frame[0] for frame in ifstack)
        if text.startswith("?"):
            directive, _, rest = text.partition(" ")
            directive = directive.upper()
            rest = rest.strip()
            if directive == "?IF":
                cond = live and evaluate(rest, variables, path, buf_start)
                ifstack.append([cond, cond])
            elif directive == "?ELSIF":
                if not ifstack:
                    raise ConfigError("?ELSIF without ?IF", path, buf_start)
                frame = ifstack[-1]
                outer = all(f[0] for f in ifstack[:-1])
                cond = (outer and not frame[1]
                        and evaluate(rest, variables, path, buf_start))
                frame[0] = cond
                frame[1] = frame[1] or cond
            elif directive == "?ELSE":
                if not ifstack:
                    raise ConfigError("?ELSE without ?IF", path, buf_start)
                frame = ifstack[-1]
                outer = all(f[0] for f in ifstack[:-1])
                frame[0] = outer and not frame[1]
                frame[1] = True
            elif directive == "?ENDIF":
                if not ifstack:
                    raise ConfigError("?ENDIF without ?IF", path, buf_start)
                ifstack.pop()
            elif not live:
                pass
            elif directive == "?FORMAT":
                fmt = int(rest)
            elif directive == "?SECTION":
                section = rest.upper()
            elif directive == "?COMMENT":
                pass
            else:
                raise ConfigError(f"unsupported directive {directive}",
                                  path, buf_start)
            continue
        if not live:
            continue
        if text.startswith("INCLUDE"):
            inc = text.split(None, 1)[1]
            inc_path = os.path.join(os.path.dirname(path), inc)
            yield from read_file(inc_path, variables)
            continue
        text = expand(text, variables, path, buf_start)
        yield Line(path, buf_start, text, section=section, fmt=fmt)
    if ifstack:
        raise ConfigError("?IF without ?ENDIF", path, lineno)


def split_inline(text):
    """Split a rule line at its first semicolon into the Shorewall
    columns and the inline passthrough. Everything after the first
    ';' (a lone ';' or the INLINE ';;') is raw nft, kept whole. Returns
    (columns_text, inline_text_or_None)."""
    i = text.find(";")
    if i < 0:
        return text, None
    return text[:i], text[i:].lstrip(";").strip()


def split_columns(text, path=None, lineno=None):
    """Split a config line into columns. Parenthesised groups stay
    together. A semicolon here means an inline passthrough reached a
    file that does not support one; the caller should have split it off."""
    if ";" in text:
        raise ConfigError("';' inline passthrough not supported in this file",
                          path, lineno)
    cols = []
    depth = 0
    cur = ""
    for ch in text:
        if ch == "(":
            depth += 1
            cur += ch
        elif ch == ")":
            depth -= 1
            cur += ch
        elif ch.isspace() and depth == 0:
            if cur:
                cols.append(cur)
                cur = ""
        else:
            cur += ch
    if cur:
        cols.append(cur)
    # A column ending in a comma continues in the next column. Upstream
    # allows address lists split across continuation lines this way.
    merged = []
    for col in cols:
        if merged and merged[-1].endswith(","):
            merged[-1] += col
        else:
            merged.append(col)
    return merged


def read_simple_vars(path, depth=0, variables=None):
    """Read KEY=VALUE lines from params or shorewall.conf. Sourcing
    lines (. or source) follow the referenced file by basename in the
    same directory, the common pattern for site variable files.
    References to earlier variables expand sequentially with shell
    semantics: an undefined reference becomes empty. Other shell
    constructs are ignored."""
    if variables is None:
        variables = {}
    if not os.path.exists(path) or depth > 5:
        return variables
    assign = re.compile(r"^([A-Za-z_]\w*)=(.*)$")
    source = re.compile(r"^(?:\.|source)\s+(\S+)")

    def sub(m):
        return variables.get(m.group("braced") or m.group("plain"), "")

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            s = source.match(line)
            if s:
                sourced = os.path.join(os.path.dirname(path),
                                       os.path.basename(s.group(1)))
                read_simple_vars(sourced, depth + 1, variables)
                continue
            m = assign.match(line)
            if not m:
                continue
            key, value = m.group(1), m.group(2).strip()
            if value[:1] in "\"'" and value[-1:] == value[:1]:
                value = value[1:-1]
            variables[key] = VAR_RE.sub(sub, value)
    return variables
