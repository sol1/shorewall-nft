"""Config file reader.

Reproduces the parts of Shorewall's line model the corpus needs:
comments, continuation lines, $variable expansion, ?FORMAT and
?SECTION directives, INCLUDE. Unsupported directives raise ConfigError
so nothing is dropped silently.
"""
import os
import re
import shutil
import subprocess

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
    try:
        return bool(eval(text, {"__builtins__": {}}))  # noqa: S307
    except (SyntaxError, TypeError):
        # The token whitelist admits shapes eval still rejects, e.g. a value
        # next to a parenthesis ("True(True)") raising TypeError.
        raise ConfigError(f"cannot evaluate ?IF expression: {expr}",
                          path, lineno)


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


def read_file(path, variables, max_format=2):
    """Yield logical Line objects from one config file. max_format is the
    highest ?FORMAT the file supports. Most files stop at 2; conntrack goes
    to 3."""
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
                try:
                    fmt = int(rest)
                except ValueError:
                    raise ConfigError(f"?FORMAT wants a number, got {rest!r}",
                                      path, buf_start)
                if not 1 <= fmt <= max_format:
                    raise ConfigError(f"unsupported ?FORMAT {fmt}",
                                      path, buf_start)
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
        parts = text.split(None, 1)
        if parts[0] == "INCLUDE":
            if len(parts) < 2 or not parts[1].strip():
                raise ConfigError("INCLUDE needs a file name", path, buf_start)
            inc = expand(parts[1].strip(), variables, path, buf_start)
            inc_path = os.path.join(os.path.dirname(path), inc)
            if not os.path.exists(inc_path):
                raise ConfigError(f"INCLUDE file not found: {inc}",
                                  path, buf_start)
            yield from read_file(inc_path, variables, max_format)
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


# Bash constructs that the simple reader cannot evaluate: a for/while/if block,
# a bash builtin, or command substitution. A params file using any of these is
# sourced through bash instead, the way upstream sources it.
_NEEDS_SHELL = re.compile(r"(^|\s)(for|while|if|case|declare|local|typeset)\s"
                          r"|\$\(|\bBASH_SOURCE\b|\[\[")


def needs_shell(path):
    """True if a variable file uses shell logic beyond KEY=VALUE and simple
    sourcing, so it must be sourced through bash rather than read line by line.
    A file it also sources is followed, since the logic may live there."""
    seen = set()

    def scan(p):
        if p in seen or not os.path.exists(p) or len(seen) > 20:
            return False
        seen.add(p)
        try:
            with open(p) as f:
                text = f.read()
        except OSError:
            return False
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if _NEEDS_SHELL.search(s):
                return True
            m = re.match(r"^(?:\.|source)\s+(\S+)", s)
            if m:
                nxt = os.path.join(os.path.dirname(p),
                                   os.path.basename(m.group(1).strip("\"'")))
                if scan(nxt):
                    return True
        return False

    return scan(path)


def read_shell_vars(path, confdir, seed=None):
    """Source a variable file through bash, the way upstream sources params, so
    a file that uses shell logic (loops, includes, bash builtins) works.
    g_confdir is set as shorewall sets it, and seed variables (from
    shorewall.conf, already read) are exported so the file may reference them.
    Returns the variables the file introduces, found by diffing the shell's
    variable list, or None if bash is missing or sourcing fails so the caller
    can fall back to the line reader. The caller must have checked the file's
    permissions first, since this executes it."""
    if not os.path.exists(path):
        return {}
    bash = shutil.which("bash") or (
        "/bin/bash" if os.path.exists("/bin/bash") else None)
    if not bash:
        return None
    script = (
        'g_confdir=$1\n'
        '__b=" $(compgen -v | tr "\\n" " ") "\n'
        '. "$2" || exit 3\n'
        'for __v in $(compgen -v); do\n'
        '  case "$__b" in *" $__v "*) continue;; esac\n'
        '  printf "%s=%s\\0" "$__v" "${!__v}"\n'
        'done\n')
    env = {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")}
    for k, v in (seed or {}).items():
        if re.fullmatch(r"[A-Za-z_]\w*", k):
            env[k] = str(v)
    try:
        r = subprocess.run([bash, "--norc", "--noprofile", "-c", script,
                            "bash", confdir, path],
                           capture_output=True, text=True, timeout=30, env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    # Bash bookkeeping a params file can introduce as a side effect (set -o
    # posix sets POSIXLY_CORRECT, and so on). These are not config variables.
    internal = {"__b", "__v", "POSIXLY_CORRECT", "FUNCNAME", "OPTIND",
                "OPTARG", "OPTERR", "PIPESTATUS"}
    out = {}
    for item in r.stdout.split("\0"):
        if not item:
            continue
        key, _, value = item.partition("=")
        if key not in internal:
            out[key] = value
    return out
