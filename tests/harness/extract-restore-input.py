#!/usr/bin/env python3
"""Extract the iptables-restore payload from a compiled Shorewall script.

The generated script writes the payload to fd 3 as one or more heredocs:

    exec 3>${VARDIR}/.iptables-restore-input
    cat >&3 << __EOF__
    ...
    __EOF__
    ...
    exec 3>&-

Usage: extract-restore-input.py FIREWALL_SCRIPT [--stop]

--stop extracts the stopped-state payload (.iptables-restore-stop-input)
instead of the start payload. Runtime chain-name variables are replaced
with fixed tokens so the output loads standalone.
"""
import re
import sys

SUBS = [("$g_sha1sum1", "shorewall_sha1a"), ("$g_sha1sum2", "shorewall_sha1b")]


def extract(path, stop=False):
    suffix = "-restore-stop-input" if stop else "-restore-input"
    anchor = re.compile(r"exec 3>\$\{VARDIR\}/\.ip6?tables"
                        + re.escape(suffix) + r"\s*$")
    out, active, heredoc = [], False, False
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if not active:
                if anchor.search(stripped):
                    active = True
                continue
            if heredoc:
                if stripped == "__EOF__":
                    heredoc = False
                else:
                    text = line.rstrip("\n")
                    for old, new in SUBS:
                        text = text.replace(old, new)
                    out.append(text)
            elif stripped.startswith("cat >&3 <<"):
                heredoc = True
            elif stripped.startswith("exec 3>&-"):
                break
    if not out:
        sys.exit(f"no payload found for {which} in {path}")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    args = sys.argv[1:]
    stop = "--stop" in args
    args = [a for a in args if a != "--stop"]
    if len(args) != 1:
        sys.exit(__doc__)
    sys.stdout.write(extract(args[0], stop))
