#!/usr/bin/env python3
# Compile every configuration shown in the documentation and check that nft
# accepts the result. A scenario page prints its configuration as fenced code
# blocks, each tagged with the file it belongs to:
#
#     ```text title="/etc/shorewall/zones"
#     fw      firewall
#     net     ipv4
#     loc     ipv4
#     ```
#
# This proof reads those blocks out of docs-site/docs, writes them to a
# configuration directory, compiles it with shorewall-nft, and runs the
# generated ruleset through "nft -c". A page that shows a configuration the
# compiler rejects fails the suite, so the examples in the documentation are
# the examples the test kernel accepts. No example drifts from what works.
#
# A page carries directives in an HTML comment:
#
#     <!-- docs-proof: skip -->                 do not compile this page
#     <!-- docs-proof: base=getting-started/two-interface.md -->
#                                               start from that page's files,
#                                               then overlay this page's files
#     <!-- docs-proof: family=6 -->             compile for IPv6
#
# A page that shows only part of a configuration (a rules snippet, say) names a
# base page so the snippet is compiled in a working context. A page with
# nothing to compile is reported and skipped.
import os
import re
import stat
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
DOCS = os.path.join(REPO, "docs-site", "docs")
SRC = os.path.join(REPO, "src")

FENCE_RE = re.compile(r"^(`{3,})(.*)$")
TITLE_RE = re.compile(r'title="([^"]+)"')
DIRECTIVE_RE = re.compile(r"<!--\s*docs-proof:\s*(.*?)\s*-->")
PATH_RE = re.compile(r"^/etc/(shorewall6?)/([A-Za-z0-9_.\-]+)$")

# The three files that make a configuration the compiler will accept. A page
# with all three (on its own or through a base) is compiled.
REQUIRED = {"zones", "interfaces", "policy"}


def find_tool(name, fallback):
    for d in os.environ.get("PATH", "").split(os.pathsep) + ["/usr/sbin", "/sbin",
                                                             "/usr/bin", "/bin"]:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return fallback


NFT = find_tool("nft", "/usr/sbin/nft")
UNSHARE = find_tool("unshare", "/usr/bin/unshare")


def parse_page(path):
    """Return (files, directives, v6) for one Markdown page.

    files maps a Shorewall file name to its contents. directives is the parsed
    docs-proof comment. v6 is true when any block names a shorewall6 path.
    """
    files = {}
    directives = {}
    v6 = False
    in_block = False
    fence = ""
    name = None
    buf = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if in_block:
                if line.strip() and set(line.strip()) == {"`"} \
                        and len(line.strip()) >= len(fence):
                    if name is not None:
                        files[name] = "\n".join(buf) + "\n"
                    in_block = False
                    name = None
                    buf = []
                else:
                    buf.append(line)
                continue
            m = FENCE_RE.match(line)
            if m:
                fence = m.group(1)
                tm = TITLE_RE.search(m.group(2))
                in_block = True
                name = None
                buf = []
                if tm:
                    pm = PATH_RE.match(tm.group(1))
                    if pm:
                        if pm.group(1) == "shorewall6":
                            v6 = True
                        name = pm.group(2)
                continue
            dm = DIRECTIVE_RE.search(line)
            if dm:
                for tok in dm.group(1).split():
                    if "=" in tok:
                        k, val = tok.split("=", 1)
                        directives[k] = val
                    else:
                        directives[tok] = True
    return files, directives, v6


def write_config(files):
    d = tempfile.mkdtemp(prefix="docs-config-")
    os.chmod(d, stat.S_IRWXU)
    for name, content in files.items():
        fp = os.path.join(d, name)
        with open(fp, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(fp, stat.S_IRUSR | stat.S_IWUSR)
    return d


def compile_config(cfgdir, family):
    out = os.path.join(cfgdir, "fw.nft")
    env = dict(os.environ, PYTHONPATH=SRC, SHOREWALL_NFT_STATIC_CAPS="1")
    r = subprocess.run([sys.executable, "-m", "shorewall_nft", "compile",
                        cfgdir, "-o", out, "--family", str(family)],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout).strip()
    return out, ""


def nft_check(out):
    r = subprocess.run([UNSHARE, "-r", "-n", NFT, "-c", "-f", out],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()


def pages():
    for root, _, names in os.walk(DOCS):
        for n in sorted(names):
            if n.endswith(".md"):
                yield os.path.join(root, n)


def main():
    if not os.path.isdir(DOCS):
        print("no docs-site/docs, nothing to verify")
        return 0

    compiled = skipped = failed = 0
    for path in pages():
        rel = os.path.relpath(path, DOCS)
        files, directives, v6 = parse_page(path)

        if directives.get("skip"):
            continue

        family = int(directives.get("family", 6 if v6 else 4))

        base = directives.get("base")
        if base:
            base_path = os.path.join(DOCS, base)
            if not os.path.exists(base_path):
                print(f"FAIL {rel}: base page {base} not found")
                failed += 1
                continue
            base_files, _, base_v6 = parse_page(base_path)
            merged = dict(base_files)
            merged.update(files)
            files = merged
            if "family" not in directives and base_v6:
                family = 6

        if not files:
            continue

        if not REQUIRED.issubset(files):
            # Some config blocks, but not a whole configuration and no base to
            # complete it. A partial snippet without a base cannot be compiled.
            if "zones" in files:
                print(f"FAIL {rel}: incomplete configuration "
                      f"(has {sorted(files)}, needs {sorted(REQUIRED)}); "
                      f"add the missing files or a base= directive")
                failed += 1
            else:
                print(f"note {rel}: partial snippet, add base= to verify it")
                skipped += 1
            continue

        cfgdir = write_config(files)
        out, err = compile_config(cfgdir, family)
        if out is None:
            print(f"FAIL {rel}: compile rejected the configuration\n{err}")
            failed += 1
            continue
        ok, err = nft_check(out)
        if not ok:
            print(f"FAIL {rel}: nft rejected the ruleset\n{err}")
            failed += 1
            continue
        print(f"PASS {rel} (family {family})")
        compiled += 1

    print(f"\ndocs examples: {compiled} compiled, {skipped} skipped, "
          f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
