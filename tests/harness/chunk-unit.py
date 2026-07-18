#!/usr/bin/env python3
# Prove the ruleset chunker splits a monolithic nft ruleset into a
# fail-closed skeleton plus rule/element chunks without losing or
# duplicating anything, and keeps each chunk under the byte budget. The
# chunked path is the fallback for rulesets too large for one netlink
# transaction, so a lost rule there would silently drop protection.
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import chunk  # noqa: E402

fails = 0


def ok(name):
    print("PASS", name)


def bad(name):
    global fails
    print("FAIL", name)
    fails += 1


# Build a large, emitter-shaped ruleset: one set with many non-adjacent
# networks (so collapse does not merge them) and one chain with many rules,
# comfortably over the chunk byte budget so it must split into several.
TABLE = "ip shorewall"
nets = [f"10.{i // 256}.{i % 256}.0/24" for i in range(0, 4000, 2)]  # 2000, gapped
rules = [f"ip saddr 172.16.{i // 256}.{i % 256} tcp dport {1000 + i} accept"
         for i in range(1500)]

lines = [f"table {TABLE}", f"delete table {TABLE}", f"table {TABLE} {{",
         "    set big {", "        type ipv4_addr; flags interval; auto-merge;",
         "        elements = {"]
lines += ["            " + n + "," for n in nets[:-1]]
lines.append("            " + nets[-1])
lines += ["        }", "    }",
          "    chain input {",
          "        type filter hook input priority filter; policy drop;",
          "        ct state established,related accept"]
lines += ["        " + r for r in rules]
lines += ["    }", "}"]
ruleset = "\n".join(lines) + "\n"

skeleton, chunks = chunk.split(ruleset, TABLE)

# 1. Skeleton declares the table, set and chain with policy, but carries no
#    rules and no set elements: the window before the chunks load is closed.
(ok if all(s in skeleton for s in (
    f"table {TABLE} {{", "set big {", "flags interval",
    "chain input {", "policy drop;"))
 else bad)("skeleton declares the table, set and chain")
(ok if "elements = {" not in skeleton and "add rule" not in skeleton
    and "10.0.0.0/24" not in skeleton and "ct state established" not in skeleton
 else bad)("skeleton carries no elements and no rules")

# 2. Every rule body from the source chain appears exactly once as an
#    `add rule`, and none is lost.
chunk_text = "\n".join(chunks)
add_rules = [ln[len(f"add rule {TABLE} input "):]
             for ln in chunk_text.splitlines()
             if ln.startswith(f"add rule {TABLE} input ")]
want_rules = ["ct state established,related accept"] + rules
(ok if sorted(add_rules) == sorted(want_rules)
 else bad)(f"all {len(want_rules)} rules chunked, none lost or duplicated "
           f"(got {len(add_rules)})")

# 3. Every set element appears across the add element statements.
got_elems = set()
for m in re.findall(r"add element " + re.escape(TABLE)
                    + r" big \{ ([^}]*) \}", chunk_text):
    for e in m.split(","):
        got_elems.add(e.strip())
(ok if got_elems == set(nets)
 else bad)(f"all {len(nets)} set elements chunked (got {len(got_elems)})")

# 4. The split actually happened, and every chunk is under the byte budget.
(ok if len(chunks) >= 3 else bad)(f"large ruleset split into several chunks "
                                  f"(got {len(chunks)})")
(ok if all(len(c) <= chunk.CHUNK_BYTES for c in chunks)
 else bad)("every chunk is within the byte budget")

# 5. A small ruleset still round-trips: skeleton plus its one-or-more chunks.
small = (f"table {TABLE}\ndelete table {TABLE}\ntable {TABLE} {{\n"
         "    chain input {\n"
         "        type filter hook input priority filter; policy drop;\n"
         "        ip saddr 10.0.0.1 accept\n"
         "    }\n}\n")
sk, ch = chunk.split(small, TABLE)
(ok if "policy drop;" in sk and "add rule" not in sk
    and any("ip saddr 10.0.0.1 accept" in c for c in ch)
 else bad)("small ruleset: rule moves to a chunk, policy stays in skeleton")

sys.exit(1 if fails else 0)
