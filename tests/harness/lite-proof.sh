#!/bin/bash
# Shorewall Lite simulation. Prove that `compile -e` produces a self-contained
# firewall script that a Python-free, source-free target runs with only a base
# system plus nft and ip, that it validates and drives its lifecycle there, and
# that it yields the same packet verdicts as the full stack. See
# docs/design/lite.md.
#
# Four layers:
#   1. Static    - the artifact is #!/bin/sh, has no python, no bashisms, no
#                  build-host paths, and calls only lite tools.
#   2. Shell     - it parses under dash and, when present, busybox ash.
#   3. Behaviour - loaded by running the script (not the compiler), it gives
#                  the verdicts the case expects.
#   4. Isolation - in a fresh net+mount namespace with python shadowed and the
#                  source tree absent, check/start/status/stop/clear all work
#                  and python is never invoked.
set -u
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
REPO=$(cd "$(dirname "$0")/../.." && pwd)

# Representative configs: filter+zones, and DNAT (nat table). Both have probes.
CASES="0003-two-interfaces 0005-dnat"
ISOLATION_CASE=0005-dnat

pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; FAIL=1; }

if [ -z "${SWNFT_IN_SANDBOX:-}" ]; then
    FAIL=0
    OUT=$(mktemp -d)
    trap 'rm -rf "$OUT"' EXIT

    # --- Layer 1 + 2: build the export artifact and inspect it ---
    art="$OUT/firewall"
    PYTHONPATH=$REPO/src python3 -m shorewall_nft compile -e \
        "$REPO/tests/corpus/$ISOLATION_CASE/config" \
        -o "$OUT/ruleset.nft" --script "$art" >/dev/null

    [ "$(head -1 "$art")" = "#!/bin/sh" ] \
        && pass "artifact is #!/bin/sh" || bad "artifact shebang is not /bin/sh"
    if grep -q python "$art"; then bad "artifact references python"
    else pass "artifact has no python reference"; fi
    if grep -Eq '\[\[|(^|[[:space:]])local[[:space:]]|echo -e|<<<|\bfunction[[:space:]]' "$art"; then
        bad "artifact contains a bashism"
    else pass "artifact has no bashisms"; fi
    # Executable lines must carry no build-host or source path. A provenance
    # comment ("# Generated ... from <dir>") is fine, so ignore comment lines.
    if grep -vE '^[[:space:]]*#' "$art" \
         | grep -Eq "$REPO|PYTHONPATH|shorewall_nft|/etc/shorewall[/ ]"; then
        bad "artifact bakes a build-host or source path into executable code"
    else pass "artifact bakes no build-host path into executable code"; fi
    # Every external command it runs must be in the lite base set.
    forbidden=$(grep -oE '\b(python[0-9]*|perl|iptables[^ ]*|ip6tables[^ ]*|ipset|conntrack)\b' "$art" | sort -u | tr '\n' ' ')
    if [ -n "$forbidden" ]; then bad "artifact needs a non-lite tool: $forbidden"
    else pass "artifact calls only lite tools (nft, ip, tc, sysctl)"; fi

    if command -v dash >/dev/null 2>&1; then
        dash -n "$art" && pass "dash -n accepts the artifact (POSIX)" \
            || bad "dash rejects the artifact"
    fi
    if command -v busybox >/dev/null 2>&1 && busybox ash -c true 2>/dev/null; then
        busybox ash -n "$art" && pass "busybox ash -n accepts the artifact" \
            || bad "busybox ash rejects the artifact"
    else
        echo "SKIP busybox ash not available"
    fi
    if command -v checkbashisms >/dev/null 2>&1; then
        checkbashisms -f -p "$art" >/dev/null 2>&1 \
            && pass "checkbashisms is clean" || bad "checkbashisms flagged the artifact"
    fi

    # --- Layer 3: behavioural parity, loaded by the SCRIPT ---
    for case in $CASES; do
        cdir="$REPO/tests/corpus/$case"
        PYTHONPATH=$REPO/src python3 -m shorewall_nft compile -e \
            "$cdir/config" -o "$OUT/$case.nft" --script "$OUT/$case.fw" >/dev/null
        if PYTHONPATH=$REPO/src python3 "$REPO/tests/harness/sandbox.py" \
               "$cdir" --load "script:$OUT/$case.fw" > "$OUT/$case.json" 2>"$OUT/$case.err"; then
            PYTHONPATH=$REPO/src python3 - "$cdir/case.toml" "$OUT/$case.json" "$case" <<'PY'
import json, sys
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
conf, jf, name = sys.argv[1], sys.argv[2], sys.argv[3]
case = tomllib.load(open(conf, "rb"))
doc = json.load(open(jf))
vmap = {v["id"]: v for v in doc.get("verdicts", [])}
probes = list(case.get("probes", []))
for ev in case.get("events", []):
    probes += ev.get("probes", [])
bad = 0
for p in probes:
    v = vmap.get(p["id"])
    want = p["expect"]
    got = (v or {}).get("verdict")
    if p["proto"] == "icmp":
        if want in ("drop", "reject", "blocked"):
            want = "blocked"
        if got not in ("allow", None):
            got = "blocked"
    if got != want:
        print(f"FAIL {name}: {p['id']} expected {want}, got {got}")
        bad = 1
    elif p.get("peer") and (v or {}).get("peer") != p["peer"]:
        print(f"FAIL {name}: {p['id']} expected peer {p['peer']}, got {(v or {}).get('peer')}")
        bad = 1
    else:
        print(f"PASS {name}: {p['id']} -> {got}")
sys.exit(bad)
PY
            [ $? -eq 0 ] || FAIL=1
        else
            bad "$case: sandbox script-load failed"; tail -3 "$OUT/$case.err" >&2
        fi
    done

    # --- Layer 4: hand off to the isolated target simulation ---
    cp "$art" "$OUT/target-firewall"    # bare copy: no source tree beside it
    exec unshare -r -n -m env SWNFT_IN_SANDBOX="$OUT" LITE_FAIL="$FAIL" "$0"
fi

# ---------------- inside the isolated "target" ----------------
OUT=$SWNFT_IN_SANDBOX
FAIL=${LITE_FAIL:-0}
mount -t tmpfs tmpfs /run

# Simulate an embedded box: a base system with nft and ip, but no Python.
# Shadow python so any attempt to run it fails loudly and leaves a marker.
NOPY="$OUT/nopython"
mkdir -p "$NOPY"
for p in python python3; do
    printf '#!/bin/sh\necho "python invoked: %s $*" >> "%s/py-invoked"\nexit 127\n' \
        "$p" "$OUT" > "$NOPY/$p"
    chmod +x "$NOPY/$p"
done
export PATH="$NOPY:/usr/sbin:/sbin:/usr/bin:/bin"
unset PYTHONPATH
# Lite runtime directories, matching the shorewall-lite layout. /var/lib is
# read-only for the namespace's mapped root, so give it a private tmpfs.
mount -t tmpfs tmpfs /var/lib 2>/dev/null || :
export SWNFT_STATE=/run/shorewall-lite
export SWNFT_VARDIR=/var/lib/shorewall-lite
mkdir -p "$SWNFT_VARDIR" "$SWNFT_STATE"
ip link add eth0 type dummy 2>/dev/null || :
ip link add eth1 type dummy 2>/dev/null || :

resolved=$(command -v python3 || true)
if [ -n "$resolved" ] && [ "$resolved" != "$NOPY/python3" ]; then
    bad "a real python3 is still on the target PATH ($resolved)"
else
    pass "target has no usable python3"
fi

fw="$OUT/target-firewall"
sh "$fw" check >/dev/null && pass "target: check validates the ruleset" \
    || bad "target: check failed"
sh "$fw" start >/dev/null && pass "target: start returned 0" \
    || bad "target: start failed"
nft list table ip shorewall >/dev/null 2>&1 \
    && pass "target: ruleset is loaded" || bad "target: ruleset not loaded"
sh "$fw" status >/dev/null 2>&1 && pass "target: status" || bad "target: status failed"
sh "$fw" stop >/dev/null 2>&1 && nft list table ip shorewall 2>/dev/null | grep -q . \
    && pass "target: stop swaps in the stopped ruleset" || bad "target: stop failed"
sh "$fw" clear >/dev/null 2>&1 && ! nft list table ip shorewall >/dev/null 2>&1 \
    && pass "target: clear removes the table" || bad "target: clear failed"

if [ -f "$OUT/py-invoked" ]; then
    bad "the target invoked python: $(cat "$OUT/py-invoked")"
else
    pass "the target never invoked python"
fi

[ "$FAIL" = 0 ] && echo "lite-proof: all passed"
exit "$FAIL"
