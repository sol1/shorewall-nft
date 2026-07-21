# Shorewall Lite for shorewall-nft

## The goal

Run a shorewall-nft firewall on a box that cannot run the compiler: a small
embedded system, an OpenWRT router, anything without Python. Compile the
configuration on a full system, ship the result to the target, and run it there
with only `sh`, `nft` and `ip`.

This is upstream's Shorewall Lite model. We copy it rather than invent a new
one, so anyone who knows Shorewall Lite already knows this.

## How upstream Shorewall Lite works

Two products. The full Shorewall runs on an administrative system and has the
compiler. Shorewall Lite runs on the target and is runtime only.

- The admin system compiles the target's configuration into one self-contained
  firewall script.
- Shorewall Lite on the target provides `/etc/shorewall-lite/` (a small
  shorewall-lite.conf), `/var/lib/shorewall-lite/firewall` (the compiled
  script), `/usr/share/shorewall-lite/` (a runtime library and `shorecap`), the
  `shorewall-lite` command, and a service with init scripts for several
  systems, OpenWRT among them.
- `shorecap` is a shell script run on the target that captures the target's
  capabilities, so the admin compiles against what the target actually has.
- The admin deploys with `shorewall load <system>` and `shorewall reload
  <system>`: compile, copy the script to the target, run it. Or you copy an
  exported script by hand and run `shorewall-lite start`.

## Why we are most of the way there already

shorewall-nft's compiled artifact is already a self-contained POSIX shell
script (src/shorewall_nft/script.py). It embeds the nft ruleset (start, a
fail-closed skeleton, and stop) as heredocs and loads them atomically with `nft
-f`. It embeds the routing and provider `ip` changes and the sysctls. It reads
nothing from `/etc/shorewall` at runtime. It relocates through `SWNFT_VARDIR`
and `SWNFT_STATE`. It needs no Python and no ipset.

Runtime dependencies on the target: `sh`, `nft`, `ip`. `tc` and `sysctl` only
when the configuration uses traffic control or sets sysctls.

So the compiler already emits the lite artifact. What is missing is the target
runtime package, the deployment commands, and the guarantees that make it safe
on a box we did not compile on.

## Design

### 1. Export compile, admin side

`shorewall compile -e [directory] [pathname]` writes the self-contained script.
The `-e` flag is already accepted; formalize it as the documented way to
produce a lite artifact, and make export compilation use the static capability
defaults rather than probing the build host (see Capabilities). One script per
family: `shorewall compile -e` for IPv4, `shorewall6 compile -e` for IPv6.

### 2. The shorewall-nft-lite package, target side

A runtime-only package that mirrors the upstream layout:

- `/usr/sbin/shorewall-lite` and `shorewall6-lite`: a POSIX shell dispatcher for
  `start`, `stop`, `reload`, `restart`, `status`, `check` and `version`. It runs
  `/var/lib/shorewall-lite/firewall <verb>` with `SWNFT_VARDIR` and
  `SWNFT_STATE` pointed at the lite directories. `status` reports the table and
  rule counts through `nft` alone.
- `/etc/shorewall-lite/shorewall-lite.conf`: VERBOSITY, LOGFILE, PATH and the
  few runtime knobs, matching upstream's file.
- `/var/lib/shorewall-lite/firewall`: the deployed compiled script.
- `/usr/share/shorewall-lite/`: the runtime library, `shorecap`, and a version
  stamp.
- A systemd unit and init scripts, OpenWRT included.
- Depends on `nftables` and `iproute2`. It must not depend on python3.

The dispatcher is thin: the compiled script does the work. This keeps the
target package small and stable.

### 3. Remote deploy, admin side

`shorewall load [system]` and `shorewall reload [system]` compile the
configuration to an export script, copy it to `system:/var/lib/shorewall-lite/
firewall` over ssh, and run `shorewall-lite start` or `reload` there. Same
verbs and meaning as upstream: `load` is the full first push, `reload`
recompiles and reloads. Deployment is ssh and scp, as upstream does it.

Hand deployment stays supported: copy the `compile -e` output to the target and
run `shorewall-lite start`.

### 4. Capabilities: conservative static, fail loud

The ruleset is compiled on the full system. Its kernel and the target's may
differ, and the conntrack-helper probing added in 0.1.5 reflects the build
host, not the target.

For v1, export compilation uses the static capability defaults (the
`SHOREWALL_NFT_STATIC_CAPS` behaviour) so the artifact is deterministic and does
not bake in a helper the build host happens to have. On the target,
`shorewall-lite check` runs `nft -c` against the target's own kernel, and
`start` falls back to the fail-closed skeleton and reports if the kernel rejects
the ruleset. A bad assumption fails loud on the target instead of silently
loading the wrong thing.

Upstream parity, later: `shorecap` on the target captures its capabilities into
a profile, and `compile --caps <profile>` compiles helper-dependent rules to
match the target exactly. This is the fully correct answer and the path to it,
but it is not needed to ship v1.

### 5. Out of scope for v1

- Dynamic multi-ISP failover. The static provider routing is in the compiled
  script and works on lite. The link monitor (`lsm`) is a Python daemon and does
  not run on a Python-free target. Document that failover needs the full
  package; revisit with a shell monitor if there is demand.
- geoip updates. The geoip sets ship with the artifact as a point-in-time
  snapshot under the lite VARDIR. Refresh by recompiling and redeploying. There
  is no on-target `geoip-update`.

## Constraints

- The compiled script and the dispatcher must be POSIX shell, safe under
  busybox `ash`, since OpenWRT and similar targets have no bash. No `[[`, no
  `local` where ash differs, no `echo -e`. The lite proof lints for this.
- No absolute paths that assume the full install. Everything the runtime
  touches is under `SWNFT_VARDIR` and `SWNFT_STATE`, both overridable.

## Code changes

- cli.py: formalize `-e`/`--export`; add `load` and `reload [system]`
  (ssh/scp). Export compilation forces static capabilities.
- script.py: add a `check` verb to the emitted wrapper that runs `nft -c` on the
  embedded ruleset. Confirm every runtime path derives from `SWNFT_VARDIR` or
  `SWNFT_STATE`.
- New data: the `shorewall-lite` dispatcher, shorewall-lite.conf, the service
  and init scripts (OpenWRT included), a `shorecap` stub, and a small runtime
  library.
- packaging: a `shorewall-nft-lite` deb and rpm, depending on nftables and
  iproute2, not python3.

## Testing

- A `lite-proof` in tests/run: `compile -e` a configuration, place the script in
  a fresh network namespace whose PATH has no `python3` and only `nft`, `ip` and
  `sh`, run `shorewall-lite start`, send packets, and check the verdicts match
  the full-stack run for the same config. This proves Python-free execution and
  behavioural parity.
- An `ash` lint of the emitted script and the dispatcher, so a bashism cannot
  slip in and break an OpenWRT target.
- A check that the artifact contains no reference to python and runs under a
  minimal PATH.

## Phasing

1. Formalize `compile -e`, add the wrapper `check` verb, and land the lite proof
   (Python-free execution of the export script). This proves the model on the
   code that already exists.
2. The `shorewall-nft-lite` package: dispatcher, config, service, init scripts.
3. `load`/`reload` remote deploy, `docs/lite.md` for operators, and the
   `shorecap` capability profile for full upstream parity.
