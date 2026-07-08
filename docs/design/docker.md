# Docker coexistence design

How shorewall-nft and Docker share an nftables firewall. This is a
design proposal. Nothing here is built yet.

## The problem

Docker and a host firewall both program netfilter. Under iptables they
fought, because iptables has one shared table per hook and whoever
writes last wins. Upstream Shorewall coped with a heavy workaround: on
every start, stop and reload it snapshotted Docker's chains to text
files, flushed the whole ruleset, then pasted Docker's rules back and
re-added the jumps Docker expects. It also rerouted its own SNAT into a
private SHOREWALL nat chain to keep the builtin POSTROUTING free for
Docker. The scheme is fragile: a restart at the wrong moment loses
Docker's rules, Debian's stop uses clear which skips the save, and
Swarm is unsupported.

Docker has since moved to nftables. Docker 29 ships a native nftables
backend. The default is still the iptables backend, which on modern
distros is iptables-nft. Either way the world is nftables now, and the
old model does not fit it.

The goal: Docker works out of the box with shorewall-nft running, a
shorewall-nft reload never disturbs Docker, and an administrator can
filter container traffic with normal Shorewall zones and rules.

## What Docker does in nftables

Two modes, and the design must handle both.

**iptables backend (default).** Docker drives iptables-nft. The
FORWARD chain jumps to DOCKER-USER first, then DOCKER-FORWARD, then
DOCKER-INGRESS. DOCKER-USER is empty and reserved for the
administrator; Docker guarantees it runs before Docker's own rules.
This is the hook ufw-docker and firewalld target. DNAT for published
ports lives in nat PREROUTING, masquerade in nat POSTROUTING.

**native nftables backend (Docker 29, opt-in).** Docker owns
`table ip docker-bridges` and `table ip6 docker-bridges`, verified
against moby source. Base chains and priorities:

| Chain | Hook | Priority | Job |
|---|---|---|---|
| raw-PREROUTING | prerouting | -300 (raw) | drop direct-to-container and remote-to-loopback |
| nat-PREROUTING | prerouting | -100 (dstnat) | DNAT published ports |
| nat-OUTPUT | output | -100 (dstnat) | host-origin DNAT |
| filter-FORWARD | forward | 0 (filter) | vmap to per-network chains |
| nat-POSTROUTING | postrouting | 100 (srcnat) | masquerade |

There is no DOCKER-USER in native mode. Docker's maintainers dropped it
on purpose (moby #49643): a user chain in a different table cannot
reliably override rules in Docker's table, so the sanctioned method is
to own your own table and pick hook priorities, plus one explicit
accept hook, `--bridge-accept-fwmark`, for letting marked traffic
through Docker's drop.

Per-network ingress chains end in a drop of unpublished ports, so
Docker already blocks everything to a container except its published
ports and established flows. Docker force-enables ip_forward and sets
its forward policy to drop, but in native mode that policy lives in
Docker's table and resets to accept on daemon restart (moby #50566), so
it cannot be trusted for host security.

## The nftables insight this design rests on

At one hook, nftables runs every base chain in ascending priority
order. A `drop` verdict is terminal: the packet dies and no further
chain sees it. An `accept` verdict is not terminal across chains: the
packet still traverses the other base chains at that hook. A base chain
with `policy drop` drops a packet that reaches the chain's end without a
terminal verdict.

The consequence is the whole design:

- Two independent tables at a hook compose to **drop if either drops,
  accept only if neither drops**. That result does not depend on their
  relative priority. So shorewall-nft and Docker each own a table and
  the combined filtering is deterministic without coordinating
  priorities.
- To **restrict** container traffic Docker would allow, shorewall-nft
  drops it in its own table. The drop wins wherever it runs.
- To **permit** traffic Docker would drop, a drop cannot be undone by a
  later accept. shorewall-nft cannot force it open from its own table.
  The only sanctioned lever is Docker's `--bridge-accept-fwmark`: set a
  mark before Docker's forward chain reads it, and Docker accepts. This
  is the one case that needs an agreed mark and a prerouting priority
  below Docker's.

Because shorewall-nft already owns `table inet shorewall` and never
flushes another table, Docker's table survives a shorewall-nft reload
untouched. The entire upstream save and restore machinery is deleted,
not ported. There is nothing to snapshot.

## The one thing that would break Docker, and the fix

shorewall-nft's forward chain has `policy drop`. Container forward
traffic that shorewall-nft does not explicitly accept would fall to
that policy and die, breaking Docker, even though Docker's own table
would have allowed it.

The fix is a single decision: shorewall-nft must give container traffic
an `accept` verdict in its own forward chain so it does not hit the
drop policy, and then let Docker's table be the authority. An accept in
our chain does not stop Docker's chain from dropping an unpublished
port, so Docker still enforces its own policy. We get out of the way;
Docker decides.

That accept is scoped to the Docker bridges, matched by interface name:
`docker0` and the per-network `br-*` bridges. nft matches these with a
glob, `iifname "br-*"`, and a literal `docker0`, so no runtime bridge
list is needed.

## Proposed design

### 1. DOCKER option and detection

`DOCKER=Yes` in shorewall.conf turns the integration on, matching the
upstream setting name so existing configs read the same. When set, the
compiler treats the Docker bridges as a known interface group. A future
`autodetect` value can probe for docker0 at compile or run time, but
the explicit setting is the first target.

`DOCKER_BRIDGE` keeps its upstream meaning and default of docker0, and
names the primary bridge. Per-network bridges are matched by the `br-*`
glob.

### 2. Coexistence, the default behavior

With `DOCKER=Yes` and no docker zone declared, shorewall-nft stays out
of Docker's way:

- The forward chain accepts established and related first, as it
  already does.
- Before the zone dispatch, it accepts traffic to and from the Docker
  bridges: `oifname { "docker0", "br-*" } accept` and
  `iifname { "docker0", "br-*" } accept`. This keeps the drop policy
  from clobbering containers while Docker's table does the real
  filtering.
- NAT is left entirely to Docker. shorewall-nft's own postrouting is a
  separate base chain and masquerades only the zones the config names,
  which do not overlap Docker's container subnets.

Result: containers work exactly as they do without shorewall-nft, and a
shorewall-nft reload never disturbs them.

### 3. Docker as a first-class zone, the opt-in

The administrator declares a zone for containers, the automated version
of upstream's documented manual pattern:

    # zones
    dock    ipv4

    # interfaces
    dock    docker0    bridge

    # policy
    dock    net        ACCEPT      # containers may reach the internet
    net     dock       DROP        # but the internet may not reach them
    dock    all        DROP

The zone covers exactly the interfaces the administrator writes,
nothing more. A firewall must not silently fold interfaces into a zone
the admin did not name. To cover the per-network `br-*` bridges the
admin writes a wildcard interface, `physical=br-+`, which compiles to
an `iifname "br-*"` match. To cover the default bridge as well, add a
`docker0` interface line. There is no automatic inclusion tied to
`DOCKER=Yes`; that setting only governs the coexistence accept for
bridges no zone claims.

For every bridge a zone does claim, the blanket coexistence accept from
section 2 is suppressed for that bridge and normal zone dispatch takes
over. Because Docker's table filters independently, the two compose: a
connection is allowed only if both the dock policy and Docker permit
it. A dock policy drop is terminal and wins, so the administrator can
always tighten what Docker allows.

The `bridge` interface option enables inter-container communication, as
upstream, and implies routeback so containers on one bridge can talk to
each other through the firewall.

Wildcard interfaces in general now compile correctly: a Shorewall
trailing `+` becomes an nft name glob (`br-+` to `br-*`), and only a
bare `+` matches every interface. Previously a prefixed wildcard
emitted a bare match-all jump, which silently made the zone match all
traffic. That was a firewall correctness bug in its own right.

### 4. Filtering published ports

Publishing a port with `-p` makes Docker DNAT it in prerouting and
accept the translated flow in forward. By the time shorewall-nft's
forward chain sees the packet the destination is the container address
and the container port, not the published host port. To let the
administrator write a rule against the published port, shorewall-nft
matches the pre-DNAT tuple through conntrack:

    # allow only the net zone to reach published tcp 8080
    ACCEPT    net    dock    tcp    -    -    ;; ct original ip daddr $HOST_IP tcp dport 8080

The clean form is a dedicated column or macro so the user writes the
host port and shorewall-nft emits the `ct original` match. A drop of a
published port from the wrong source is terminal and takes effect even
though Docker accepts it, closing the ufw-style bypass by construction
rather than by a DOCKER-USER shim.

### 5. Mode independence

This design never writes into a Docker chain and never relies on
DOCKER-USER. It works the same whether Docker runs the iptables backend
or the native nftables backend, because it only ever writes
shorewall-nft's own table and leans on the drop-wins composition rule.
That is a strict improvement over the DOCKER-USER approach, which only
exists in the iptables backend.

The one place mode matters is the permit-past-Docker lever. In native
mode that is `--bridge-accept-fwmark`: if a config needs to open direct
routing to a container, shorewall-nft sets the agreed mark in a
prerouting chain at a priority below Docker's dstnat, and the
administrator sets `--bridge-accept-fwmark` on the daemon. This is a
documented, narrow escape hatch, not the common path.

### 6. What is deleted

Everything upstream needed and this design does not:

- No save of Docker chains to VARDIR text files.
- No restore of those files into the ruleset.
- No SHOREWALL nat chain indirection to keep POSTROUTING free.
- No g_docker liveness probes gating chain headers.
- No dependency on the stop command to snapshot, so the Debian clear
  problem disappears.

Container rules survive a reload because we never touch Docker's table,
not because we carefully put it back.

## Comparison with upstream

| Concern | Upstream (iptables) | shorewall-nft |
|---|---|---|
| Docker rules on reload | snapshot to files, flush, paste back | untouched, separate table |
| POSTROUTING sharing | private SHOREWALL nat chain | separate table, no sharing needed |
| User hook | DOCKER-USER, populated out of band | shorewall-nft's own table via drop-wins |
| Container zone | manual, documented convention | declared zone, first class |
| Published-port filter | DOCKER-USER with ct original | rule with ct original in our table |
| Docker backend support | iptables only | iptables-nft and native nftables |
| Stop or clear edge cases | fragile, Debian workaround needed | none, nothing to preserve |

## Testing

The differential harness gains a Docker dimension. A test spins up a
real dockerd in a container or namespace with a published-port
container, loads shorewall-nft alongside, and probes:

1. Container reaches the internet (dock to net) with shorewall-nft
   running.
2. A published port is reachable from the allowed zone and dropped from
   a disallowed zone, proving the ct original filter and the drop-wins
   composition.
3. A shorewall-nft reload does not drop container connectivity, proving
   the no-touch coexistence.
4. An unpublished container port stays closed, proving Docker's own
   drop still applies under our accept.

Where feasible the same probes run against both Docker firewall
backends.

## Open questions

- Autodetection of the Docker bridges at compile time versus a runtime
  probe in the wrapper script. Runtime is more robust since bridges
  come and go with `docker network` commands.
- Swarm ingress (DOCKER-INGRESS) and overlay networks. Upstream does
  not support Swarm. Scope for a later phase.
- macvlan and ipvlan networks receive no Docker firewall rules at all,
  so container traffic there is ordinary interface traffic and needs a
  normal zone. Document this.
- Whether to model per-network bridges as distinct zones rather than
  one dock zone, so different Docker networks can have different
  policies.

## Implementation phases

1. `DOCKER=Yes` parsing and the default coexistence accept for the
   bridge globs. Delete nothing yet; there is nothing to delete since
   we never built the upstream hack.
2. The docker zone: allow a bridge interface in a zone and dispatch
   container traffic into it. Reuse the existing interface and zone
   machinery.
3. The published-port filter: a rules syntax that emits the ct original
   match.
4. The harness Docker dimension and corpus cases.
5. The native-mode fwmark escape hatch and its documentation.
