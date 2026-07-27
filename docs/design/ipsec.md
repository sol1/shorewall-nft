# IPSEC zone support design

How shorewall-nft filters traffic to and from an IPSEC peer as a normal
Shorewall zone. The target is site-to-site tunnels keyed by reqid, the common
sol1 case. The site-to-site core, the full option set, and cleartext
coexistence on a shared interface are built (Phases 1 to 3). The nat, masq,
accounting and provider paths and the harness xfrm dimension are Phases 4
and 5.

## The goal

An administrator declares an IPSEC zone the same way as any other zone, and
writes ordinary policies and rules for it. Traffic that arrived over the tunnel
is in the zone; cleartext on the same interface is not. A site-to-site tunnel
is identified by its reqid, so the zone is tied to that SA.

## Why it is refused today

An `ipsec`, `ipsec4` or `ipsec6` zone means its members are reached over an
IPSEC SA, so the zone's rules must match only encrypted traffic. Upstream does
this with `-m policy --pol ipsec`. We never built the match, and the zones
parser refuses the ipsec types rather than downgrade them to a plain net zone.
A plain zone would match every packet on the interface, cleartext included,
and accept as tunnel traffic what never went through the tunnel. That is a
security hole, so we fail loud, the same principle as refusing NETMAP or ECN on
an nft too old to express them. It was never impossible, only unbuilt and
unsafe to fake.

## What an IPSEC zone is

The zone is attached to an interface or a set of hosts, and its traffic is
scoped by the IPSEC policy the kernel applied:

- Inbound traffic from the peer arrives already decrypted, carrying an xfrm
  secpath. For a site-to-site tunnel the SA has a reqid set in the SPD, and the
  decrypted packet carries that reqid.
- Outbound traffic to the peer is selected for encryption by the same reqid
  before it leaves.

So a zone tied to reqid N matches inbound packets that came in on SA reqid N
and outbound packets selected for SA reqid N.

## How upstream builds the match

Confirmed by reading the upstream Perl (Zones.pm, Chains.pm, Rules.pm,
Misc.pm, Nat.pm). An IPSEC zone's rules carry an iptables policy match,
`-m policy --dir {in|out} --pol ipsec [flags]`, and the flags come from the
zone OPTIONS/IN OPTIONS/OUT OPTIONS columns in the user's source order:

| option | flag | note |
|---|---|---|
| `reqid=N` | `--reqid N` | SPD reqid, the site-to-site key |
| `spi=N` | `--spi N` | a specific SA |
| `proto=ah\|esp\|ipcomp` | `--proto P` | encapsulation protocol |
| `mode=tunnel\|transport` | `--mode M` | |
| `tunnel-src=A`, `tunnel-dst=A` | `--tunnel-src/dst A` | tunnel mode only |
| `strict` | `--strict` | all policy elements must match |
| `next` | `--next` | separates policy elements |

`--dir in` scopes packets arriving from the zone (source side), `--dir out`
packets going to it (dest side). OPTIONS apply to both, IN OPTIONS only to the
in match, OUT OPTIONS only to the out match. A bare ipsec zone with no options
is valid and emits `--pol ipsec` with no qualifier (any SA). mss and blacklist
also apply to non-ipsec zones; the rest are ipsec-only.

The load-bearing detail for a faithful clone: whenever any ipsec zone or host
is present, upstream also sprays `--pol none --dir {in|out}` on the
non-encrypted paths, so a decrypted packet does not fall through to a
cleartext rule on the same interface. The `--dir in` rules are ordered first
in the forward chain for the same reason. The `tunnels` file also changes:
with ipsec in play it opens only the key-exchange UDP ports, not raw ESP/AH.

## The nft mechanism and how it maps

nft matches IPSEC state directly, no policy module. The match is ANDed onto
the zone's existing interface and address scoping.

| upstream `-m policy` | nft |
|---|---|
| `--dir in --pol ipsec` (any SA) | `meta secpath exists` |
| `--dir in --reqid N` | `ipsec in reqid N` |
| `--dir out --reqid N` | `ipsec out reqid N` |
| `--spi S` | `ipsec {in\|out} spi S` |
| `--mode tunnel --tunnel-src A` | `ipsec {in\|out} spnum 0 ip saddr A` |
| `--mode tunnel --tunnel-dst A` | `ipsec {in\|out} spnum 0 ip daddr A` |
| `--strict` (multi-element) | chained `ipsec ...` clauses (spnum 0, 1, ...) |
| `--pol none --dir in` | `meta secpath missing` |
| `--proto P` | no nft selector (gap) |
| `--pol none --dir out` | no clean nft form (gap) |

Two nft gaps, both edges. There is no `proto` selector on the ipsec
expression, and no outbound "not ipsec" match, since `meta secpath` is set by
decryption and so is inbound only. The site-to-site and per-host-encryption
cases do not need either. A config that uses `proto=` or depends on an
outbound cleartext exclusion is refused or warned rather than mis-scoped.

nft 0.9.0 (Debian 10) has no ipsec expression at all, so any ipsec zone is
refused there with a located error, capability NFT_IPSEC, the same as NETMAP
and ECN; nft 0.9.3 (Ubuntu 20.04) and later have it.

## Design

1. Accept the `ipsec`, `ipsec4` and `ipsec6` zone types. Carry an ipsec flag on
   the zone plus the reqid (and later spi, proto, mode) read from the zone
   OPTIONS column, which already parses `reqid=`, `spi=`, `proto=`, `mode=`,
   `tunnel-src=` and `tunnel-dst=`.
2. Scope the zone dispatch. Where the emitter matches a zone's interface or
   host, AND the IPSEC match for an ipsec zone:
   - as a source (packets from the zone): `iifname X ipsec in reqid N`
   - as a destination (packets to the zone): `oifname X ipsec out reqid N`
   A reqid-less zone uses `meta secpath exists` inbound.
3. The shorewall-hosts `ipsec` option. An ipsec zone is commonly attached with
   a hosts entry, `zone iface:0.0.0.0/0 ipsec`, and upstream lets the option be
   omitted when the zone TYPE is already ipsec. Read the option and treat the
   host group as ipsec-scoped, with the zone's reqid.
4. Policies and rules for the zone need no new syntax. The IPSEC match rides on
   the zone dispatch, so `loc ipsec-peer ACCEPT` and a rule
   `ACCEPT ipsec-peer loc tcp 22` both scope correctly with no extra columns.

## Phases

1. Done. Site-to-site core. The `ipsec`, `ipsec4` and `ipsec6` zone types are
   accepted, and the zone dispatch is scoped with `ipsec in reqid N` inbound
   and `ipsec out reqid N` outbound, so cleartext on the tunnel interface is
   not in the zone. The redundant hosts `ipsec` option is accepted. Corpus
   0051 locks the cleartext-dropped property against upstream.
2. Done. The option set. `reqid=`, `spi=` (`ipsec spi S`) and `mode=tunnel`
   with `tunnel-src`/`tunnel-dst` (`ipsec spnum 0 ip saddr/daddr A`) are
   applied, the OPTIONS/IN OPTIONS/OUT OPTIONS column split is honoured
   (options in the in and out buckets scope only that direction), and a
   reqid-less zone matches any SA inbound with `meta secpath exists`. The
   phase-1 reqid requirement is relaxed. Refused with a located error, since
   nft cannot express them: `proto=` (no proto selector), `reqid` with `spi`
   in one clause, and a bare (any-SA) ipsec zone used as a destination (nft
   has no outbound any-SA match). A multi-element policy (`next`) is deferred.
3. Done. Coexistence with cleartext on a shared interface, the `--pol none`
   companion. When an interface carries both an ipsec zone and a cleartext
   zone, the cleartext inbound dispatch excludes decrypted traffic with
   `meta secpath missing`, so a decrypted packet belongs to the ipsec zone,
   not the cleartext one. Inbound the two matches (`meta secpath missing` and
   `ipsec in ...`) are mutually exclusive, so order does not matter, the same
   as upstream `--pol none`/`--pol ipsec --dir in`. Outbound nft has no
   secpath match, so the cleartext rule carries no guard; instead the ipsec
   `out` rule sorts first, and a to-be-encrypted packet is caught by the
   positive `ipsec out` match while cleartext falls through. In the forward
   chain the source-side match already discriminates, so the unguarded
   cleartext dest is harmless. This is what makes per-host encryption (an
   ipsec zone attached by a hosts entry on a shared interface) correct.
   Corpus 0052 locks it against upstream, whose emitted `--pol none` on the
   cleartext paths and `--pol ipsec --reqid` on the tunnel confirm the split.
4. The rest of the upstream ipsec surface: the nat/masq, accounting and
   provider paths that also emit a policy match, and the `tunnels` file
   opening only key-exchange ports when ipsec is in play.
5. The harness IPSEC dimension: build an xfrm SA in the netns and prove SA
   traffic matches the zone while cleartext does not.

## Testing

The userns harness sets up a transport or tunnel SA between two nodes with
`ip xfrm state` and `ip xfrm policy`, giving it a known reqid, loads the
ruleset, and probes that traffic carried over the SA matches the ipsec zone
while cleartext to the same address on the same interface does not. Where the
test kernel or namespace cannot create an xfrm SA, the case falls back to a
no_upstream compile and nft-load check, so the ruleset is still exercised.

## Comparison with upstream

| Concern | Upstream (iptables) | shorewall-nft |
|---|---|---|
| IPSEC match | `-m policy --pol ipsec` | `ipsec in/out reqid N`, `meta secpath exists` |
| Zone syntax | unchanged | unchanged |
| reqid source | zone option | zone option |
| Unknown/unsafe | matched cleartext if misconfigured | fail loud until scoped |

## Open questions

- Whether a zone carries a single reqid or a tunnel can present several, in
  which case the match becomes a set of reqids.
- Outbound scoping for tunnel mode, where tunnel-src and tunnel-dst select the
  outer addresses through `spnum`.
- Interaction with multi-ISP routing, where the tunnel egress interface is
  chosen by a provider.
