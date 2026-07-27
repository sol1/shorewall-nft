# IPSEC zone support design

How shorewall-nft filters traffic to and from an IPSEC peer as a normal
Shorewall zone. The target is site-to-site tunnels keyed by reqid, the common
sol1 case. Phase 1 (the site-to-site core) is built; the reqid-less and finer
selectors are Phase 2.

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

## The nft mechanism

nft matches IPSEC state directly, with no policy module:

| Need | nft |
|---|---|
| inbound came via IPSEC | `meta secpath exists` |
| inbound via SA reqid N | `ipsec in reqid N` |
| outbound selected for SA reqid N | `ipsec out reqid N` |
| a specific SA | `ipsec in spi <spi>`, `ipsec in reqid N proto esp` |
| tunnel endpoints | `ipsec in spnum 0 ip saddr <tunnel-src>` |

`ipsec in reqid N` and `ipsec out reqid N` load on the baseline nft, so the
site-to-site case needs nothing exotic. nft 0.9.0 (Debian 10) has no ipsec
expression, so an ipsec zone is refused there with a located error, capability
NFT_IPSEC, the same as NETMAP and ECN on an nft too old to express them; nft
0.9.3 (Ubuntu 20.04) and later have it. `meta secpath exists` covers the
reqid-less road-warrior case.

## Mapping upstream to nft

Upstream adds a policy match to every rule for the zone.

| upstream | nft |
|---|---|
| `-m policy --dir in --pol ipsec` | `meta secpath exists` |
| `--dir in --reqid N` | `ipsec in reqid N` |
| `--dir out --reqid N` | `ipsec out reqid N` |
| `--proto esp` | `... proto esp` |

The match is ANDed onto the zone's existing interface and address scoping, it
does not replace it. An IPSEC zone still lives on an interface.

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
   accepted with a required `reqid=` option, and the zone dispatch is scoped
   with `ipsec in reqid N` inbound and `ipsec out reqid N` outbound, so
   cleartext on the tunnel interface is not in the zone. The redundant hosts
   `ipsec` option is accepted. Corpus 0051 locks the cleartext-dropped property
   against upstream.
2. Reqid-less and finer selectors. `meta secpath exists` for road-warrior
   zones; the spi, proto, mode, tunnel-src and tunnel-dst options.
3. The harness IPSEC dimension: build an xfrm SA in the netns and prove SA
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
