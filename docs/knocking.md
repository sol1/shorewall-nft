# Port knocking

shorewall-nft provides native `KNOCK` and `KNOCKSEQUENCE` actions. They use
nftables dynamic timed sets; no Perl module or external daemon is required.
Port knocking gates access to a service. It is not authentication, so the
service must still use normal authentication and should have appropriate rate
limiting.

## Basic knocking

Put the action in `/etc/shorewall/rules`. The protocol inside the action is the
protocol of the knock packet; the rules-file protocol and destination port are
the protected service:

    KNOCK(7000,tcp,timeout=30) net $FW tcp 22
    KNOCK(7000,udp,timeout=30) net $FW tcp 22
    KNOCK(7000,tcp,timeout=30) net $FW udp 53

The source address is authorized for 30 seconds after a matching knock. The
knock packet is dropped and the authorization is reusable by default. Use
`reusable=no` to consume authorization on the first new connection:

    KNOCK(7000,tcp,timeout=30,reusable=no) net $FW tcp 22

Authorization is consumed only by the first new protected-service flow;
established packets do not consume it repeatedly.

## Stateful sequences

A uniform protocol applies to every step:

    KNOCKSEQUENCE(7000,8000,9000,tcp,timeout=30) net $FW tcp 22

A mixed sequence gives every port its protocol:

    KNOCKSEQUENCE(7000,tcp,8000,udp,9000,tcp,timeout=30) \\
        net $FW tcp 22

A sequence with one or more explicit protocols must specify a protocol after
every port. This is invalid because `8000` has no protocol:

    KNOCKSEQUENCE(7000,udp,8000,9000,tcp,timeout=30) net $FW tcp 22

Timeouts apply independently to each stage. Repeating the port that completed
the current stage refreshes that stage. A known sequence port arriving out of
order resets the sequence. The first port then starts a new sequence. Traffic
to unrelated ports or protocols does not affect the sequence.

`reusable=no` removes the final authorization after the first new protected
service connection and clears the sequence state. The sequence must then be
completed again.

## Forwarded services

For a DNAT service, define the translation and the knock sequence together.
Only the protected service is translated. Use `DNAT-` so that the automatic
DNAT filter accept is not emitted and access remains gated by the knock:

    DNAT- net loc:10.0.1.2:22 tcp 2222
    KNOCKSEQUENCE(7000,8000,9000,tcp,timeout=30) \\
        net loc tcp 22 - 203.0.113.10

The knock ports are handled in an early prerouting filter chain and are not
sent to the internal host. `ORIGDEST` restricts the knocking rule to the public
address. The protected-service rule runs in the normal input or forward filter
path after DNAT.

## NFLOG

NFLOG is optional and non-terminal. It observes matching packets and then
continues processing. The action parameter is:

    nflog=[PREFIX:]GROUP[:SNAPLEN[:QUEUE_THRESHOLD]]

The prefix is optional and is an arbitrary safe label, eg security-knock:

    KNOCK(7000,tcp,timeout=30,nflog=5) net $FW tcp 22
    KNOCKSEQUENCE(7000,8000,9000,tcp,timeout=30,nflog=security-knock:5:128:1) \\
        net $FW tcp 22

Without a prefix, shorewall-nft uses a generated prefix. NFQUEUE is not part
of the knocking action yet; it remains a separate userspace handoff whose
interaction with state transitions will be designed independently.
