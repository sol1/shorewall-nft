# Raw nft passthrough

The escape hatch for anything the compiler has no column or action
for. When a rule needs a match or a construct shorewall-nft does not
model, write raw nft after a semicolon and it is spliced into the
generated rule.

Upstream Shorewall offers the same escape hatch with the `IPTABLES()`
and `INLINE` actions and the inline `;;` syntax, but its content is
iptables. We emit real nft, so ours is raw nft. That is the one place
the syntax cannot be identical, because there is no nft equivalent of
pasting iptables into an nft table.

## Inline matches

Append raw nft matches to any rule after a semicolon. The rule's ACTION
still supplies the verdict; the passthrough adds to the match.

    # accept net to fw tcp 22 only from source port 5000
    ACCEPT  net  $FW  tcp  22  -  -  ;  tcp sport 5000

Both a single `;` and the `;;` upstream uses for INLINE are accepted.
The text after the semicolon is passed through untouched and placed
after the parsed matches, before the verdict.

## The INLINE action

`INLINE(verdict)` writes the verdict in the ACTION column and leaves
the passthrough as extra matches:

    INLINE(ACCEPT)  net  $FW  -  -  -  -  ;;  tcp dport 8888

Bare `INLINE` is fully free form: the passthrough is the entire rule
body, matches and verdict, spliced verbatim into the chain the SOURCE
and DEST columns select:

    # open net to loc tcp 7777, verdict and all in the passthrough
    INLINE  net  loc  -  -  -  -  ;;  tcp dport 7777 accept

## Safety

The passthrough is not parsed by the compiler. It is validated the
same way as everything else: the wrapper runs `nft -c -f` before
`nft -f`, so a malformed passthrough fails the load loudly and the
running firewall is never left half-applied. A typo produces a clear
nft syntax error naming the line, not a silent hole.

## Where it works

The rules file today. The mangle file is a later addition.

Case 0029 proves the behavior: an inline match gates the verdict on
source port, and a free-form INLINE opens a port that is otherwise
dropped.
