# Developing shorewall-nft

shorewall-nft is a reimplementation of the Shorewall compiler in Python.
Where the original produces iptables-restore input, this produces an
nftables ruleset. It reads the same /etc/shorewall files, so if you know
Shorewall you already know the input. What is new is the code that turns
that input into nft, and that is what this document orients you to.

## Layout

    src/shorewall_nft/   The compiler. The parsers read the configuration
                         files, emit.py builds the ruleset, script.py builds
                         the runtime wrapper that handles routing, tc,
                         sysctls and the rest.
    tests/               The differential test harness and the corpus.
    docs/                Design decisions, the research behind them, and the
                         file-by-file coverage map.
    packaging/, debian/  The installer and the distribution packages.

Read docs/internals.md for how the ruleset is generated and
docs/DECISIONS.md for why the design is shaped the way it is.
docs/coverage.md states what works and what does not, file by file.

## Running from the source tree

    bin/swnft check /etc/shorewall
    bin/swnft compile /etc/shorewall -o out.nft

swnft runs the compiler straight out of src/ without installing, so you can
work in the checkout. The installed command is shorewall; the two are the
same program.

## Upstream sources

The tests compare our output against the real Shorewall, so the Shorewall
and nftables sources are cloned into upstream/, which is not committed.
Re-clone if it is missing:

    git clone https://gitlab.com/shorewall/code upstream/shorewall
    git clone https://git.netfilter.org/nftables upstream/nftables

Nothing under upstream/ is ever modified. It is reference, and the harness
builds the stock Shorewall compiler from it to diff against.

## Tests

    tests/run                        the whole suite
    tests/run 0003-two-interfaces    a single case

Each corpus case is compiled by both Shorewall and shorewall-nft, loaded
into its own network namespace, and probed with real packets; the verdicts
from the two firewalls are compared. Everything runs unprivileged. See
docs/verifying.md for the detail and CONTRIBUTING.md for how to add a case.

Results are written to tests/results/ as the run happens. A failing run is
recorded as a failure.
