# Contributing to shorewall-nft

This project reimplements a firewall compiler. Correctness is the whole
point. The bar for a change is not that it looks right, it is that it
behaves the same as Shorewall and there is a test that proves it.

## The one rule

Every behavioral change ships with a test. New feature, bug fix,
edge case: add or extend a corpus case so the behavior is pinned. A
change without a test that demonstrates it will be asked for one.

## How testing works

The tests are differential. A corpus case is a small /etc/shorewall
configuration. The harness compiles it with both upstream Shorewall
and shorewall-nft, loads each ruleset into its own network-namespace
topology, sends real packets, and compares the verdicts. Parity means
both firewalls treat the same packet the same way.

Everything runs unprivileged, in user namespaces. No root, no virtual
machines. If you can run `unshare`, you can run the suite:

    tests/run                 # the whole suite
    tests/run 0003-two-interfaces   # one case

Results and a running journal land in tests/results/. Failures are
committed as failures. We do not hand-edit results to make them green.

See docs/verifying.md for a full walk through of reproducing a result,
and docs/coverage.md for what is and is not supported.

## What a good change looks like

- It fails loud. If a configuration uses something we do not support,
  the compiler errors and names the file and line. It never silently
  produces a weaker firewall. A change that makes us silently ignore
  something is a bug, not a feature.
- It matches upstream behavior where upstream has behavior. When there
  is no nftables equivalent, that is documented in docs/coverage.md and
  the compiler rejects it clearly, rather than guessing.
- It reads like the code around it. Match the naming, structure and
  comment density of the file you are editing.
- The generated output stays readable. The point of emitting text nft
  is that a human can audit it. Keep it legible.

## Writing style

Match the existing docs, which follow the style of the Shorewall manuals.
Document what a thing does and what it does not do. Comments explain why,
not what.

## Reporting problems

A good bug report is a configuration that misbehaves. The most useful
report is a minimal /etc/shorewall snippet plus what you expected and
what you got. If you can turn it into a failing corpus case, even
better; that is exactly the form a fix needs.

Security-sensitive reports (a configuration that compiles to a ruleset
weaker than the config asked for) should be treated as high priority.
Say so in the report.

## Maintenance

Issues and pull requests are read. A change that comes with a test and
keeps the suite green is the easy path to getting merged. The state of
what works lives in docs/coverage.md, kept current as the code changes.

The design decisions and the research behind them are written down in
docs/DECISIONS.md and docs/research/. Read them before a large change;
they explain why the shape is what it is.
