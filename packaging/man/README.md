# Man pages

`shorewall.8` is the command reference for shorewall-nft, written for this
implementation and edited by hand.

## Config-file man pages

The 42 `shorewall-*(5)` pages describe the configuration file formats.
shorewall-nft reads the identical files, so the pages read like upstream's,
with shorewall-nft notes added where a setting maps to a specific piece of
nftables output.

The source is upstream Shorewall's own DocBook, vendored under `docbook/`
(GPLv2, the same license). Keeping the DocBook, rather than hand-writing the
pages, means the wording and structure stay identical to upstream, and a
future upstream sync is a diff on the XML.

The generated roff pages live under `man5/` and are what the installer ships.
Regenerate them after editing anything under `docbook/`:

    packaging/man/regenerate.py

It needs `python3-lxml` and the docbook-xsl manpages stylesheet (the
`docbook-xsl` package). It applies the stylesheet through lxml, so no external
command is required, and it names each page after its source file, so
`man shorewall-rules` works.

## The nftables notes

The one change from upstream is added content, never removed content. Where a
setting or keyword produces a specific construct in the nftables ruleset, a
short paragraph in the same voice records it, led by a bold `nftables:`. For
example, in `shorewall-policy` the ACCEPT policy note reads:

> nftables: the zone-pair chain ends in accept, after the leading ct state
> established,related accept that every chain carries.

Keep the notes factual and current with what the compiler emits. Confirm the
output by compiling a small configuration and reading the ruleset, not from
memory. `shorewall-policy` is the worked example; the other pages are being
annotated the same way.
