# Man pages

`shorewall.8` is the command reference for shorewall-nft, shipped by the
installer and the packages. It is written for this implementation.

## Config-file man pages

The 42 shorewall-*(5) pages (shorewall-zones, shorewall-rules and the
rest) describe the configuration file formats. Because shorewall-nft
reads the identical files, those pages apply as written for the
supported files. They are adopted from upstream at package build time
rather than forked here, so they do not drift from the format they
document:

1. Take the upstream DocBook manpage sources (GPLv2, the same license).
2. Prepend a short banner naming the shorewall-nft support state, from
   docs/coverage.md: supported, deprecated, or not supported.
3. Convert to man format and install under $MANDIR/man5.

Keeping them generated from upstream, banner aside, means an admin's
`man shorewall-rules` stays correct and does not become a second copy we
have to maintain by hand. The per-file support state lives in
docs/coverage.md, which the banner points to, so there is one source of
truth for what works.

Until the build step lands, `man shorewall` and docs/coverage.md cover
the same ground.
