# Documentation site

The shorewall-nft documentation. It is a MkDocs site built with the Material
theme. The source is Markdown under `docs/`.

## Build and preview

```sh
cd docs-site
pip install -r requirements.txt
mkdocs serve          # preview at http://127.0.0.1:8000
mkdocs build          # render to ./site
```

## Layout

- `docs/index.md` introduces shorewall-nft.
- `docs/getting-started/` holds the scenario walk-throughs, one per common
  network. Each one shows a complete configuration.
- `mkdocs.yml` holds the theme, the navigation and the Markdown extensions.

## Verified examples

Every configuration a page shows is compiled and checked. A page prints its
configuration as fenced blocks, each tagged with the file it belongs to:

````markdown
```text title="/etc/shorewall/zones"
fw      firewall
net     ipv4
loc     ipv4
```
````

`tests/harness/docs-proof.py` reads those blocks, writes them to a
configuration directory, compiles it with shorewall-nft, and runs the result
through `nft -c`. The proof is part of `tests/run`, so a page that shows a
configuration the compiler rejects fails the suite. The examples in the
documentation are the examples the test kernel accepts.

A page can steer the proof with an HTML comment:

- `<!-- docs-proof: skip -->` leaves the page out of the check.
- `<!-- docs-proof: base=getting-started/two-interface.md -->` starts from
  another page's configuration, then overlays this page's files. Use it on a
  how-to that shows only the lines it adds.
- `<!-- docs-proof: family=6 -->` compiles the page for IPv6.

## Publishing

`.github/workflows/docs.yml` builds the site and deploys it to GitHub Pages on
every push to `main` that touches `docs-site/`. The repository must have Pages
set to build from GitHub Actions. The site is meant to move to shorewall.org
later; only `site_url` and the DNS need to change.
