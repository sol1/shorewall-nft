#!/usr/bin/env python3
"""Regenerate the configuration-file man pages from the vendored DocBook.

The DocBook under packaging/man/docbook/ is Shorewall's own manpage source,
kept here so the pages read exactly like upstream, plus the shorewall-nft
notes we add to it. This script turns it into roff man pages with the
docbook-xsl manpages stylesheet, driven through lxml, so the only thing needed
is python3-lxml and the docbook-xsl stylesheets, no external command.

Run it after editing anything under packaging/man/docbook/. It writes
packaging/man/man5/, which the installer ships.

Usage: packaging/man/regenerate.py
"""
import glob
import os
import sys
import tempfile

try:
    from lxml import etree
except ImportError:
    sys.exit("regenerate needs python3-lxml (pip install lxml, or the distro "
             "package python3-lxml)")

HERE = os.path.dirname(os.path.realpath(__file__))
SRC = os.path.join(HERE, "docbook")
OUT = os.path.join(HERE, "man5")

# The manpages stylesheet, at its usual place on Debian, Fedora and Arch.
STYLESHEETS = [
    "/usr/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl",
    "/usr/share/xml/docbook/stylesheet/docbook-xsl-ns/manpages/docbook.xsl",
    "/usr/share/sgml/docbook/xsl-stylesheets/manpages/docbook.xsl",
]


def find_stylesheet():
    for p in STYLESHEETS:
        if os.path.exists(p):
            return p
    for base in ("/usr/share/xml/docbook", "/usr/share/sgml/docbook"):
        hits = glob.glob(base + "/**/manpages/docbook.xsl", recursive=True)
        if hits:
            return hits[0]
    sys.exit("docbook-xsl manpages stylesheet not found; install docbook-xsl")


def main():
    xsl = etree.parse(find_stylesheet())
    # The manpages stylesheet writes its output with exsl:document, so lxml
    # needs write access, which it denies by default.
    transform = etree.XSLT(xsl, access_control=etree.XSLTAccessControl(
        read_file=True, write_file=True, create_dir=True,
        read_network=False, write_network=False))
    os.makedirs(OUT, exist_ok=True)
    for old in glob.glob(os.path.join(OUT, "*")):
        os.remove(old)
    count = 0
    for xml in sorted(glob.glob(os.path.join(SRC, "*.xml"))):
        base = os.path.splitext(os.path.basename(xml))[0]
        # The stylesheet names the output by the refname and writes it to the
        # working directory, so run each conversion in its own temp dir and
        # rename the result to the source's own name (man shorewall-rules, not
        # man rules).
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                transform(etree.parse(xml))
                produced = sorted(glob.glob("*.[0-9]"))
                if not produced:
                    sys.exit(f"no man page produced for {os.path.basename(xml)}")
                vol = os.path.splitext(produced[0])[1]        # .5, .8, ...
                data = open(produced[0], "rb").read()
            finally:
                os.chdir(cwd)
        open(os.path.join(OUT, base + vol), "wb").write(data)
        count += 1
    print(f"generated {count} man pages in {OUT}")


if __name__ == "__main__":
    main()
