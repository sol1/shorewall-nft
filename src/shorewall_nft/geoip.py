"""Populate the geoip country sets at runtime.

The compiler emits an empty `geoip_<cc>` interval set for every country
code a configuration matches with ^CC. This module fills those sets
from per-country CIDR lists, either downloaded or read from a local
directory, and saves a reload file so a restart repopulates without the
network.

The default source is the ipdeny aggregated zone files, the same public
data the community uses. A local directory of <cc>.zone files serves
offline hosts, an admin's own data, or tests.
"""
import ipaddress
import os
import re
import subprocess
import urllib.request

from .chunk import CHUNK_BYTES
from .emit import table_for


def _add_batches(table, setname, cidrs):
    """add-element statements for a set, each batch kept under the netlink
    transaction budget so a large country (thousands of CIDRs) does not
    overflow a single nft transaction."""
    out, batch, size = [], [], 0
    for c in cidrs:
        if batch and size + len(c) + 2 > CHUNK_BYTES:
            out.append(f"add element {table} {setname} {{ {', '.join(batch)} }}")
            batch, size = [], 0
        batch.append(c)
        size += len(c) + 2
    if batch:
        out.append(f"add element {table} {setname} {{ {', '.join(batch)} }}")
    return out

URL_V4 = "https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone"
URL_V6 = "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{cc}-aggregated.zone"


def discover_sets(nft, family):
    """The geoip sets in this family's live table, as (setname, cc,
    family)."""
    out = subprocess.run([nft, "list", "sets", *table_for(family).split()],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return []
    sets = []
    name = None
    for line in out.stdout.splitlines():
        m = re.search(r"set (geoip_[a-z]{2}) \{", line)
        if m:
            name = m.group(1)
        elif name and "type ipv" in line:
            fam = 6 if "ipv6_addr" in line else 4
            sets.append((name, name[len("geoip_"):], fam))
            name = None
    return sets


def _valid(cidr, family):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return net.version == family


def fetch(cc, family, source_dir=None, timeout=30):
    """Return the validated CIDR list for a country. Reads a local
    <cc>.zone or <cc>-aggregated.zone from source_dir when given,
    otherwise downloads the ipdeny aggregated zone."""
    if source_dir:
        for name in (f"{cc}.zone", f"{cc}-aggregated.zone"):
            path = os.path.join(source_dir, name)
            if os.path.isfile(path):
                with open(path) as f:
                    text = f.read()
                break
        else:
            raise FileNotFoundError(f"no zone file for {cc} in {source_dir}")
    else:
        url = (URL_V6 if family == 6 else URL_V4).format(cc=cc)
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            text = resp.read().decode()
    cidrs = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if line and _valid(line, family):
            cidrs.append(line)
    return cidrs


def _load_set(nft, table, setname, cidrs, geodir):
    """Flush and refill a set from the live table, then write a reload file so
    the wrapper can repopulate it on a restart without the network. The refill
    is applied in transactions kept under the netlink budget: a large country
    exceeds a single transaction. If a batch fails, the set is restored from
    the last good reload file rather than left empty, which would fail a geoip
    rule open."""
    lines = _add_batches(table, setname, cidrs)
    reload_file = os.path.join(geodir, f"{setname}.nft")
    first = f"flush set {table} {setname}\n" + (lines[0] + "\n" if lines else "")
    try:
        subprocess.run([nft, "-f", "-"], input=first, text=True, check=True)
        for stmt in lines[1:]:
            subprocess.run([nft, "-f", "-"], input=stmt + "\n", text=True,
                           check=True)
    except subprocess.CalledProcessError:
        # Roll back to the previous contents so the set is never left empty.
        if os.path.isfile(reload_file):
            with open(reload_file) as f:
                subprocess.run([nft, "-f", "-"],
                               input=f"flush set {table} {setname}\n" + f.read(),
                               text=True)
        raise
    os.makedirs(geodir, exist_ok=True)
    with open(reload_file, "w") as f:
        f.write("\n".join(lines) + "\n")


def update(nft, geodir, family, source_dir=None, only=None):
    """Refresh every geoip set in this family's live table. Returns a
    list of (setname, count, error) tuples, one per set."""
    table = table_for(family)
    results = []
    for setname, cc, setfam in discover_sets(nft, family):
        if only and cc not in only:
            continue
        try:
            cidrs = fetch(cc, setfam, source_dir)
            if not cidrs:
                raise ValueError("no valid CIDRs")
            _load_set(nft, table, setname, cidrs, geodir)
            results.append((setname, len(cidrs), None))
        except Exception as e:              # noqa: BLE001 report per set
            results.append((setname, 0, str(e)))
    return results
