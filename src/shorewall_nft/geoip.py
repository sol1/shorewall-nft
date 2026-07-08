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

from .emit import table_for

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
    """Flush and refill a set from the live table, then write a reload
    file so the wrapper can repopulate it on a restart without the
    network. Elements are added in chunks to stay under the arg limit."""
    tbl = table.split()
    subprocess.run([nft, "flush", "set", *tbl, setname], check=True)
    lines = []
    for i in range(0, len(cidrs), 500):
        chunk = ", ".join(cidrs[i:i + 500])
        subprocess.run([nft, "add", "element", *tbl, setname,
                        "{ " + chunk + " }"], check=True)
        lines.append(f"add element {table} {setname} {{ {chunk} }}")
    os.makedirs(geodir, exist_ok=True)
    with open(os.path.join(geodir, f"{setname}.nft"), "w") as f:
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
