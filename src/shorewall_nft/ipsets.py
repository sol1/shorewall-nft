"""Translate ipset save files to native nft sets.

Real deployments keep an ipset dump in /etc/shorewall/ipsets and load
it at boot. nftables replaces ipset with typed native sets, so the
dump becomes set declarations with elements. This is the same job as
ipset-translate, done at compile time.

Supported set types: hash:ip, hash:net (interval sets). Anything else
fails loudly at the point of use.
"""
import os
from dataclasses import dataclass, field

from .errors import ConfigError


@dataclass
class IpsetDef:
    name: str
    settype: str              # hash:ip or hash:net
    family: str = "inet"
    elements: list = field(default_factory=list)


def parse(path):
    sets = {}
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            parts = line.split()
            if not parts or parts[0].startswith("#"):
                continue
            if parts[0] == "create":
                name, settype = parts[1], parts[2]
                if settype not in ("hash:ip", "hash:net"):
                    raise ConfigError(
                        f"ipset type {settype} not supported yet",
                        path, lineno)
                fam = "inet"
                if "family" in parts:
                    fam = parts[parts.index("family") + 1]
                sets[name] = IpsetDef(name=name, settype=settype, family=fam)
            elif parts[0] == "add":
                name = parts[1]
                if name not in sets:
                    raise ConfigError(f"add to unknown ipset {name}",
                                      path, lineno)
                sets[name].elements.append(parts[2])
            elif parts[0] in ("flush", "destroy", "swap"):
                continue
            else:
                raise ConfigError(f"unsupported ipset command {parts[0]}",
                                  path, lineno)
    return sets


def load_for(confdir):
    path = os.path.join(confdir, "ipsets")
    if not os.path.isfile(path):
        return {}
    return parse(path)
