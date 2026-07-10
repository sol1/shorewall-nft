"""Translate ipset save files to native nft sets.

Real deployments keep an ipset dump in /etc/shorewall/ipsets and load
it at boot. nftables replaces ipset with typed native sets, so the
dump becomes set declarations with elements. This is the same job as
ipset-translate, done at compile time.

Supported set types: hash:ip, hash:net (interval sets). Anything else
fails loudly at the point of use.
"""
import os
import sys
from dataclasses import dataclass, field

from .errors import ConfigError


@dataclass
class IpsetDef:
    name: str
    settype: str              # hash:ip or hash:net
    family: str = "inet"
    timeout: int = 0          # default element timeout in seconds, 0 = none
    elements: list = field(default_factory=list)


def parse(path, strict=True):
    """Parse an ipset save file. Returns (sets, unsupported), where
    unsupported is a list of (name, settype) skipped because the type is
    not translatable. In strict mode an unsupported type raises instead,
    so a typo or a genuinely unhandled set is caught. In lenient mode the
    set and its adds are skipped and reported, so one odd set does not
    take the whole ruleset down."""
    sets = {}
    unsupported = []
    skipped = set()
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            parts = line.split()
            if not parts or parts[0].startswith("#"):
                continue
            if parts[0] == "create":
                name, settype = parts[1], parts[2]
                if settype not in ("hash:ip", "hash:net"):
                    if strict:
                        raise ConfigError(
                            f"ipset type {settype} not supported yet",
                            path, lineno)
                    unsupported.append((name, settype))
                    skipped.add(name)
                    continue
                fam = "inet"
                if "family" in parts:
                    fam = parts[parts.index("family") + 1]
                timeout = 0
                if "timeout" in parts:
                    timeout = int(parts[parts.index("timeout") + 1])
                sets[name] = IpsetDef(name=name, settype=settype, family=fam,
                                      timeout=timeout)
            elif parts[0] == "add":
                name = parts[1]
                if name in skipped:
                    continue
                if name not in sets:
                    raise ConfigError(f"add to unknown ipset {name}",
                                      path, lineno)
                sets[name].elements.append(parts[2])
            elif parts[0] in ("flush", "destroy", "swap"):
                continue
            else:
                raise ConfigError(f"unsupported ipset command {parts[0]}",
                                  path, lineno)
    return sets, unsupported


def load_for(confdir, strict=True):
    path = os.path.join(confdir, "ipsets")
    if not os.path.isfile(path):
        return {}
    sets, unsupported = parse(path, strict)
    for name, settype in unsupported:
        print(f"shorewall-nft: ipset {name} (type {settype}) is not "
              f"supported and was skipped; rules using +{name} will match "
              "nothing", file=sys.stderr)
    return sets
