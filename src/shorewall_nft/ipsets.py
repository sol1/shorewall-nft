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
                if len(parts) < 3:
                    raise ConfigError("ipset create needs NAME TYPE",
                                      path, lineno)
                name, settype = parts[1], parts[2]
                if settype not in ("hash:ip", "hash:net"):
                    if strict:
                        raise ConfigError(
                            f"ipset type {settype} not supported yet",
                            path, lineno)
                    unsupported.append((name, settype))
                    skipped.add(name)
                    continue
                # Options follow the type. Look for keywords only there, so a
                # set literally named "family" or "timeout" is not mistaken
                # for the option, and bound-check the value.
                opts = parts[3:]
                fam = "inet"
                if "family" in opts:
                    idx = parts.index("family", 3)
                    if idx + 1 >= len(parts):
                        raise ConfigError(f"ipset {name}: family needs a value",
                                          path, lineno)
                    fam = parts[idx + 1]
                timeout = 0
                if "timeout" in opts:
                    idx = parts.index("timeout", 3)
                    if idx + 1 >= len(parts):
                        raise ConfigError(f"ipset {name}: timeout needs a value",
                                          path, lineno)
                    try:
                        timeout = int(parts[idx + 1])
                    except ValueError:
                        raise ConfigError(
                            f"ipset {name}: timeout not an integer: "
                            f"{parts[idx + 1]!r}", path, lineno)
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
              f"supported and was skipped; rules using +{name} match "
              "nothing, so a DROP or REJECT that relies on it will not "
              "block and an ACCEPT will not match. Set REQUIRE_IPSETS=Yes "
              "to make this a hard error instead.", file=sys.stderr)
    return sets
