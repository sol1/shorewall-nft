"""Split a monolithic nft ruleset into loadable chunks.

A very large ruleset is one netlink transaction, and one transaction
must fit the socket send buffer. Big rulesets come in two shapes:
many chains (zone-heavy configs) and huge sets (country-block ipsets).
Both split:

  skeleton   destroy + recreate the table, declare every set (empty),
             object and chain with its hook and policy, but no rules
             and no set elements. Small, one transaction. Hook chains
             carry their real drop policy, so the window before the
             chunks load is fail closed.
  chunks     add element batches for set contents, then add rule
             batches, each under a byte budget.

The monolithic file is still emitted and preferred. Chunking is the
fallback for when one transaction cannot fit.
"""

# Conservative budget per chunk in bytes. Comfortably under a default
# 212992 byte wmem_max, which the kernel halves for accounting.
CHUNK_BYTES = 60000

HEADER_STARTS = ("type ", "policy ")


class _Chunker:
    def __init__(self):
        self.chunks = []
        self.current = []
        self.size = 0

    def add(self, stmt):
        if self.size + len(stmt) + 1 > CHUNK_BYTES:
            self.flush()
        self.current.append(stmt)
        self.size += len(stmt) + 1

    def flush(self):
        if self.current:
            self.chunks.append("\n".join(self.current) + "\n")
            self.current = []
            self.size = 0


def _collapse(elements):
    """Merge overlapping and adjacent networks. Within one transaction
    auto-merge does this, but chunked adds are separate transactions
    and the kernel rejects overlaps arriving later. Falls back to the
    raw list when elements are not plain addresses."""
    import ipaddress
    try:
        nets = [ipaddress.ip_network(e, strict=False) for e in elements]
    except ValueError:
        return elements
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    out = []
    for group in (v4, v6):
        for n in ipaddress.collapse_addresses(group):
            out.append(str(n))
    return out


def _element_statements(table, name, elements, out):
    """Batch set elements into add element statements."""
    batch = []
    batch_len = 0
    limit = CHUNK_BYTES // 2
    for e in _collapse(elements):
        batch.append(e)
        batch_len += len(e) + 2
        if batch_len >= limit:
            out.add(f"add element {table} {name} {{ "
                    + ", ".join(batch) + " }")
            batch = []
            batch_len = 0
    if batch:
        out.add(f"add element {table} {name} {{ " + ", ".join(batch) + " }")


def split(text, table="inet shorewall"):
    """Return (skeleton_text, [chunk_text, ...]).

    Parses our own emitter output, which is regular: one statement per
    line, blocks opened with `... {` and closed with `}`, and set
    elements written as an `elements = {` block of comma-separated
    lines.
    """
    skeleton = [f"table {table}", f"delete table {table}", f"table {table} {{"]
    elements_out = _Chunker()
    rules_out = _Chunker()

    context = "table"     # table, chain, object or elements
    chain_name = None
    object_name = None
    element_items = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("delete table") or (
                line.startswith("table ") and not line.endswith("{")):
            # The declare and delete that atomically replace our table.
            continue
        if line.startswith("table ") and line.endswith("{"):
            continue
        if context == "elements":
            if line == "}":
                _element_statements(table, object_name, element_items,
                                    elements_out)
                element_items = []
                context = "object"
                continue
            for item in line.split(","):
                item = item.strip()
                if item:
                    element_items.append(item)
            continue
        if line == "}":
            if context in ("chain", "object"):
                skeleton.append("    }")
                context = "table"
                chain_name = None
                object_name = None
            continue
        if line.endswith("{"):
            first = line.split()[0]
            if context == "object" and first == "elements":
                context = "elements"
                continue
            if first in ("chain", "map"):
                context = "chain"
                chain_name = line.split()[1]
            else:
                context = "object"
                object_name = line.split()[1] if len(line.split()) > 1 \
                    else None
            skeleton.append("    " + line)
            continue
        if context == "object":
            skeleton.append("        " + line)
            continue
        if context == "chain":
            if line.startswith(HEADER_STARTS):
                skeleton.append("        " + line)
                continue
            rules_out.add(f"add rule {table} {chain_name} {line}")
            continue
        skeleton.append("    " + line)
    elements_out.flush()
    rules_out.flush()

    skeleton.append("}")
    return ("\n".join(skeleton) + "\n",
            elements_out.chunks + rules_out.chunks)
