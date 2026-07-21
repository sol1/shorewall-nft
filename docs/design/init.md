# shorewall init: bootstrap a clean install

## The goal

`shorewall migrate` adapts an existing /etc/shorewall. It has nothing to do on
a box that never ran Shorewall. `shorewall init` is the other half: on a clean
install with no configuration, it writes a working starting point, with the
interfaces filled in from the running system, and leaves you a firewall you can
check and start.

It is a bootstrap, not a policy engine. It produces one of the three classic
Shorewall topologies, the same ones the sample configs and the test corpus are
built from, and then gets out of the way so you can edit /etc/shorewall.

## The three topologies

Straight from the upstream samples (corpus 0002 to 0004):

- **Standalone** (one interface). Protect this one box. Zones fw and net.
  Policy: the firewall reaches out (`$FW net ACCEPT`), the world is dropped
  (`net all DROP`), everything else rejected.
- **Gateway** (two interfaces). Share one uplink with a LAN, with NAT. Zones
  fw, net, loc. Policy: `loc net ACCEPT`, `net all DROP`, `all all REJECT`. A
  MASQUERADE of the RFC1918 ranges out the uplink.
- **Three-zone** (three interfaces). Add a DMZ. Zones fw, net, loc, dmz, with
  the DMZ reachable from the LAN and able to reach the net.

## What it detects

The wizard reads the running system so you are choosing real interfaces, not
typing them from memory:

- `ip -o link show` for the interfaces, with their addresses, skipping lo and
  the obviously-virtual (docker0, veth*, br-*, virbr*), which it lists but does
  not select by default.
- `ip route show default` to guess the uplink: the interface with the default
  route is offered as net (the internet side).

You confirm or override each role. The rest is derived.

## What it writes

Into /etc/shorewall (or a directory you pass), adapted from the samples with
your interface names:

- **zones**: fw firewall, then net/loc/dmz per topology.
- **interfaces**: each zone on its device, with the sample's safe options
  (tcpflags, nosmurfs, routefilter, logmartians, sourceroute=0; dhcp on the
  uplink).
- **policy**: the topology's policy above, ending in `all all REJECT` with a
  log level.
- **rules**: a minimal, safe set. DNS and ping out, ping controlled inbound,
  and, importantly, SSH to the firewall so a remote box is not locked out (see
  below).
- **snat**: for gateway and three-zone, MASQUERADE the RFC1918 ranges out the
  uplink.
- **shorewall.conf**: a stock config with sane defaults.

Numbers use literal values (log levels, RFC1918 ranges) rather than variables,
so the generated tree is self-contained and readable.

## Safety

init is for clean installs and must never surprise a running system:

- **It refuses to overwrite an existing configuration.** If /etc/shorewall
  already has real content, it stops and points at `migrate`. `migrate` already
  does the reverse, refusing when there is nothing to migrate. `--force` backs
  up the existing files to a timestamped directory first.
- **It never starts the firewall.** It writes the files, runs `shorewall
  check`, and prints the next steps. Starting is your decision.
- **It keeps SSH open to the firewall.** The generated rules always allow SSH
  to $FW (from the LAN on a gateway, and optionally from the net), so
  initialising a firewall over ssh cannot lock you out. This is the one thing a
  naive starter config gets wrong, so init gets it right by default.

## The command

Interactive by default:

    $ shorewall init
    No configuration at /etc/shorewall. Let's create a starting point.

    Interfaces on this system:
      eth0   203.0.113.10/24   (default route)   likely your uplink
      eth1   192.168.1.1/24
      docker0                                     virtual, skipped

    Topology?
      1) Standalone host   protect this box
      2) Gateway / router  two interfaces, LAN behind one uplink, NAT
      3) Three-zone        add a DMZ
    [2]:

    Uplink (net) interface [eth0]:
    LAN (loc) interface [eth1]:
    Allow SSH to the firewall from the LAN? [Y/n]:
    Allow SSH from the internet? [y/N]:

    Wrote /etc/shorewall (zones, interfaces, policy, rules, snat, shorewall.conf).
    shorewall check: verified.

    Next:
      shorewall start                    # load it now
      systemctl enable --now shorewall   # and at boot

Non-interactive, for Ansible and scripts:

    shorewall init --gateway --net eth0 --loc eth1 [--ssh-from net] [--force]
    shorewall init --standalone --net eth0
    shorewall init --three-zone --net eth0 --loc eth1 --dmz eth2

With every interface given on the command line, no detection or prompting
happens, so a provisioning run is deterministic. A future `shorewall automate
init` can wrap this with JSON output.

## How it fits

- `init` bootstraps a clean box; `migrate` adapts an existing Shorewall box.
  Each refuses the other's job and says which to run.
- The output is an ordinary /etc/shorewall you then edit. init is a starting
  point, not a manager: it does not come back and rewrite your files.

## Testing

- An init-proof: in a namespace with dummy interfaces (eth0, eth1, eth2),
  run `init` non-interactively for each topology and assert the generated tree
  compiles and passes nft-check, that the SSH-to-firewall rule is present, and
  that a gateway config emits the masquerade. Loading a generated gateway in
  the sandbox and probing it reuses the behavioural engine.
- A safety check: init refuses when /etc/shorewall already has content, and
  `--force` backs it up rather than deleting it.
- Interface detection is only the interactive convenience; the tests drive the
  flags, so they stay deterministic and need no real NICs.

## Phasing

1. The non-interactive core: `init --standalone|--gateway|--three-zone` with
   the interface flags, the file templates, the refuse-existing safety, and the
   init-proof. This is the whole value for automation and is fully testable.
2. The interactive wizard: interface detection, the default-route guess, the
   prompts. A thin layer over the core.
3. Polish: `--force` backups, an optional `--start`, and `shorewall automate
   init` with JSON.
