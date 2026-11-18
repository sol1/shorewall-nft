# shorewall

The `shorewall` command compiles the configuration and controls the running
firewall. On an IPv6 system the command is `shorewall6` and reads
`/etc/shorewall6`. Everything below applies to both.

```text
shorewall [options] <command> [arguments]
```

## Options

Options come before the command.

`-v`, `-q`
: Raise or lower the amount of progress output. Repeatable.

`-vN`
: Set the level directly, from `-1` to `2`. `0` is quiet, `1` is the default,
  `2` is full detail. This overrides `VERBOSITY` in shorewall.conf.

`trace`, `debug`
: Accepted for compatibility with Shorewall and ignored.

## Firewall lifecycle

`start [directory]`
: Compile the configuration and load the ruleset.

`reload`, `restart [directory]`
: Recompile and reload the ruleset.

`stop`
: Load the stopped ruleset, which permits only the hosts listed in
  [stoppedrules](configuration-files.md). The firewall is still running; it is
  not open.

`clear`
: Remove the shorewall table entirely. This leaves the firewall open. Use it to
  recover from a lockout.

`try directory [timeout]`
: Load a configuration and revert it unless you confirm it within the timeout.

`safe-start`, `safe-restart [directory]`
: Like `start` and `restart`, but revert automatically unless you confirm. Use
  these over a remote link so a mistake does not lock you out.

## Status and inspection

`status`
: Report whether the firewall is running and how many rules it has.

`show`, `list`, `ls [object]`
: Show the ruleset, or `capabilities`, `zones`, `routing` or `connections`.
  `show routing <dest>` names the provider a flow would take.

`monitor [fancy]`
: A live view of the firewall. `fancy` is the full-screen variant.

`version`
: Print the shorewall-nft version and the nft version.

## Configuration

`check [directory]`
: Compile and validate a configuration without loading it. Run it before every
  `start`.

`compile [directory] -o file`
: Write the generated nftables ruleset to a file, loading nothing.

`init [topology] [--net dev] [--loc dev] [--dmz dev] [--ssh-from zones] [--force]`
: Bootstrap a clean configuration. With no arguments it runs a wizard.

`migrate [--undo] [--yes]`
: Hand a Shorewall system over to shorewall-nft, or reverse it.

`save`, `restore`, `forget [name]`
: Manage a saved ruleset.

`savesets`
: Snapshot externally-filled ipsets so they survive a reload or reboot.

`automate command`
: The JSON machine interface, for configuration-management tools.

## Multi-ISP providers

`enable provider`
: Return a provider to service and recompute routing.

`disable provider`
: Take a provider out of service and recompute routing.

`reenable provider`
: Reset a provider to enabled.

`lsm [--once]`
: Run the link status monitor. `--once` runs a single check cycle.

## Remote Shorewall Lite

These compile here and drive Shorewall Lite on another machine over ssh.

`remote-start`, `remote-reload`, `remote-restart [-r user] [-s] [-D dir] [--capture | --caps file] system`
: Compile here, then start, reload or restart Shorewall Lite on the target.

`remote-check [-r user] [-D dir] [--capture | --caps file] system`
: Validate the configuration against the target's kernel, loading nothing.

`remote-getcaps [-R] [-r user] [-D dir] system`
: Fetch the target's capability profile. `-R` also fetches its shorewallrc.

`remote-getrc [-c] [-r user] [-D dir] system`
: Fetch the target's shorewallrc. `-c` also fetches its capabilities.

## Utilities

`ipcalc address mask | address/vlsm`
: Print the network, broadcast and host range for an address.

`iprange low-high`
: Express an address range as the smallest set of CIDR blocks.

`geoip-update [--from dir] [cc ...]`
: Fill the geoip country sets from downloaded or local CIDR data.

`help [command]`
: Show the command list, or the usage for one command.

## See also

`shorewall help` prints this list at the terminal, and `shorewall help
<command>` prints the usage for one command.
