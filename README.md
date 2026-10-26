# OPNsense plugins

Plugins for [OPNsense](https://opnsense.org/), each in its upstream category directory:

- `net/wg-client-tunnels`: WireGuard upstream tunnels ([page](https://legotypes.github.io/wg-upstream-tunnels/))
- `net/mac-alias-cache`: rebuild MAC firewall aliases from current host discovery
  ([page](https://legotypes.github.io/mac-alias-cache/))
- `net/wan-failover`: hold a lossy WAN down until it is clean
- `dns/unbound-upstream`: forward Unbound's root zone through a gateway group's best member

Each plugin builds inside the [opnsense/plugins](https://github.com/opnsense/plugins) tree (its `Makefile` includes
`../../Mk/plugins.mk`). The packages are built and signed by
[LegoTypes/opnsense-repo](https://github.com/LegoTypes/opnsense-repo) and installed from the signed LegoTypes
repository: see [Install](https://legotypes.github.io/install/).

BSD 2-Clause licensed; see `LICENSE`.
