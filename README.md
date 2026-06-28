# kres-netlinkd

`kres-netlinkd` is a small Go daemon that keeps [nftables](https://wiki.nftables.org/) sets in
sync with DNS answers observed by [Knot Resolver](https://www.knot-resolver.cz/).

It is meant for selective routing / policy-based "VPN" setups: you decide which domains should be
routed through a given target (for example, a VPN interface), and as soon as the resolver answers a
query for one of those domains, the resolved IPv4/IPv6 addresses are added to the matching nftables
sets. Your firewall/routing rules can then match traffic to those addresses and route it accordingly.

## How it works

The project has two cooperating parts:

1. **`blocked.lua`** – a Knot Resolver module (LuaJIT). It inspects every `A`/`AAAA` answer, checks the
   queried name against a configurable domain → target map, and for matching names extracts the
   resolved addresses and sends them to the daemon over a Unix domain socket.
2. **`kres-netlinkd`** – the Go daemon. It listens on a Unix domain socket, receives newline-delimited
   JSON messages, validates the addresses, and adds them as elements to the appropriate nftables sets
   directly over netlink.

```
            DNS query
client ───────────────▶ Knot Resolver ──(A/AAAA answer)──▶ blocked.lua
                                                               │
                                       JSON over AF_UNIX socket │
                                                               ▼
                                                         kres-netlinkd
                                                               │
                                                  netlink (add set element)
                                                               ▼
                                                        nftables sets
                                              blocked-<target>  / blocked6-<target>
```

### Wire protocol

The resolver module connects to the daemon's Unix socket and writes one JSON object per line. Each
message looks like:

```json
{"name":"<target>","ipv4":["1.2.3.4"],"ipv6":["2001:db8::1"]}
```

For every received line the daemon replies with a single plain-text, newline-terminated line:

- `OK` – the message was applied successfully (or contained no usable addresses);
- `NOK` – the line could not be decoded or applying it failed.

The connection stays open and can carry many messages in sequence; a `NOK` does not close it.

### Set naming

For a message with `name = "vpn"` the daemon resolves the nftables sets as:

- IPv4 set: `<set-prefix><name>`  → `blocked-vpn` by default;
- IPv6 set: `<set-prefix6><name>` → `blocked6-vpn` by default.

The sets must already exist in the configured table; the daemon only adds elements to them. Target
names are restricted to `[A-Za-z0-9_-]+` to avoid resolving unexpected set names. Invalid or
mismatched addresses (e.g. an IPv6 value in the IPv4 list) are skipped and logged.

## Requirements

- Linux with `nftables`.
- Go 1.26+ to build the daemon.
- Knot Resolver (with LuaJIT/FFI support) to run the `blocked.lua` module.
- The daemon must run with enough privileges to modify nftables over netlink (typically root or
  `CAP_NET_ADMIN`).

## Building

```sh
go build -o kres-netlinkd .
```

Run the tests with:

```sh
go test ./...
```

## Running the daemon

```sh
./kres-netlinkd [flags]
```

### Flags

| Flag           | Default                   | Description                                         |
|----------------|---------------------------|-----------------------------------------------------|
| `-socket`      | `/run/kres-netlinkd.sock` | Unix socket path to listen on.                      |
| `-family`      | `inet`                    | nftables table family: `inet`, `ip`, or `ip6`.      |
| `-table`       | `route`                   | nftables table name.                                |
| `-set-prefix`  | `blocked-`                | Prefix for IPv4 set names.                          |
| `-set-prefix6` | `blocked6-`               | Prefix for IPv6 set names.                          |

Logging is configured through the standard [apexutils](https://github.com/kvaster/apexutils) flags.

The daemon removes any stale socket file on start, creates the socket with mode `0660`, and removes
it again on shutdown. It stops cleanly on `SIGINT`, `SIGTERM`, or `SIGHUP`.

## Configuring nftables

Create the table and the sets referenced by your targets before starting the daemon. For example,
for a target named `vpn` using the defaults (`inet` family, `route` table):

```nft
table inet route {
    set blocked-vpn {
        type ipv4_addr
        flags interval
    }
    set blocked6-vpn {
        type ipv6_addr
        flags interval
    }
}
```

You can then add routing/marking rules that match these sets.

## Configuring Knot Resolver

1. Install `blocked.lua` (for example to `/etc/knot-resolver/blocked.lua`) and make sure
   `SOCKET_PATH` inside it matches the daemon's `-socket` value. The bundled module uses
   `/var/lib/knot-resolver/kres-netlinkd.sock`, so either change it or start the daemon with a
   matching `-socket`.
2. Provide a domain map module `blocked-map.lua` next to it that returns a table mapping each target
   name to the list of domains that should be routed through it:

   ```lua
   -- /etc/knot-resolver/blocked-map.lua
   return {
       vpn = {
           "example.com",
           "example.org",
       },
   }
   ```

   Domains are matched on label boundaries, so a configured `example.com` also matches
   `www.example.com`.
3. Load the module from your resolver configuration:

   ```lua
   modules.load('blocked')
   ```

When the resolver answers a matching query, the addresses are forwarded to the daemon and inserted
into the corresponding sets. If the daemon is unreachable or replies with `NOK`, the module logs a
warning and DNS resolution proceeds normally.

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
