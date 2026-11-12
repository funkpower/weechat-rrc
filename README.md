# weechat-rrc

A native WeeChat plugin, written in C, for [Reticulum Relay Chat](https://rrc.kc1awv.net/)
(RRC): IRC-style rooms on hubs reached over the [Reticulum](https://reticulum.network/)
network.

Reticulum support is built in. The plugin implements the parts an RRC client needs
(identities, announce validation, path requests, links with their handshake, encryption,
identify and keepalive), so it needs no Python and no `rns` package. It connects to a
Reticulum node over TCP, or to the local `rnsd` shared instance, and that node routes it to
the hub over whatever the network runs on: TCP, I2P, LoRa.

## Requirements

| | |
| --- | --- |
| WeeChat | 4.1 or later, with its development header (`weechat-plugin.h`) |
| OpenSSL | libcrypto 1.1.1 or 3.x |
| A Reticulum node | a local `rnsd`, or a transport node with a `TCPServerInterface` you can reach |

On Debian: `apt install build-essential pkg-config weechat-dev libssl-dev`.
On Arch: `pacman -S base-devel weechat openssl`.

## Build and install

```sh
make
make install        # into ~/.local/share/weechat/plugins
```

Then `/plugin load rrc` in WeeChat. It loads by itself on later starts.

The plugin is built against the installed WeeChat's plugin API, so rebuild it when WeeChat is
upgraded. Install with `make install`, not by copying over the old file. WeeChat keeps the loaded
`rrc.so` mapped, and overwriting it in place crashes the next `/plugin reload`.

## Connect

Add a hub by its destination hash, or paste an `rrc://` link (the room in it is joined
automatically):

```
/rrc add permanet rrc://082f8e4293d19281108a5d4faa52dcbe/lobby -nick yournick
/rrc connect permanet
```

Where Reticulum is reached is the server's address, the argument after the hash:

| Address | |
| --- | --- |
| `unix:default` | the local `rnsd` shared instance (the default) |
| `shared:HOST:PORT` | a shared instance over TCP (`shared_instance_port`, 37428) |
| `tcp:HOST:PORT` | a `TCPServerInterface` on a Reticulum transport node |

```
/rrc add community 28c7c1a68c735693aa8e6b8193ed44b2 tcp:node.example.org:4242 -autojoin general -autoconnect
```

Connecting asks the network for a path to the hub, opens a link, identifies, and joins the
server's `autojoin` rooms. On a slow network (I2P, LoRa) this takes a few seconds. If the link
drops, the plugin reconnects, waiting longer after each failure, and rejoins the rooms that are
open.

## Commands

| Command | |
| --- | --- |
| `/rrc list` | servers and their state |
| `/rrc add <name> <hub\|rrc://hub/room> [<address>] [-nick <nick>] [-autojoin <rooms>] [-autoconnect]` | add a server |
| `/rrc del <name>` | delete a server |
| `/rrc connect <name>\|-all` | connect |
| `/rrc disconnect [<name>]` | disconnect |
| `/rrc join <room>`, `/rrc part [<room>]` | join or leave a room |
| `/rrc nick <nick>` | change your nickname |
| `/rrc ping` | round trip to the hub |
| `/rrc status` | link, hops, round trip, hub limits |
| `/rrc identity` | your identity hash |

In RRC buffers `/join`, `/part`, `/me` and `/nick` work as they do on IRC. Text that starts
with `//` goes to the hub as a hub command. On `rrcd` hubs, `//list` lists the registered rooms
and `//who` shows who is in a room. `//topic` and `//register` work there too.

## Settings

Each server's options are `rrc.server.<name>.*`:

| Option | |
| --- | --- |
| `hub` | the hub's destination hash (32 hex characters) |
| `address` | where Reticulum is reached (see above) |
| `nick` | your nickname on this hub |
| `autojoin` | rooms to join on connect, comma-separated |
| `autoconnect` | `on` to connect when WeeChat starts |

| Option | Default | |
| --- | --- | --- |
| `rrc.network.identity_file` | `${weechat_data_dir}/rrc/identity` | the Reticulum identity, created if missing |
| `rrc.network.path_timeout` | `90` | seconds to wait for a path to the hub |
| `rrc.network.debug` | `off` | show paths, link ids and protocol detail in the server buffer |

## Identity and privacy

Your identity is a Reticulum key pair stored in `identity_file` (mode 0600). Its hash is who you
are to every hub: nicknames are labels anyone can pick. The file uses the same 64-byte format as
`rnid` and other Reticulum programs, so you can use an existing identity by pointing
`identity_file` at it. Keep it private, because anyone with the file can speak as you.

Hubs relay a room's messages to everyone in it. Links are encrypted between you and the hub,
but everyone in the room can read what you write there.

## Finding hubs

Hubs announce themselves on the network. On a machine running `rnsd`, every `rrc.hub` destination
it has heard about is in `~/.reticulum/storage/known_destinations`. Their app data names the hub:

```sh
python3 tools/list-hubs.py ~/.reticulum/storage/known_destinations
```

## Tests

```sh
make check        # unit tests against vectors from the Python reference implementation
make check-asan   # the same under AddressSanitizer and UBSan
make fuzz         # random and mutated network input through every parser, under ASan
```

`tests/gen_vectors.py` regenerates `tests/vectors.h` with Python RNS. `tests/rrc-cli` is a
bare command-line client for testing against a hub:
`make tests/rrc-cli && tests/rrc-cli 127.0.0.1:4242 <hub-hash> /tmp/id lobby "hello"`.

## Limits

- Resource transfers are not supported, so messages a hub sends as a Reticulum resource (a very
  long MOTD, a `//who` reply for a large room) do not arrive.
- No direct messages between users.
- Interfaces with IFAC (network name or passphrase) are not supported. Connect through a node that
  handles them.

## License

GPL-3.0. See [LICENSE](LICENSE).
