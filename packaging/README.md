# packaging/

Deployment files. Nothing here is required to build or run Favonius — see
the README's Quick Start for that.

| file | what it is |
|---|---|
| `favonius-daemon.service` | systemd unit for the receiver, hardened, with `--dest-root` set |

## The `fvn` alias

`fvn` is a short alias for the `favonius` client. It is a **symlink, not a
second binary** — same executable, same behaviour, nothing dispatches on
`argv[0]`. Release tarballs ship it alongside `favonius`; if you install
from source, make it yourself:

```bash
install -m755 target/release/favonius        /usr/local/bin/favonius
install -m755 target/release/favonius-daemon /usr/local/bin/favonius-daemon
ln -sf favonius /usr/local/bin/fvn
```

The link is relative on purpose, so it survives being moved with the
directory it lives in. Use whichever name you prefer:

```bash
fvn send /tmp/big.bin "10.0.0.2:7801:/srv/in/big.bin"
```

The daemon has no alias. It is typed once in a unit file, not
interactively, so a short form would buy nothing.

## Not here yet

No distribution packages (`.deb`, `.rpm`), no Homebrew formula, no
container image for the daemon itself. Release binaries are attached to
GitHub releases by `.github/workflows/release.yml` when a `v*` tag is
pushed; there is no `cargo install` path yet because the binaries live in a
workspace rather than a published crate.
