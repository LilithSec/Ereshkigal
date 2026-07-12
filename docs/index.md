# Ereshkigal documentation

Ereshkigal is the Sumerian goddess of Kur, the underworld — she
decides who is sent below, how long they stay, and who returns. In
the world above, Ereshkigal is a ban manager for firewalls: an
`ereshkigal` manager ruling over one `kur` underworld per firewall
concern, each wrapping a Net::Firewall::BlockerHelper backend.

| doc                                    | covers                                                        |
|----------------------------------------|---------------------------------------------------------------|
| [architecture.md](architecture.md)     | how the manager and the kur underworlds fit together — processes, sockets, the protocol, sentences and the sweeper, the clay tablets |
| [install.md](install.md)               | dependencies in detail, per-OS install, and running at boot    |
| [configuration.md](configuration.md)   | the ereshkigal.toml reference and a complete example           |
| [usage.md](usage.md)                   | the CLI by task, and driving the socket directly from integrations |
| [security.md](security.md)             | the trust model, Neti at the gate, and why you probably want `kill = 1` |
| [examples.md](examples.md)             | worked scenarios to copy from                                  |

Startup scripts for running at boot ship in the source tree's
[`rc/`](../rc/) directory — a FreeBSD rc.d script at
`rc/freebsd/ereshkigal` and a systemd unit at
`rc/systemd/ereshkigal.service`; [install.md](install.md) covers
putting them in place.

The module POD (`perldoc Ereshkigal`, `perldoc Ereshkigal::Kur`,
`perldoc Ereshkigal::Client`, and so on) is the API reference, and
[DESIGN.md](../DESIGN.md) in the repo root is the development design
doc.
