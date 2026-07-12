# Ereshkigal documentation

Ereshkigal is the Sumerian goddess of Kur, the underworld. She decides
who is sent below, how long they stay, and who is permitted to return
to the world above.

- [architecture.md](architecture.md) :: how the manager and the kur underworlds fit
  together — processes, sockets, the protocol, sentences, the sweeper, and the clay
  tablets

- [install.md](install.md) :: dependencies in detail, per-OS install, and running at boot

- [configuration.md](configuration.md) :: the ereshkigal.toml reference and a complete
  example
  
- [usage.md](usage.md) :: communing with Ereshkigal via CLI or socket

- [security.md](security.md) :: the trust model, Neti at the gate, and why you probably
  want `kill = 1`

- [examples.md](examples.md) :: More examples!

Also...

- `perldoc Ereshkigal`
- `perldoc Ereshkigal::Kur`
- `perldoc Ereshkigal::Client`
