# Contributing

Keep changes fail-closed and avoid executing fixture content. Security fixtures must be inert text that demonstrates a pattern without contacting a network, changing the host, or containing live malware.

Before submitting a change, run:

```bash
python3 -m unittest discover -s tests -v
ruff check .
ruff format --check .
```

Changes to the `yay` or `makepkg` integration should include a regression test and an update to the threat model when they alter a guarantee or trust boundary. Never weaken a blocking condition merely to make a real package pass; document and design a narrow policy exception instead.
