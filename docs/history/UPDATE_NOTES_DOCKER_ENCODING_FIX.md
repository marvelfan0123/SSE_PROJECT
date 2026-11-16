# Docker lab Windows encoding fix

- Configured the Docker subprocess to decode output as UTF-8 with replacement for invalid bytes, avoiding Windows cp1252 `UnicodeDecodeError` crashes.
- Made the container JSON-lines parser safely return an empty inventory when output is absent, preventing a follow-on `NoneType.splitlines` exception.
- Added regression tests for absent output and explicit subprocess decoding settings.

The Docker integration remains read-only: it only inspects containers and probes the configured loopback lab URLs.
