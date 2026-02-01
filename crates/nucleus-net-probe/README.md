# nucleus-net-probe

Tiny TCP probe binary used for integration tests of network policy. It attempts
to connect to a target `HOST:PORT` with a short timeout and exits non-zero on
failure.
