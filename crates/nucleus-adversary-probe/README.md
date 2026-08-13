# nucleus-adversary-probe

An **active attacker** run as a pod's workload — the offensive twin of
`nucleus-workload-probe`. From inside the guest it campaigns against the sandbox
(steal a mediator secret from PID 1, tamper the read-only rootfs, exfiltrate over
the network) and reports whether the pod **contained** every attempt:
`NUCLEUS_ADVERSARY: CONTAINED | BREACH:<stage> | INCONCLUSIVE`.

Zero-dependency static musl binary; booleans only (never a stolen value). Its
verdict logic is gated on every PR (no boot needed) by
`scripts/check-adversary-probe.sh`, which reconstructs each attack surface
hermetically and asserts the three verdict states plus a meta-anti-leak check.
