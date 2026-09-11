# Nucleus Documentation

**Nucleus expands the frontier of safely delegatable machine agency: any agent should
be able to do as much useful real-world work as its principal is willing to authorize,
while being structurally incapable of exceeding that authorization.**

The invariant everything here exists to hold:

```
    exercised authority  ≼  delegated authority
```

Nucleus is a vendor-agnostic runtime that enforces that bound — capability lattice,
compiled least-privilege grants, microVM isolation, information-flow control — proves
the enforcement boundary sound, and attests what was exercised in receipts a third
party can check offline.

Start with the [North Star](north-star.md) for the objective and the flagship claims,
[ADR 0005](adr/0005-delegatable-agency.md) for why the objective is stated as a ratio,
and [ADR 0004](adr/0004-delegation-compiler.md) for how a stated goal becomes a
minimum-authority grant. Use the sections below to explore the architecture, threat
model, and integration notes.
