# nucleus-permission-market

Lagrangian permission pricing for multi-dimensional capability constraints.

## What it does

In constrained optimization, a Lagrange multiplier `λ` converts a hard
constraint into a continuous penalty; by duality, `λ` **is** the market price
of relaxing that constraint by one unit. This crate keeps one `λ` per
permission dimension. When a dimension's utilization is low, `λ ≈ 0` and the
permission is effectively free; as utilization approaches its limit, `λ` grows
exponentially and prices out low-value operations first.

Prices are **micro-USD** and utilization is **basis points**. `λ` is computed
by a fixed-point exponential — no float anywhere in the shipped build — and
pinned to the `f64` curve it replaced within one micro-unit at every basis
point. Monotonicity and overflow-freedom are checked over the curve's WHOLE
domain — `bps` is bounded by 10 000, so the test walks all 10 001 inputs under
debug overflow checks.

## Dimensions

| `PermissionDimension` | Covers |
|---|---|
| `Filesystem` | file read/write/glob/grep |
| `CommandExec` | shell / process spawning |
| `NetworkEgress` | outbound requests (web_fetch, web_search) |
| `Approval` | the meta-permission to approve other operations |

## A bid comes from a certificate, not a request

`PermissionBid` has private fields, no `Deserialize`, and one public
constructor: `PermissionBid::from_verified(&portcullis::VerifiedPermissions)`.
That argument is sealed — it cannot exist unless a delegation certificate
chain was walked — so a bid in hand is evidence that someone verified a
certificate, and the value it carries is the ceiling the *principal*
delegated. The trust tier is a function of chain depth, assigned by
verification. There is no header, and nothing a request can say changes its
price.

```rust
use nucleus_permission_market::{PermissionBid, PermissionDimension, PermissionMarket};
use std::collections::BTreeMap;

// Current utilization per dimension, basis points.
let mut utilizations = BTreeMap::new();
utilizations.insert(PermissionDimension::Filesystem, 3_000);  // low pressure
utilizations.insert(PermissionDimension::CommandExec, 8_500); // high pressure
let market = PermissionMarket::with_utilization(utilizations);

// `verified` is a portcullis::VerifiedPermissions from verify_certificate(..).
let bid = PermissionBid::from_verified(&verified);
let grant = market.evaluate_bid(&bid);
assert!(grant.granted.contains(&PermissionDimension::Filesystem)); // cheap → granted
// CommandExec is denied if the certificate's budget < λ_exec × the tier's discount.
// grant.total_cost_micro and each DeniedDimension::price_micro are micro-USD.
```

## Where it sits

```text
request ─► delegation certificate ─► verify_certificate ─► VerifiedPermissions
                                                                   │
                                                       PermissionBid::from_verified
                                                                   │
                                                 PermissionMarket::evaluate_bid ─► grant / 402
```

The **mechanism** (λ computation, bid evaluation) is vendor-agnostic. The
**calibration** (utilization tracking, what a dollar of budget buys) is the
orchestrator's responsibility — this crate prices; it does not decide whether
an agent may act. `cargo xtask econ-boundary` refuses it a way into that
decision (`docs/econ-layer-boundary.md`).

## Features

- `certificate` (default): `PermissionBid::from_verified`, via `portcullis`
  with default features off. Disable for targets that cannot build it; the
  market and dimensions remain, and no bid can be constructed.

## License

MIT
