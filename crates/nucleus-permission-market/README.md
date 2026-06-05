# nucleus-permission-market

Lagrangian permission pricing oracle for multi-dimensional capability
constraints.

[![docs.rs](https://img.shields.io/docsrs/nucleus-permission-market)](https://docs.rs/nucleus-permission-market)

In constrained optimization, a Lagrange multiplier `λ` turns a hard constraint
into a continuous penalty — and by duality, `λ` **is** the market price of
relaxing that constraint by one unit. This crate generalizes a 1-D budget
constraint to N independent permission dimensions:

```text
L' = L + Σᵢ λᵢ · gᵢ(utilization)
```

Each dimension has its own utilization and `λ`. When utilization is low, `λ ≈ 0`
and permissions are effectively free; as utilization approaches the limit, `λ`
grows exponentially, pricing out low-value operations first.

## Dimensions

| `PermissionDimension` | Covers |
|---|---|
| `Filesystem` | file read/write/glob/grep |
| `CommandExec` | shell / process spawning |
| `NetworkEgress` | outbound requests (web_fetch, web_search) |
| `Approval` | the meta-permission to approve other operations |

## Usage

```rust
use nucleus_permission_market::{PermissionMarket, PermissionBid, PermissionDimension, TrustTier};
use std::collections::BTreeMap;

// Current utilization per dimension.
let mut utilizations = BTreeMap::new();
utilizations.insert(PermissionDimension::Filesystem, 0.3);   // low pressure
utilizations.insert(PermissionDimension::CommandExec, 0.85); // high pressure
let market = PermissionMarket::with_utilization(utilizations);

// A skill bids for capabilities with a value estimate and a trust tier.
let bid = PermissionBid {
    skill_id: "my-plugin".into(),
    requested: vec![PermissionDimension::Filesystem, PermissionDimension::CommandExec],
    value_estimate: 2.0,
    trust_tier: TrustTier::Verified,
};

let grant = market.evaluate_bid(&bid);
assert!(grant.granted.contains(&PermissionDimension::Filesystem)); // cheap → granted
// CommandExec may be denied if value < λ_exec adjusted by the trust-tier discount.
```

## Where it sits

```text
Plugin → X-Nucleus-Permission-Bid header → PermissionMarket.evaluate_bid()
         → grant/deny with λ pricing      → tool-proxy endpoint (enforcement)
```

The **mechanism** (λ computation, bid evaluation) is vendor-agnostic. The
**calibration** (cost models, trust assignment, utilization tracking) is the
orchestrator's responsibility — this crate prices; it does not enforce.

## License

MIT
