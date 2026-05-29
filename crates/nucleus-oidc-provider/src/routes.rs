//! HTTP handlers. Per-endpoint logic lives in sibling modules
//! (`discovery`, `jwks`, `token`); the previous stub `healthz`
//! handler moved into `app::healthz` (task #43) so it has direct
//! access to `AppState` for operator-meaningful state reporting.
