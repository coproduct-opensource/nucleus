//! A pod's upstream credential, minted per exchange and never stored at rest.
//!
//! # What this replaces
//!
//! Until this module, the credential the host attached to a pod's upstream call
//! was a static value an operator put in the node's environment
//! (`broker_launch::store_from_node_environment`). That is a long-lived secret
//! at rest on every node that serves the upstream. For a registry entry whose
//! credential is `federated` (ADR 0010), the node instead:
//!
//! 1. signs a short ES256 assertion naming the calling pod — `sub` is the pod's
//!    SPIFFE ID as the HOST observed it, `aud` is the operator's registered
//!    audience, `nucleus_upstream` / `nucleus_tenant` / `nucleus_root` /
//!    `nucleus_chain` say which upstream and on whose authority;
//! 2. presents it once at the upstream's token endpoint (RFC 8693 or 7523);
//! 3. holds the short-lived token it gets back in the pod's own
//!    `CredentialStore`, with an expiry the store enforces;
//! 4. and the ordinary fetch (`cdp_fetch`) then serves it like any credential.
//!
//! What exists at rest is one P-256 signing key per node
//! (`keys::load_or_create_jwt_svid_signing_key`), whose power is bounded by the
//! upstreams' own rules on `iss` and `aud` — not one secret per upstream.
//!
//! # The mint decision is the gate, and it is placed by a type
//!
//! Every pod on a node shares its issuer, so a provider rule of "`iss` = this
//! node" matches every pod (THREAT_MODEL T05's shape). The answer is that the
//! provider's rule is not the gate: [`PodCredentials::refill`] mints only
//!
//! * for a request the PDP approved — it takes `&broker::Approved`, which only
//!   `pdp_decide` can construct, so a refill placed before the decision has no
//!   value to pass and does not compile;
//! * for that request's own target, which `handle_perform` has already resolved
//!   against the upstreams the pod was ADMITTED;
//! * in the name of the pod whose broker this is — the approval's host-observed
//!   identity must equal the subject the store was built for, so one pod's
//!   approval cannot mint in another pod's name.
//!
//! # Freshness
//!
//! * **A fresh assertion per exchange.** Every exchange mints a new one with a
//!   new `jti`; an assertion is never retried or replayed, so a provider's
//!   single-use `jti` store never sees a value twice from this node.
//! * **The token is cached per (pod, upstream)**, because each pod has its own
//!   store, until `min(now + expires_in, pod certificate not_after) − 60 s`
//!   ([`cache_expiry`]). The certificate bound matters: a token must not outlive
//!   the authority it was minted under.
//! * **No `expires_in` (or zero) means use once.** The token is placed in the
//!   store for the one fetch that follows and removed before anyone else can
//!   see it. A lifetime nobody stated is not a lifetime to assume.
//! * **Single-flight per key.** Sixteen concurrent calls for one upstream wait
//!   on one exchange and then share its token, rather than making sixteen.
//! * **An upstream 401 evicts** the cached token. The call is not retried: it
//!   is a POST with side effects (`handle_perform` owns that part).
//!
//! # Locks, and why none is held across an `.await`
//!
//! The store sits behind a `std::sync::RwLock`, read synchronously by
//! `cdp_fetch` and written here after an exchange. Its guards are taken only in
//! synchronous scopes (`PodCredentials::read`, a single insert or remove), never
//! across the exchange's `.await`. That is not only discipline: std's guards
//! are `!Send`, the broker serves each connection on a spawned task, and a
//! guard held across an await would make that future `!Send` and the node would
//! not compile (`a_perform_is_send` pins it). Single-flight uses a separate
//! `tokio::sync::Mutex` per upstream, which IS held across the exchange — that
//! is what makes it single-flight — and guards no credential material itself.
//!
//! # What is recorded
//!
//! One structured event per refill ([`ExchangeRecord`]): the issuer, the
//! registry name of the upstream, the assertion's `jti`, `expires_in`, and
//! whether the cache answered. The record type has no field that could hold
//! the token or the assertion, so no log line built from it can.

// The broker's serving path is reached from `start_broker_for_pod`, which is
// linux-only; see `broker_transport.rs` for the same allowance and why.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use nucleus_cred_broker::{Credential, CredentialStore};
use nucleus_federation::{
    AssertionClaims, AssertionSigner, AssertionSubject, ExchangeError, ExchangedToken, TokenRequest,
};

use crate::broker::Approved;
use crate::upstreams::FederatedUpstream;

/// How long before its stated end a cached token stops being served.
///
/// The token crosses a network to the upstream after it leaves the store, and
/// the upstream's clock is not ours; a token served in its last second arrives
/// expired. Sixty seconds is the margin ADR 0010 states.
pub const CACHE_MARGIN_SECS: u64 = 60;

/// The instant a freshly exchanged token stops being served from the cache, or
/// `None` if it must not be cached at all.
///
/// `min(now + expires_in, cert_not_after) − CACHE_MARGIN_SECS`, provided that
/// is still in the future. `None` when the endpoint stated no lifetime (or
/// zero), or when the margin leaves nothing.
///
/// # The property, stated where it can be checked
///
/// If `Some(e)`, then for every `t` the store serves the token at (`t < e`):
/// `t + margin < now + expires_in` — the token has at least the margin left —
/// and `t < cert_not_after` — the pod's authority has not ended. The proptest
/// `a_cached_token_is_served_only_inside_both_bounds` checks exactly that.
#[must_use]
pub fn cache_expiry(now: u64, expires_in: Option<u64>, cert_not_after: u64) -> Option<u64> {
    let lifetime = expires_in.filter(|secs| *secs > 0)?;
    let end = now.saturating_add(lifetime).min(cert_not_after);
    let expires_at = end.checked_sub(CACHE_MARGIN_SECS)?;
    (expires_at > now).then_some(expires_at)
}

/// The node's federation issuer: who signs, under which `iss`, over which
/// client. One per node, shared by every pod's [`PodCredentials`]; it holds no
/// token and no per-pod state, so sharing it shares nothing between pods.
pub struct FederatedSource {
    signer: Arc<dyn AssertionSigner>,
    issuer: String,
    http: reqwest::Client,
}

impl fmt::Debug for FederatedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederatedSource")
            .field("issuer", &self.issuer)
            .field("kid", &self.signer.kid())
            .finish_non_exhaustive()
    }
}

impl FederatedSource {
    /// An issuer at `issuer`, signing with `signer`, exchanging over `http`.
    ///
    /// `http` must not follow redirects — build it with
    /// `nucleus_federation::default_client`. A token endpoint that redirected
    /// would receive the assertion and pass it on.
    ///
    /// # Errors
    /// `issuer` is not an `https://` URL with a host. Checked here, at start-up,
    /// rather than on the first mint: `AssertionClaims::new` would refuse it
    /// too, but as every pod's first call failing rather than as a node that
    /// will not start.
    pub fn new(
        signer: Arc<dyn AssertionSigner>,
        issuer: impl Into<String>,
        http: reqwest::Client,
    ) -> Result<Self, String> {
        let issuer = issuer.into();
        let ok = reqwest::Url::parse(&issuer)
            .is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty()));
        if !ok {
            return Err(format!(
                "--federation-issuer must be an https URL with a host, got {issuer:?}"
            ));
        }
        Ok(Self {
            signer,
            issuer,
            http,
        })
    }

    /// The `iss` every assertion carries.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// The pod an assertion is minted for, as the host observed it, and when the
/// pod's authority ends.
#[derive(Debug, Clone)]
pub struct FederationSubject {
    assertion: AssertionSubject,
    cert_not_after_unix: u64,
}

impl FederationSubject {
    /// Built by `PodAuthority::federation_subject` from the certificate it
    /// issued; nothing a guest sends reaches either argument.
    pub fn new(assertion: AssertionSubject, cert_not_after_unix: u64) -> Self {
        Self {
            assertion,
            cert_not_after_unix,
        }
    }

    /// The pod's SPIFFE ID — the assertion's `sub`.
    pub fn pod_spiffe_id(&self) -> &str {
        self.assertion.pod_spiffe_id()
    }
}

/// Whether the cache answered a refill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOutcome {
    /// A token minted earlier was still inside its bounds.
    Hit,
    /// An assertion was minted and exchanged just now.
    Miss,
}

/// What one refill is recorded as. No field can hold a token or an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRecord {
    /// The registry name of the upstream (`nucleus_upstream`).
    pub upstream: String,
    /// The `iss` the assertion carried.
    pub issuer: String,
    /// Hit or miss.
    pub cache: CacheOutcome,
    /// The minted assertion's `jti`, on a miss — enough to find the exchange in
    /// the provider's own log without keeping the assertion.
    pub jti: Option<String>,
    /// What the token endpoint stated, on a miss. `None` there means the token
    /// was used once and not cached.
    pub expires_in: Option<u64>,
}

impl ExchangeRecord {
    fn of(
        upstream: &FederatedUpstream,
        fed: &PodFederation,
        cache: CacheOutcome,
        jti: Option<String>,
        expires_in: Option<u64>,
    ) -> Self {
        Self {
            upstream: upstream.name.clone(),
            issuer: fed.source.issuer.clone(),
            cache,
            jti,
            expires_in,
        }
    }

    fn log(&self, pod: &str) {
        tracing::info!(
            target: "nucleus_node::federation",
            pod,
            upstream = %self.upstream,
            issuer = %self.issuer,
            cache = ?self.cache,
            jti = self.jti.as_deref().unwrap_or("-"),
            expires_in = ?self.expires_in,
            "federated credential"
        );
    }
}

/// Why a refill produced no credential. For the HOST's log; a guest sees only
/// `handle_perform`'s coarse refusal, whichever of these it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefillError {
    /// This pod's store was built without a federation issuer or subject.
    NoIssuer,
    /// The approval names a different pod than this store serves.
    NotThisPod,
    /// The approval is for a different target than the upstream asked about.
    NotThisUpstream,
    /// The pod's certificate has expired; nothing is minted under it.
    AuthorityExpired,
    /// The claims could not be built (a subject, audience or lifetime problem).
    Claims,
    /// The signer failed.
    Sign,
    /// The exchange failed. The error carries a status at most, never a body.
    Exchange {
        /// The `jti` of the assertion that was spent, so the attempt can be
        /// found in the provider's log.
        jti: String,
        /// What went wrong, coarsely.
        error: ExchangeError,
    },
    /// A lock was poisoned by an earlier panic; refused rather than trusted.
    Poisoned,
}

/// One pod's federation: the node's issuer and this pod's subject.
struct PodFederation {
    source: Arc<FederatedSource>,
    subject: FederationSubject,
}

impl PodFederation {
    /// Mint a fresh assertion and exchange it. No cache, no lock: the caller
    /// holds the flight.
    async fn exchange(
        &self,
        up: &FederatedUpstream,
        now: u64,
    ) -> Result<(ExchangedToken, String), RefillError> {
        let not_after = self.subject.cert_not_after_unix;
        let remaining = not_after
            .checked_sub(now)
            .filter(|s| *s > 0)
            .ok_or(RefillError::AuthorityExpired)?;
        // The assertion does not outlive the authority it speaks for either.
        let ttl = up.assertion_ttl.min(Duration::from_secs(remaining));
        let claims = AssertionClaims::new(
            &self.subject.assertion,
            &self.source.issuer,
            &up.audience,
            &up.name,
            now,
            ttl,
        )
        .map_err(|_| RefillError::Claims)?;
        let jti = claims.jti().to_string();
        let assertion = nucleus_federation::mint(&claims, self.source.signer.as_ref())
            .map_err(|_| RefillError::Sign)?;
        let spent = |error| RefillError::Exchange {
            jti: jti.clone(),
            error,
        };
        let mut req =
            TokenRequest::new(up.token_endpoint.clone(), up.grant, up.encoding, assertion)
                .map_err(spent)?;
        if let Some(a) = &up.request_audience {
            req = req.with_audience(a);
        }
        if let Some(s) = &up.scope {
            req = req.with_scope(s);
        }
        let req = req.with_params(up.params.clone()).map_err(spent)?;
        let token = nucleus_federation::exchange(&self.source.http, &req)
            .await
            .map_err(spent)?;
        Ok((token, jti))
    }
}

/// One pod's credentials: its store, and — if any of its upstreams is
/// federated — what it needs to mint for them.
///
/// Built once per pod, when its broker starts, and never shared: that is what
/// makes the cache per (pod, upstream) rather than per upstream.
pub struct PodCredentials {
    store: RwLock<CredentialStore>,
    federation: Option<PodFederation>,
    /// One async lock per upstream name, created on first use. Bounded by the
    /// number of upstreams this pod was admitted: `handle_perform` refills only
    /// for a target it resolved against that list.
    flights: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl fmt::Debug for PodCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PodCredentials")
            .field("federated", &self.federation.is_some())
            .finish_non_exhaustive()
    }
}

impl PodCredentials {
    /// A pod's credentials: `store` holds its static ones, and `federation`, if
    /// given, lets it mint for federated upstreams.
    pub fn new(
        store: CredentialStore,
        federation: Option<(Arc<FederatedSource>, FederationSubject)>,
    ) -> Self {
        Self {
            store: RwLock::new(store),
            federation: federation.map(|(source, subject)| PodFederation { source, subject }),
            flights: Mutex::new(HashMap::new()),
        }
    }

    /// Static credentials only; every federated refill refuses. The launch
    /// path always goes through [`Self::new`]; tests that are not about
    /// federation build this.
    #[cfg(test)]
    pub fn static_only(store: CredentialStore) -> Self {
        Self::new(store, None)
    }

    /// Run `f` against the store under its read lock.
    ///
    /// A plain `FnOnce`, not a future: whatever `f` does, it cannot await with
    /// the lock held. `None` if the lock is poisoned — refused, not trusted.
    pub fn read<R>(&self, f: impl FnOnce(&CredentialStore) -> R) -> Option<R> {
        self.store.read().ok().map(|store| f(&store))
    }

    /// Forget a cached credential, for a token the upstream just refused.
    pub fn evict(&self, target: &str) {
        if let Ok(mut store) = self.store.write() {
            store.remove(target);
        }
    }

    /// The single-flight lock for one upstream.
    fn flight(&self, name: &str) -> Result<Arc<tokio::sync::Mutex<()>>, RefillError> {
        let mut flights = self.flights.lock().map_err(|_| RefillError::Poisoned)?;
        Ok(Arc::clone(flights.entry(name.to_string()).or_default()))
    }

    /// Make sure the store holds a usable credential for `upstream`, minting and
    /// exchanging a fresh assertion if it does not.
    ///
    /// Returns a [`Refilled`] that holds this upstream's flight. The caller
    /// fetches (`cdp_fetch`) while holding it and drops it BEFORE making the
    /// upstream call: holding it through the fetch is what keeps a use-once
    /// token from being seen by a second caller; dropping it before the call is
    /// what keeps one slow upstream call from serialising the pod.
    ///
    /// # Errors
    /// See [`RefillError`]. Nothing is cached on an error, and nothing is
    /// retried: the next call mints a new assertion.
    pub async fn refill(
        &self,
        approved: &Approved,
        upstream: &FederatedUpstream,
        now: u64,
    ) -> Result<Refilled<'_>, RefillError> {
        let fed = self.federation.as_ref().ok_or(RefillError::NoIssuer)?;
        let request = approved.request();
        // Never across pods: the approval was made for the identity bound to
        // this pod's listener, and the assertion is minted in this pod's name.
        // If those ever disagreed, minting would put one pod's request under
        // another pod's `sub`.
        if request.pod_identity.as_str() != fed.subject.pod_spiffe_id() {
            return Err(RefillError::NotThisPod);
        }
        if request.target != upstream.name {
            return Err(RefillError::NotThisUpstream);
        }

        let flight = self.flight(&upstream.name)?.lock_owned().await;

        // Under the flight, the cache check is the CDP's own lookup: a token is
        // "cached" exactly when `for_request` would serve it now. Written out
        // rather than through `Self::read`, whose call of its closure argument
        // the cb4a pass cannot resolve — and every call on this path should be
        // one it can follow.
        let cached = {
            let store = self.store.read().map_err(|_| RefillError::Poisoned)?;
            store.for_request(request, now).is_ok()
        };
        if cached {
            let record = ExchangeRecord::of(upstream, fed, CacheOutcome::Hit, None, None);
            record.log(fed.subject.pod_spiffe_id());
            return Ok(Refilled {
                pod: self,
                target: upstream.name.clone(),
                single_use: false,
                record,
                _flight: flight,
            });
        }

        let (token, jti) = match fed.exchange(upstream, now).await {
            Ok(done) => done,
            Err(e) => {
                tracing::warn!(
                    target: "nucleus_node::federation",
                    pod = fed.subject.pod_spiffe_id(),
                    upstream = %upstream.name,
                    issuer = %fed.source.issuer,
                    error = ?e,
                    "federated credential exchange failed; the call is refused"
                );
                return Err(e);
            }
        };
        let expires_in = token.expires_in();
        let (until, single_use) =
            match cache_expiry(now, expires_in, fed.subject.cert_not_after_unix) {
                Some(until) => (until, false),
                // Good for the fetch at `now` only, and removed when the
                // `Refilled` drops — before this flight lets anyone else in.
                None => (now.saturating_add(1), true),
            };
        self.store
            .write()
            .map_err(|_| RefillError::Poisoned)?
            .insert_expiring(&upstream.name, Credential::new(token.expose()), until);
        drop(token);

        let record = ExchangeRecord::of(upstream, fed, CacheOutcome::Miss, Some(jti), expires_in);
        record.log(fed.subject.pod_spiffe_id());
        Ok(Refilled {
            pod: self,
            target: upstream.name.clone(),
            single_use,
            record,
            _flight: flight,
        })
    }
}

/// Proof that a refill ran, holding its upstream's flight until dropped.
///
/// Dropping a use-once token's `Refilled` removes the token from the store, so
/// it cannot serve a second fetch.
#[must_use = "fetch while this is held, then drop it before the upstream call"]
pub struct Refilled<'a> {
    pod: &'a PodCredentials,
    target: String,
    single_use: bool,
    record: ExchangeRecord,
    _flight: tokio::sync::OwnedMutexGuard<()>,
}

impl Refilled<'_> {
    /// What this refill is recorded as.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn record(&self) -> &ExchangeRecord {
        &self.record
    }
}

impl Drop for Refilled<'_> {
    fn drop(&mut self) {
        if self.single_use {
            self.pod.evict(&self.target);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// **The cache bound.** Whatever the endpoint stated and whenever the
        /// pod's certificate ends, a token the store would serve at `t` has at
        /// least the margin left and was minted under authority still in force.
        ///
        /// A proptest rather than a Kani harness: `nucleus-node` has no Kani
        /// setup and links C (ring, aws-lc) Kani cannot model, and the function
        /// is four lines of saturating integer arithmetic over three inputs,
        /// where random search with edge-biased u64s covers the boundaries
        /// (overflow at `u64::MAX`, the margin exactly consumed) the proof
        /// would have to.
        #[test]
        fn a_cached_token_is_served_only_inside_both_bounds(
            now in prop_oneof![Just(0u64), any::<u64>(), Just(u64::MAX - 1)],
            expires_in in prop_oneof![Just(None), Just(Some(0u64)), any::<Option<u64>>(), (0u64..200).prop_map(Some)],
            cert_not_after in prop_oneof![any::<u64>(), Just(u64::MAX)],
            later in 0u64..10_000,
        ) {
            if let Some(until) = cache_expiry(now, expires_in, cert_not_after) {
                prop_assert!(until > now, "a cache entry must be usable at all");
                let token_end = now.saturating_add(expires_in.unwrap_or(0));
                // The store serves at `t` exactly when `t < until`. Checked at
                // an arbitrary later instant and at the last served second.
                for t in [now.saturating_add(later), until - 1] {
                    if t < until {
                        prop_assert!(t + CACHE_MARGIN_SECS < token_end);
                        prop_assert!(t < cert_not_after);
                    }
                }
            } else {
                // Not cached: no lifetime, zero, or nothing left after the margin.
                let end = expires_in
                    .filter(|s| *s > 0)
                    .map(|s| now.saturating_add(s).min(cert_not_after));
                prop_assert!(end.is_none_or(|e| e <= now.saturating_add(CACHE_MARGIN_SECS)));
            }
        }
    }

    #[test]
    fn cache_expiry_examples() {
        let now = 1_000_000;
        assert_eq!(
            cache_expiry(now, None, u64::MAX),
            None,
            "unstated: use once"
        );
        assert_eq!(cache_expiry(now, Some(0), u64::MAX), None, "zero: use once");
        assert_eq!(cache_expiry(now, Some(3600), u64::MAX), Some(now + 3540));
        assert_eq!(
            cache_expiry(now, Some(3600), now + 600),
            Some(now + 540),
            "the certificate ends first"
        );
        assert_eq!(
            cache_expiry(now, Some(60), u64::MAX),
            None,
            "nothing left after the margin"
        );
        assert_eq!(cache_expiry(now, Some(61), u64::MAX), Some(now + 1));
    }
}

/// The federated path end to end: a real token endpoint and a real upstream
/// (wiremock), a real signer, the registry parsed from TOML, and the broker's
/// own `handle_perform` — or its serving path, where the wire is the point.
#[cfg(test)]
mod through_the_broker {
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::Engine as _;
    use nucleus_cred_broker::PodIdentity;
    use nucleus_cred_protocol::{PerformReply, PerformRequest};
    use nucleus_federation::EcdsaP256Signer;
    use portcullis::{CapabilityLevel, PermissionLattice};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use crate::broker_perform::{IdempotencyLedger, PerformContext, handle_perform};
    use crate::broker_transport::{
        BrokerServing, UpstreamCaller, http_caller, serve_connection_with_timeout,
    };
    use crate::upstreams::{CredentialSource, RegistryEntry, UpstreamRegistry};

    const NOW: u64 = 1_700_000_000;
    const DAY: u64 = 86_400;
    const ISSUER: &str = "https://federation.example.invalid";
    const POD_A: &str = "spiffe://nodes.example.invalid/ns/pods/sa/pod-a";
    const POD_B: &str = "spiffe://nodes.example.invalid/ns/pods/sa/pod-b";
    const TENANT: &str = "tenant-a.example.invalid";
    const ROOT: &str = "spiffe://tenant-a.example.invalid/ns/ci/sa/release";
    const AUDIENCE: &str = "https://auth.model-api.example.invalid";
    const CAPABILITY: &[u8] = b"federation-test-capability";

    fn fingerprint() -> String {
        "ab".repeat(32)
    }

    fn source() -> Arc<FederatedSource> {
        // Workspace reqwest carries no provider; tests install ring's first.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let der = EcdsaP256Signer::generate_pkcs8().expect("keygen");
        let signer = EcdsaP256Signer::from_pkcs8(&der).expect("loads");
        Arc::new(
            FederatedSource::new(
                Arc::new(signer),
                ISSUER,
                nucleus_federation::default_client().expect("client"),
            )
            .expect("an https issuer"),
        )
    }

    fn subject(pod: &str, not_after: u64) -> FederationSubject {
        FederationSubject::new(
            AssertionSubject::new(pod, TENANT, ROOT, fingerprint()).expect("valid subject"),
            not_after,
        )
    }

    /// A status script: each request pops the next status, 200 once it is empty.
    type Script = Arc<Mutex<VecDeque<u16>>>;

    fn script(statuses: &[u16]) -> Script {
        Arc::new(Mutex::new(statuses.iter().copied().collect()))
    }

    fn next(script: &Script) -> u16 {
        script.lock().unwrap().pop_front().unwrap_or(200)
    }

    /// A token endpoint that numbers the tokens it mints and counts exchanges.
    struct TokenEndpoint {
        server: MockServer,
        minted: Arc<AtomicUsize>,
    }

    impl TokenEndpoint {
        async fn start(expires_in: Option<u64>, delay: Duration, statuses: &[u16]) -> Self {
            let server = MockServer::start().await;
            let minted = Arc::new(AtomicUsize::new(0));
            let (counter, script) = (Arc::clone(&minted), script(statuses));
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(move |_: &Request| {
                    let status = next(&script);
                    if status != 200 {
                        // A refusal body that names things the guest must never
                        // learn: which check failed and what scope exists.
                        return ResponseTemplate::new(status).set_body_json(serde_json::json!({
                            "error": "invalid_grant",
                            "error_description": "scope example-secret-scope is not granted",
                        }));
                    }
                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    let mut body = serde_json::json!({
                        "access_token": format!("minted-token-{n}"),
                        "token_type": "Bearer",
                    });
                    if let Some(secs) = expires_in {
                        body["expires_in"] = secs.into();
                    }
                    ResponseTemplate::new(200)
                        .set_body_json(body)
                        .set_delay(delay)
                })
                .mount(&server)
                .await;
            Self { server, minted }
        }

        /// Successful exchanges.
        fn minted(&self) -> usize {
            self.minted.load(Ordering::SeqCst)
        }

        /// Every assertion presented, compact form and decoded claims, in
        /// arrival order — including ones the endpoint refused.
        async fn assertions(&self) -> Vec<(String, serde_json::Value)> {
            let requests = self.server.received_requests().await.expect("recording");
            requests
                .iter()
                .map(|r| {
                    let body = String::from_utf8(r.body.clone()).expect("form body");
                    let url = reqwest::Url::parse(&format!("http://form.invalid/?{body}")).unwrap();
                    let compact = url
                        .query_pairs()
                        .find(|(k, _)| k == "subject_token")
                        .expect("an RFC 8693 subject_token")
                        .1
                        .into_owned();
                    let payload = compact.split('.').nth(1).expect("a compact JWS");
                    let claims = serde_json::from_slice(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(payload)
                            .expect("base64url"),
                    )
                    .expect("JSON claims");
                    (compact, claims)
                })
                .collect()
        }
    }

    /// A model-API upstream that records the Authorization header it received.
    struct Upstream {
        server: MockServer,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl Upstream {
        async fn start(statuses: &[u16]) -> Self {
            let server = MockServer::start().await;
            let seen = Arc::new(Mutex::new(Vec::new()));
            let (sink, script) = (Arc::clone(&seen), script(statuses));
            Mock::given(method("POST"))
                .and(path("/v1/messages"))
                .respond_with(move |req: &Request| {
                    let auth = req
                        .headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    sink.lock().unwrap().push(auth);
                    ResponseTemplate::new(next(&script))
                        .set_body_json(serde_json::json!({"ok": true}))
                })
                .mount(&server)
                .await;
            Self { server, seen }
        }

        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    /// The registry the operator would write, pointed at the two mocks.
    fn registry(tokens: &TokenEndpoint, up: &Upstream) -> Vec<RegistryEntry> {
        let toml = format!(
            r#"
[[upstream]]
name = "model-api"
base_url = "{up}/v1"
header = "authorization"
value_prefix = "Bearer "

[upstream.credential.federated]
token_endpoint = "{tok}/oauth/token"
grant = "token-exchange"
encoding = "form"
audience = "{AUDIENCE}"

[upstream.credential.federated.params]
policy_id = "example-policy-0001"
"#,
            up = up.server.uri(),
            tok = tokens.server.uri(),
        );
        let reg = UpstreamRegistry::from_toml_str(&toml).expect("the fixture registry loads");
        reg.resolve(reg.entries())
    }

    fn perform(key: &str) -> PerformRequest {
        PerformRequest {
            operation: "WebFetch".into(),
            target: "model-api".into(),
            justification: "the agent asked".into(),
            idempotency_key: key.into(),
            path: "/messages".into(),
            body: br#"{"prompt":"hi"}"#.to_vec(),
        }
    }

    /// One pod's broker state.
    struct Pod {
        identity: PodIdentity,
        policy: PermissionLattice,
        credentials: PodCredentials,
        upstreams: Vec<RegistryEntry>,
        ledger: IdempotencyLedger,
        caller: UpstreamCaller,
    }

    impl Pod {
        fn new(
            pod: &str,
            source: &Arc<FederatedSource>,
            upstreams: Vec<RegistryEntry>,
            not_after: u64,
        ) -> Self {
            Self {
                identity: PodIdentity::observed_by_host(pod),
                policy: PermissionLattice::permissive(),
                credentials: PodCredentials::new(
                    CredentialStore::new(),
                    Some((Arc::clone(source), subject(pod, not_after))),
                ),
                upstreams,
                ledger: IdempotencyLedger::new(),
                caller: http_caller(reqwest::Client::new()),
            }
        }

        async fn call_as(&self, req: &PerformRequest, now: u64) -> PerformReply {
            let ctx = PerformContext {
                identity: &self.identity,
                policy: &self.policy,
                credentials: &self.credentials,
                upstreams: &self.upstreams,
                ledger: &self.ledger,
            };
            let caller = Arc::clone(&self.caller);
            handle_perform(req, &ctx, now, move |c| caller(c)).await
        }

        async fn call(&self, key: &str, now: u64) -> PerformReply {
            self.call_as(&perform(key), now).await
        }

        fn federated(&self) -> Arc<FederatedUpstream> {
            match self.upstreams[0].credential() {
                CredentialSource::Federated(f) => Arc::clone(f),
                CredentialSource::Env { .. } => panic!("the fixture entry is federated"),
            }
        }

        fn holds(&self, target: &str) -> bool {
            self.credentials
                .read(|s| format!("{s:?}").contains(target))
                .unwrap()
        }
    }

    fn approval(pod: &str, now: u64) -> Approved {
        crate::broker::pdp_decide(
            &nucleus_cred_broker::TaskRequestEnvelope {
                operation: "WebFetch".into(),
                target: "model-api".into(),
                justification: "test".into(),
            },
            &PodIdentity::observed_by_host(pod),
            &PermissionLattice::permissive(),
            now,
        )
        .expect("permissive")
    }

    /// **The headline, over the real serving path.** A signed perform frame for
    /// a federated upstream: the node mints an assertion naming this pod,
    /// exchanges it, calls the upstream with `Bearer <minted>` — and the line
    /// that crosses back to the guest carries neither the token nor the
    /// assertion. The federated counterpart of
    /// `broker_perform::tests::the_reply_never_carries_the_credential`.
    #[tokio::test]
    async fn the_reply_never_carries_the_credential_when_it_was_minted() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[]).await;
        let source = source();
        let real_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let pod = Pod::new(POD_A, &source, registry(&tokens, &up), real_now + DAY);

        let frame = format!(
            "{}\n",
            nucleus_cred_protocol::frame::sign(
                CAPABILITY,
                &serde_json::to_string(&perform("key-1")).unwrap()
            )
        );
        let (client, server) = tokio::io::duplex(512 * 1024);
        let serving = BrokerServing {
            identity: &pod.identity,
            policy: &pod.policy,
            credentials: &pod.credentials,
            broker_secret: Some(CAPABILITY),
            upstreams: &pod.upstreams,
            ledger: &pod.ledger,
            upstream_caller: Arc::clone(&pod.caller),
        };
        let serve = serve_connection_with_timeout(server, &serving, Duration::from_secs(10));
        let talk = async {
            let (r, mut w) = tokio::io::split(client);
            w.write_all(frame.as_bytes()).await.unwrap();
            w.flush().await.unwrap();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            line
        };
        let (_, reply) = tokio::join!(serve, talk);

        assert!(reply.contains("\"granted\":true"), "reply: {reply}");
        assert!(reply.contains("\"status\":200"), "reply: {reply}");
        assert_eq!(tokens.minted(), 1);
        assert_eq!(
            up.seen(),
            vec!["Bearer minted-token-1".to_string()],
            "the upstream must receive value_prefix + the minted token"
        );

        let (assertion, claims) = tokens.assertions().await.remove(0);
        for secret in ["minted-token-1", assertion.as_str()] {
            assert!(
                !reply.contains(secret),
                "{secret:?} reached the guest: {reply}"
            );
        }
        let signature = assertion.rsplit('.').next().unwrap();
        assert!(
            !reply.contains(signature),
            "the assertion's signature reached the guest"
        );

        // The assertion says who asked, on whose authority, for what.
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["sub"], POD_A);
        assert_eq!(claims["aud"], AUDIENCE);
        assert_eq!(claims["nucleus_upstream"], "model-api");
        assert_eq!(claims["nucleus_tenant"], TENANT);
        assert_eq!(claims["nucleus_root"], ROOT);
        assert_eq!(claims["nucleus_chain"], fingerprint());
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            nucleus_federation::DEFAULT_TTL.as_secs()
        );

        // …and it verifies under the issuer's published key, as the provider
        // would check it.
        let jwk = source.signer.public_jwk();
        let key = jsonwebtoken::DecodingKey::from_ec_components(&jwk.x, &jwk.y).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[AUDIENCE]);
        jsonwebtoken::decode::<serde_json::Value>(&assertion, &key, &validation)
            .expect("the assertion verifies under the node's JWKS");

        // And the operator's opaque parameter went along verbatim.
        let body = String::from_utf8(
            tokens.server.received_requests().await.unwrap()[0]
                .body
                .clone(),
        )
        .unwrap();
        assert!(body.contains("policy_id=example-policy-0001"), "{body}");
    }

    /// **The cache.** A token with an hour to live is reused, and replaced once
    /// the margin before its end is reached — not at its end.
    #[tokio::test]
    async fn a_cached_token_is_reused_within_its_lifetime_and_re_exchanged_after() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[]).await;
        let pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + DAY);

        assert!(pod.call("k1", NOW).await.granted);
        assert!(pod.call("k2", NOW + 3000).await.granted);
        assert_eq!(
            tokens.minted(),
            1,
            "a token inside its lifetime was not reused"
        );
        assert!(pod.call("k3", NOW + 3600 - CACHE_MARGIN_SECS).await.granted);
        assert_eq!(tokens.minted(), 2, "a token past its margin was served");
        assert_eq!(
            up.seen(),
            ["minted-token-1", "minted-token-1", "minted-token-2"].map(|t| format!("Bearer {t}"))
        );
    }

    /// The pod's certificate bounds both the cached token and the assertion: a
    /// token is not served after the authority it was minted under ends, and an
    /// assertion does not claim to outlive it.
    #[tokio::test]
    async fn the_pods_certificate_bounds_the_cache_and_the_assertion() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[]).await;
        let pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + 600);

        assert!(pod.call("k1", NOW).await.granted);
        assert!(pod.call("k2", NOW + 539).await.granted);
        assert_eq!(tokens.minted(), 1);
        assert!(pod.call("k3", NOW + 540).await.granted);
        assert_eq!(
            tokens.minted(),
            2,
            "a token was served within the margin of the cert's end"
        );

        let last = &tokens.assertions().await[1].1;
        assert_eq!(
            last["exp"].as_u64().unwrap(),
            NOW + 600,
            "the assertion outlived the pod's authority"
        );

        // At the certificate's end, nothing is minted at all.
        assert!(!pod.call("k4", NOW + 600).await.granted);
        assert_eq!(tokens.assertions().await.len(), 2);
    }

    /// **No stated lifetime, no cache.** Missing or zero `expires_in`: every
    /// call exchanges, and the token is gone from the store once used.
    #[tokio::test]
    async fn a_token_without_a_lifetime_is_used_once() {
        for expires_in in [None, Some(0)] {
            let tokens = TokenEndpoint::start(expires_in, Duration::ZERO, &[]).await;
            let up = Upstream::start(&[]).await;
            let pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + DAY);
            for (i, key) in ["k1", "k2", "k3"].into_iter().enumerate() {
                assert!(pod.call(key, NOW).await.granted);
                assert_eq!(
                    tokens.minted(),
                    i + 1,
                    "{expires_in:?}: a use-once token was reused"
                );
                assert!(
                    !pod.holds("model-api"),
                    "{expires_in:?}: a use-once token stayed in the store"
                );
            }
        }
    }

    /// **Single-flight.** Sixteen concurrent calls for one upstream — the
    /// broker's whole connection budget — make one exchange and all use its
    /// token. Spawned tasks, so this also requires the perform future to be
    /// `Send`: a std lock guard held across the exchange would not compile.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sixteen_concurrent_callers_share_one_exchange() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::from_millis(300), &[]).await;
        let up = Upstream::start(&[]).await;
        let pod = Arc::new(Pod::new(
            POD_A,
            &source(),
            registry(&tokens, &up),
            NOW + DAY,
        ));

        let mut set = tokio::task::JoinSet::new();
        for i in 0..16 {
            let pod = Arc::clone(&pod);
            set.spawn(async move { pod.call(&format!("key-{i}"), NOW).await });
        }
        while let Some(reply) = set.join_next().await {
            assert!(reply.unwrap().granted);
        }
        assert_eq!(tokens.minted(), 1, "concurrent callers each exchanged");
        assert_eq!(tokens.assertions().await.len(), 1);
        let seen = up.seen();
        assert_eq!(seen.len(), 16);
        assert!(
            seen.iter().all(|a| a == "Bearer minted-token-1"),
            "{seen:?}"
        );
    }

    /// **Fresh per exchange.** Every assertion carries a new `jti`, including
    /// the one minted after a failed exchange — a failure re-mints rather than
    /// re-presenting what was already spent.
    #[tokio::test]
    async fn every_exchange_presents_a_fresh_assertion() {
        let tokens = TokenEndpoint::start(None, Duration::ZERO, &[503]).await;
        let up = Upstream::start(&[]).await;
        let pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + DAY);

        assert!(!pod.call("k1", NOW).await.granted, "the 503 is a refusal");
        for key in ["k1", "k2", "k3"] {
            assert!(pod.call(key, NOW).await.granted);
        }
        let presented = tokens.assertions().await;
        assert_eq!(presented.len(), 4, "one refused exchange, three good ones");
        let jtis: HashSet<String> = presented
            .iter()
            .map(|(_, c)| c["jti"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(jtis.len(), 4, "a jti was presented twice");
        let compacts: HashSet<&String> = presented.iter().map(|(a, _)| a).collect();
        assert_eq!(compacts.len(), 4, "an assertion was presented twice");
    }

    /// **The PDP decides before anything is minted.** A refused request costs
    /// no exchange and reaches no upstream.
    #[tokio::test]
    async fn a_pdp_refusal_mints_nothing() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[]).await;
        let mut pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + DAY);
        pod.policy.capabilities.web_fetch = CapabilityLevel::Never;

        let reply = pod.call("k1", NOW).await;
        assert!(!reply.granted);
        assert_eq!(reply.reason, "not permitted");
        assert!(
            tokens.assertions().await.is_empty(),
            "an assertion was minted for a refused call"
        );
        assert!(up.seen().is_empty());
    }

    /// **Only for what the pod was admitted.** A target outside the pod's
    /// upstreams — unregistered, or registered but not admitted to this pod —
    /// is refused before anything is minted.
    #[tokio::test]
    async fn an_unadmitted_target_mints_nothing() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[]).await;
        let source = source();

        let admitted = Pod::new(POD_A, &source, registry(&tokens, &up), NOW + DAY);
        let mut elsewhere = perform("k1");
        elsewhere.target = "unregistered-api".into();
        assert!(!admitted.call_as(&elsewhere, NOW).await.granted);

        let not_admitted = Pod::new(POD_A, &source, Vec::new(), NOW + DAY);
        assert!(!not_admitted.call("k1", NOW).await.granted);

        assert!(tokens.assertions().await.is_empty());
        assert!(up.seen().is_empty());
    }

    /// **The token endpoint is not an oracle.** A 4xx whose body names the
    /// failed check and a scope reaches the guest as the one coarse refusal a
    /// failed call gets, with none of that text — and, since nothing was
    /// called, the key is free to retry.
    #[tokio::test]
    async fn a_token_endpoint_refusal_is_a_coarse_refusal_and_frees_the_key() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[400]).await;
        let up = Upstream::start(&[]).await;
        let pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + DAY);

        let reply = pod.call("k1", NOW).await;
        assert!(!reply.granted);
        assert_eq!(reply.reason, "upstream call failed");
        assert!(reply.body.is_empty());
        let wire = serde_json::to_string(&reply).unwrap();
        for leak in ["invalid_grant", "example-secret-scope", "400", "oauth"] {
            assert!(!wire.contains(leak), "{leak:?} reached the guest: {wire}");
        }
        assert!(
            up.seen().is_empty(),
            "the upstream was called without a credential"
        );

        let retried = pod.call("k1", NOW).await;
        assert!(
            retried.granted,
            "the same key was burned by a mint that never called anything"
        );
        assert_eq!(tokens.minted(), 1);
    }

    /// **An upstream 401 evicts.** The refused token is dropped, the call is
    /// NOT retried, and the next call exchanges afresh.
    #[tokio::test]
    async fn an_upstream_401_evicts_and_the_next_call_re_exchanges() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[401]).await;
        let pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + DAY);

        let refused = pod.call("k1", NOW).await;
        assert!(!refused.granted);
        assert_eq!(refused.reason, "upstream call failed");
        assert_eq!(
            up.seen().len(),
            1,
            "the 401'd call was retried automatically"
        );
        assert!(!pod.holds("model-api"), "the refused token is still cached");

        assert!(pod.call("k2", NOW + 1).await.granted);
        assert_eq!(tokens.minted(), 2);
        assert_eq!(up.seen()[1], "Bearer minted-token-2");
    }

    /// **Never across pods.** Two pods on one issuer each exchange for
    /// themselves, and one pod's approval cannot mint in the other's name.
    #[tokio::test]
    async fn one_pods_approval_cannot_mint_for_another() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[]).await;
        let source = source();
        let a = Pod::new(POD_A, &source, registry(&tokens, &up), NOW + DAY);
        let b = Pod::new(POD_B, &source, registry(&tokens, &up), NOW + DAY);

        let wrong = a
            .credentials
            .refill(&approval(POD_B, NOW), &a.federated(), NOW)
            .await;
        assert_eq!(wrong.err(), Some(RefillError::NotThisPod));
        assert!(tokens.assertions().await.is_empty());

        assert!(a.call("k1", NOW).await.granted);
        assert!(b.call("k1", NOW).await.granted);
        assert_eq!(tokens.minted(), 2, "pod B was served pod A's cached token");
        let subs: Vec<String> = tokens
            .assertions()
            .await
            .iter()
            .map(|(_, c)| c["sub"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(subs, [POD_A, POD_B]);
    }

    /// A pod with no issuer — the node has none, or issued this pod no
    /// certificate — refuses its federated upstream rather than calling it
    /// bare.
    #[tokio::test]
    async fn a_pod_without_an_issuer_refuses_rather_than_calling_bare() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[]).await;
        let mut pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + DAY);
        pod.credentials = PodCredentials::static_only(CredentialStore::new());

        let reply = pod.call("k1", NOW).await;
        assert!(!reply.granted);
        assert_eq!(reply.reason, "upstream call failed");
        assert!(tokens.assertions().await.is_empty());
        assert!(up.seen().is_empty());
    }

    /// **What is recorded.** Issuer, upstream name, `jti`, `expires_in`, hit or
    /// miss — and, whatever `Debug` prints, never the token.
    #[tokio::test]
    async fn the_record_names_the_exchange_and_never_the_token() {
        let tokens = TokenEndpoint::start(Some(3600), Duration::ZERO, &[]).await;
        let up = Upstream::start(&[]).await;
        let pod = Pod::new(POD_A, &source(), registry(&tokens, &up), NOW + DAY);
        let fed = pod.federated();

        let miss = pod
            .credentials
            .refill(&approval(POD_A, NOW), &fed, NOW)
            .await
            .expect("mints");
        let record = miss.record().clone();
        drop(miss);
        let jti = tokens.assertions().await[0].1["jti"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            record,
            ExchangeRecord {
                upstream: "model-api".into(),
                issuer: ISSUER.into(),
                cache: CacheOutcome::Miss,
                jti: Some(jti),
                expires_in: Some(3600),
            }
        );

        let hit = pod
            .credentials
            .refill(&approval(POD_A, NOW + 1), &fed, NOW + 1)
            .await
            .expect("cached");
        assert_eq!(hit.record().cache, CacheOutcome::Hit);
        assert_eq!(hit.record().jti, None);
        for shown in [
            format!("{:?}", hit.record()),
            format!("{record:?}"),
            format!("{:?}", pod.credentials),
        ] {
            assert!(
                !shown.contains("minted-token"),
                "a record printed the token: {shown}"
            );
        }
    }
}
