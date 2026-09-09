# State of the Art (2024–2026): Delegatable, Attenuable Authorization Carriers and Policy Engines for AI Agents

Research date: 2026-09-08. Method: 17 web searches plus fetches of primary specs where the egress proxy allowed (GitHub-hosted specs fetched in full; ietf.org, openid.net, arxiv.org, biscuitsec.org, rfc-editor.org were blocked, so those items rely on search-result excerpts of the primary documents and are marked "[excerpt]"). Nothing in either local repo was modified.

Framing against the North Star: clause (3) "as much as its principal is willing to authorize" is about the *expressiveness* of the carrier; clause (4) "structurally incapable of exceeding" is about *verification locality, no-bypass, and formal treatment*; clause (2) about *friction* across hosts and vendors. Each system below is scored informally on: what it expresses; how attenuation/delegation works; offline verifiability; revocation; formal treatment; adoption.

---

## 1. Capability-token families (the carrier is the authority)

### 1.1 Macaroons (Google, 2014; Fly.io, L402 in production)
- **Expresses**: bearer credential = root HMAC + ordered list of *caveats* (first-party predicates: resource, action mask, validity window; third-party caveats that must be *discharged* by a separate service). Fly.io's production design forces every token to start with an org caveat, adds resource/feature/mutation/`IfPresent` caveats, and separates "what may be done" (root macaroon) from "who is doing it" (a third-party discharge issued by the auth endpoint), so a stolen root token is useless without the discharge (Fly macaroon-thought.md, fetched).
- **Attenuation**: anyone holding a macaroon appends caveats offline; caveats can never be removed. Symmetric HMAC chaining means *verification requires the root secret*, so verification is centralized to the issuer (Fly keeps keys on isolated TKDB hardware).
- **Offline verifiability**: attenuation is offline; verification is not (needs root key).
- **Revocation**: not intrinsic. Practice: short validity windows, third-party caveats to a freshness/epoch service, splitting credentials [excerpt, Birgisson et al.].
- **Formal**: the original paper gives a security argument; no mechanized proof found.
- **Adoption**: Fly.io API tokens (`fly tokens attenuate`), Lightning L402 (macaroon committed to a payment hash; Lightning Labs pitched L402 "for agents" in March 2026), HashiCorp/Boulder historically.
- **Lesson**: the *what/who split* via discharges is the cleanest known way to separate authority from identity, and it maps directly onto principal→agent chains. Limitation: the issuer must be online for every verification.

### 1.2 Biscuit (Eclipse Biscuit; spec v5, tokens v3–v5)
- **Expresses**: a chain of blocks; each block carries Datalog facts, rules, checks; the authorizer adds its own facts and `allow`/`deny` policies. Checks come in `check if` (any match), `check all`, and `reject if` forms (SPECIFICATIONS.md, fetched).
- **Attenuation/delegation**: each block ends with an ephemeral Ed25519 keypair; the next block is signed by the previous ephemeral key, so any holder can append a block *offline* without contacting the issuer, and the chain is unforgeable. A holder can *seal* a token (sign the last block with its own key) to forbid further attenuation. **Third-party blocks** (v3+): an external authority signs a block via a request/response exchange; the signature covers `data_n + alg_n + pk_n` so it cannot be transplanted. `trusting` annotations scope which blocks' facts a rule/check may see (`authority`, `previous`, or a named public key), which is the cross-domain safety mechanism: an attenuated block cannot pretend to be facts from the root.
- **Offline verifiability**: yes, with only the root public key (plus known third-party keys).
- **Revocation**: every block yields a `revocation_id` (its signature bytes); verifiers keep a deny-list. Expiry is a Datalog check on `time()`.
- **Formal**: Datalog semantics are well understood; no machine-checked proof of the token construction found. Multiple independent implementations (Rust, Haskell, Go, Java, .NET, JS) with a shared conformance sample set.
- **Adoption**: Eclipse Foundation project; Space and Time; the 2026 AIP (Agent Identity Protocol) paper uses Biscuit as its "chained mode" wire format for multi-hop agent delegation [excerpt, arXiv 2603.24775].

### 1.3 UCAN v1.0 (delegation, invocation, promise, revocation subspecs)
- **Expresses** (delegation README fetched): envelope `ucan/dlg@1.0.0` over DAG-CBOR; `iss`/`aud` DIDs; `sub` (resource owner, or `null` for *powerline* delegations that bind late); `cmd` hierarchical command path (`/crud/read` covers subcommands); `pol` predicate policy with jq-style selectors (`==`, `<`, glob, `and/or/not`) that *must constrain the args of the eventual invocation*; `nonce`, `exp`, `nbf`, unsigned `meta`.
- **Delegation**: chain of signed delegations, validated at execution time for principal alignment (`aud` of one is `iss` of the next, ending at `sub`), time bounds, and signatures. **Invocation** is a separate signed object naming the chain as proof, which closes the "bearer" hole: possession of a delegation is not enough, one must sign an invocation.
- **Offline**: fully offline verification given DIDs resolvable to keys (did:key needs nothing).
- **Revocation**: separate `ucan/rvk` object; any issuer in the chain may revoke downstream; propagation is out-of-band (validators must be told). Cacheability is a design goal.
- **Formal**: none machine-checked; the spec has a security-considerations section only.
- **Adoption**: Fission/Storacha (web3.storage) production, Go/Rust/TS libs; niche outside decentralized-web.

### 1.4 ZCAP-LD (W3C CCG, v0.4.0-draft)
- **Expresses**: JSON-LD capability with `invocationTarget`, `controller`, `parentCapability` chain, `allowedAction` and `expires` caveats, Data Integrity proofs (not JOSE). Invocation is a signed request carrying the capability chain.
- **Attenuation**: delegate by signing a child that names the parent; caveats only narrow.
- **Revocation**: implementation-specific revocation lists at the target.
- **Formal**: none. **Adoption**: Digital Bazaar's EDV/wallet stack, some SSI projects; still a community-group draft after years, so treat as a design reference rather than a target.

### 1.5 Object-capability systems: CapTP / OCapN (Spritely, Agoric, Cap'n Proto)
- **Expresses**: unforgeable object references; authority *is* reachability. Across hosts, CapTP proxies references, supports promise pipelining, distributed acyclic GC, "sturdyrefs" for offline re-connection, and third-party handoffs (ocapn/ocapn, fetched). Netlayers abstract transports (Tor onion, libp2p, etc.).
- **Attenuation**: build a facet/forwarder object that exposes a subset; delegation is passing the reference. No policy language: attenuation is code.
- **Offline**: no; live sessions.
- **Revocation**: revocable forwarders (caretaker pattern) or session teardown — the strongest revocation story of any system here because the reference simply stops working.
- **Formal**: strong theory (Miller's "Robust Composition", E), but OCapN itself is "still pre-specification" with an NLnet-funded 2025 spec effort aiming at Spritely–Agoric interop.
- **Lesson**: the right *semantics* (confinement, attenuation by construction, no ambient authority) but not a wire-portable *credential*.

---

## 2. OAuth/OIDC-family carriers (authorization server in the loop)

### 2.1 RFC 9396 Rich Authorization Requests
Adds `authorization_details` (typed JSON objects: `type`, `actions`, `locations`, `datatypes`, custom fields) to requests and tokens, replacing flat scopes. Vendors (HashiCorp Vault "AI/IAM", MojoAuth, MCP issue #1670) now pitch RAR as "the closest thing the standards world has" to agent task scoping ("refill inventory up to this limit for this account"). No delegation semantics; attenuation only by asking the AS for a narrower token.

### 2.2 Token Exchange (RFC 8693) + Transaction Tokens + Identity Chaining
- **Transaction Tokens** (`draft-ietf-oauth-transaction-tokens-08`, March 2026; a `-latest` dated June 2026): short-lived JWT minted by a Transaction Token Service at ingress that carries `sub`, `purp` (purpose), `azd` (authorization details), `rctx` (request context); *replacement* tokens may be minted per hop to narrow `azd`. Domain-internal only. **Transaction Tokens for Agents** (`draft-oauth-transaction-tokens-for-agents-06`, individual draft) adds `act` for the agent, nests actor chains for multi-hop, and keeps `sub` as the principal; a companion "A2A profile" (`draft-liu-oauth-a2a-profile-00`) exists [excerpt].
- **Identity Chaining** (`draft-ietf-oauth-identity-chaining`, WG item, -08 Feb 2026): Token Exchange (8693) → JWT authorization grant (7523) → access token in another trust domain. Keycloak 26.5 shipped preview support (Jan 2026) [excerpt]. Cross-App Access (Okta) is the enterprise packaging of this.
- **Offline**: JWTs verify offline against the issuer's JWKS, but *attenuation requires an AS round-trip* (the holder cannot narrow a JWT).
- **Revocation**: short lifetimes; introspection; no holder-side revocation.
- **Formal**: none mechanized (OAuth has had pen-and-paper/Tamarin analyses of core flows, not these drafts).

### 2.3 "OAuth for AI agents" drafts (status as of Aug 2026)
- `draft-oauth-ai-agents-on-behalf-of-user` (-02, expired Feb 2026): `requested_actor` in the authorization request and `actor_token` at the token endpoint so consent and the resulting token name the agent (`act`/`may_act` claims). Individual submission, no WG.
- `draft-klrc-aiagent-auth-03`, `draft-aap-oauth-profile-01` (Agent Authorization Profile, Feb 2026), `draft-chen-oauth-agent-authz-use-cases-03` (Aug 2026), `draft-prakash-aip-00`: all individual. In August 2026 the OAuth WG chairs said it was **premature to adopt any agent document**; "more than 70 individual drafts" target agent use cases, concentrating on human approval of specific transactions and carrying context across trust boundaries [excerpt, Duende recap / OAuth list].
- **OpenID Foundation**: the AI Identity Management Community Group whitepaper ("Identity Management for Agentic AI", Oct 2025, arXiv 2510.25819) argues unmodified OAuth forces impersonation or broad static keys, and recommends profiles of OAuth 2.1 + token exchange, SCIM agent resources, and "OIDC for Agents" rather than new protocols.
- **MCP** (July 2026 revision): OAuth 2.1 + PKCE, Resource Indicators (RFC 8707) for audience binding, RFC 8693 token exchange so an MCP server obtains *its own* downstream tokens (confused-deputy mitigation), standardized scope step-up, and production-grade Enterprise-Managed Authorization [excerpt, WorkOS/Descope].

### 2.4 GNAP (RFC 9635, Oct 2024; RS connections RFC 9767)
Grant negotiation with structured *access rights* objects (type/actions/locations/datatypes), key-bound (proof-of-possession) tokens by default, grant continuation, token rotation and revocation endpoints, and multiple interaction modes. Better shaped for agents than OAuth 2 (explicit key binding, structured rights, continuation for step-up) but adoption is thin; it is best mined for its data model.

### 2.5 AP2 (Google Agent Payments Protocol, Sept 2025)
Not a general carrier but the clearest deployed example of *principal-signed mandates*: Intent Mandate (natural-language request, hard constraints, TTL, allowed merchants, agent id) → Cart Mandate (specific approved action; may be auto-signed by the agent only if the Intent's conditions are exactly met) → Payment Mandate. Each is a W3C Verifiable Credential; 60+ payments partners. It demonstrates the "intent → concrete action" two-level approval that a runtime should generalize beyond payments.

---

## 3. Workload identity (who is the hop)

- **SPIFFE/SPIRE**: attested, hourly-rotating SVIDs per agent/MCP container is the mid-2026 reference architecture (HashiCorp, Stacklok, Riptides). Pain point: SPIRE requires pre-registration, which fights dynamically spawned subagents; teams automate entry creation or attest the orchestrator and derive child identities.
- **WIMSE** (IETF WG): architecture (-07), Workload Identifier (-03, a URI, embeddable in X.509 and JWT), Workload Credentials (-02), and **Workload Proof Token** (-01, a signed JWT binding a Workload Identity Token to a specific HTTP request, i.e. DPoP for workloads). WIMSE explicitly hands user-context propagation to transaction tokens/identity chaining. Nothing agent-specific yet, but this is where a per-hop *identity* credential for subagents will standardize.

---

## 4. Policy engines (decision, not carrier)

- **Cedar** (AWS, CNCF): default-deny, forbid-overrides-permit, validator soundness and evaluator properties proven in **Lean**, differential testing of Lean model vs Rust; 2025 "Cedar Analysis" ships a symbolic compiler whose correctness is proven in Lean, enabling SMT-backed policy equivalence/containment checks (PACMPL 2024 paper; AWS blogs). **Bedrock AgentCore Policy** (GA March 3, 2026) puts a Cedar engine in front of every tool call at the AgentCore Gateway, "outside the agent's code, outside the model's reasoning," with a neuro-symbolic NL→Cedar loop. This is the most credible production instance of a *machine-checked* tool-call PDP.
- **OPA/Rego**: dominant CNCF policy engine; vendor content now frames it as the guardrail at the tool-calling layer ("the agent does not decide"). Rego has no formal semantics proof; `draft-liu-oauth-rego-policy-00` proposes Rego as an OAuth policy carrier.
- **AuthZEN Authorization API 1.0** (OpenID Final, Jan 2026; fetched): PEP→PDP JSON API with `subject/action/resource/context`, single and batch evaluation (`deny_on_first_deny`, `permit_on_first_permit`), decision plus context/obligations. The 1.0 API text has no delegation or agent concepts; the WG followed with an Obligations profile, COAZ (protocol-neutral mapping), an **MCP Tool Authorization profile**, and the **Access Request and Approval Profile (AARP)** for human-in-the-loop approvals (2026 WG drafts) [excerpt].
- **Zanzibar-family (SpiceDB, OpenFGA, Permify)**: relationship tuples with delegation modeled as `agent#acts_for@user` and schema-level `permission` unions; OpenAI runs SpiceDB for ChatGPT Enterprise connectors; late-2025 surge in "delegation" schemas. Strength: precise resource-level entitlements and reverse queries; weakness: centralized, online, no carrier, no formal treatment beyond consistency guarantees.

---

## 5. Comparative summary

| Carrier | Holder-side attenuation | Offline verify | Revocation | Formal | Cross-domain |
|---|---|---|---|---|---|
| Macaroon | yes (caveats) | no (root secret) | expiry / 3P freshness | paper only | 3P discharges |
| Biscuit | yes (blocks, seal) | yes (root pubkey) | revocation_id deny-list | Datalog semantics; no mech. proof | third-party blocks + `trusting` |
| UCAN v1 | yes (cmd/pol) | yes (DIDs) | `ucan/rvk`, out-of-band | none | DIDs, powerline |
| ZCAP-LD | yes | yes | target lists | none | DI proofs |
| CapTP/OCapN | by construction (facets) | no (live) | strongest (caretakers) | ocap theory | netlayers |
| JWT + RAR / txn-token | no (AS mints) | yes | short TTL | none | identity chaining |
| GNAP | no (AS), key-bound | yes | endpoint | none | RS connections |
| Cedar / OPA / AuthZEN / Zanzibar | n/a (decision) | n/a | n/a | Cedar: Lean | PDP API |

---

## 6. What a world-class agent runtime would adopt or emulate in 2026

1. **Carry authority in a Biscuit-shaped chain, not a JWT.** The requirement that a subagent on another host can narrow authority *without a round-trip* and that any verifier with the root public key can check the chain is exactly Biscuit's block-chaining-with-ephemeral-keys plus `seal`. Nucleus' `portcullis` already has this skeleton (`LatticeCertificate::mint/delegate`, `AttenuationToken::seal/verify`, Ed25519, chain depth, expiry, SPIFFE-ID holders). What is missing relative to the frontier: (a) **third-party blocks with `trusting` scoping**, so a budget service, an approval service, or a second principal can co-sign a hop without seeing the root key; (b) a **per-block revocation identifier** and a verifier deny-list interface; (c) a **structured caveat language with a decidable meet** — Biscuit's Datalog checks or UCAN's `pol` predicates — instead of only lattice fields, so principals can express "≤ $50, only repo X, only before 17:00, only if approval receipt R present".
2. **Separate delegation from invocation (UCAN).** Possession of a chain must not be sufficient; each effect should be a signed invocation naming the chain, the exact args, and a nonce, with policies that constrain args. This turns receipts into provable "who authorized this, through which agents, with what scope at each hop" objects (AIP's IBCT framing) and closes bearer-token replay.
3. **Split "what" from "who" (Macaroon discharges / WIMSE WPT).** Bind each hop's block to an attested workload identity (SPIFFE SVID today; WIMSE WIT+WPT as it lands) so a stolen chain is inert off the attested host, and so dynamically spawned subagents get identity derived from the parent's attestation rather than SPIRE pre-registration.
4. **Two-level approval like AP2 and AuthZEN AARP.** Encode principal intent (constraints, TTL, allowed targets) as a signed mandate; concrete high-consequence actions produce a second, narrower signed approval — auto-issuable only when the mandate's predicates hold, else routed to a human. Expose this over the AuthZEN 1.0 request shape so external PDPs/approval systems interoperate.
5. **Keep the decision engine machine-checked (Cedar's bar).** Cedar sets the expectation: evaluator semantics, validator soundness, and even the symbolic analyzer proven in Lean, with differential testing against the shipped implementation. Nucleus' Lean/Kani attenuation laws (`attenuation.rs`, `PortcullisCore/Attenuation.lean`) are the right direction; the frontier ratchet is to extend proofs from the lattice algebra to the *wire chain verifier* (signature chaining, seal, third-party scoping, revocation), and to publish policy-containment analysis ("child ≤ parent" decided symbolically).
6. **Interoperate at the edges via OAuth plumbing, not as the internal carrier.** Ingress: accept RAR `authorization_details`, MCP OAuth 2.1 tokens, identity-chaining JWT grants; convert them into the root block of a chain. Egress: exchange the chain for scoped downstream tokens via RFC 8693 so third-party APIs see a token minted for *this* hop (the MCP confused-deputy rule). Emit transaction-token-style `sub`/`act`/`purp`/`azd` claims in audit records so enterprise IdPs can consume them.
7. **Revocation as a first-class, layered story**: short expiries by default, per-block revocation ids gossiped to verifiers (Nucleus already has witness gossip), and ocap-style caretakers for live sessions (kill the forwarder, not the key).
8. **Measure the envelope (clause 5)**: publish, per release, the set of caveat predicates supported, chain depth/latency overhead (AIP reports ~0.05–0.2 ms/verify, 2.35 ms end-to-end in a multi-agent run), and conformance vectors shared with Biscuit/UCAN so external verifiers can check Nucleus chains.

Net: no single standard is finished. Biscuit (offline attenuation, third-party blocks), UCAN (invocation/delegation split, arg policies), Macaroons (what/who split), OCapN (revocable references), Cedar (Lean-verified decisions), and the OAuth/WIMSE drafts (interop and workload identity) each contribute one piece; a 2026 frontier runtime composes them and proves the composition.

---

## Sources

- Biscuit specification (v5, third-party blocks, `trusting`, revocation ids): https://github.com/eclipse-biscuit/biscuit/blob/master/SPECIFICATIONS.md
- Biscuit 3.0 / third-party blocks blog: https://www.biscuitsec.org/blog/biscuit-3-0/ ; https://www.biscuitsec.org/blog/third-party-blocks-why-how-when-who/
- UCAN Delegation v1.0.0: https://github.com/ucan-wg/delegation ; UCAN spec: https://github.com/ucan-wg/spec/blob/main/README.md ; UCAN Invocation: https://github.com/ucan-wg/invocation
- Macaroons paper (Birgisson et al., 2014): https://theory.stanford.edu/~ataly/Papers/macaroons.pdf
- Fly.io macaroon design notes: https://github.com/superfly/macaroon/blob/main/macaroon-thought.md ; https://fly.io/blog/macaroons-escalated-quickly/ ; https://fly.io/docs/flyctl/tokens-attenuate/
- L402 for agents (Lightning Labs, Mar 2026): https://lightning.engineering/posts/2026-03-11-L402-for-agents/
- ZCAP-LD v0.4.0-draft: https://w3c-ccg.github.io/zcap-spec/ ; https://github.com/w3c-ccg/zcap-spec
- OCapN / CapTP: https://github.com/ocapn/ocapn ; https://github.com/ocapn/ocapn/blob/main/draft-specifications/CapTP%20Specification.md ; https://ocapn.org/ ; https://nlnet.nl/project/SpritelyOCapN/
- RFC 9396 Rich Authorization Requests: https://www.rfc-editor.org/info/rfc9396/ ; MCP RAR issue: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1670 ; Vault RAR for agents: https://developer.hashicorp.com/vault/ai/iam/concepts/rar
- OAuth Transaction Tokens (-08, Mar 2026): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08 ; Transaction Tokens for Agents (-06): https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/ ; A2A profile: https://datatracker.ietf.org/doc/html/draft-liu-oauth-a2a-profile-00
- OAuth Identity Chaining (WG item): https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/
- On-Behalf-Of for AI agents draft: https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/01/ ; https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-00.html
- AI Agent Authentication and Authorization (klrc): https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/ ; Agent Authorization Profile: https://datatracker.ietf.org/doc/draft-aap-oauth-profile/ ; OAuth WG adoption discussion (Aug 2026): http://www.mail-archive.com/oauth@ietf.org/msg26607.html
- Duende Summer 2026 identity standards recap: https://duendesoftware.com/blog/20260820-summer-2026-identity-standards-recap
- GNAP RFC 9635 / RFC 9767: https://datatracker.ietf.org/doc/html/rfc9635 ; https://www.rfc-editor.org/rfc/rfc9767.html ; https://oauth.net/gnap/
- AuthZEN Authorization API 1.0 (Final): https://github.com/openid/authzen/blob/main/api/authorization-api-1_0.md ; https://openid.net/authorization-api-1-0-final-specification-approved/ ; new AuthZEN agent-era drafts (MCP profile, AARP): https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/
- OpenID Foundation agentic identity whitepaper: https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/ ; https://arxiv.org/pdf/2510.25819
- "AI Identity: Standards, Gaps" (Apr 2026): https://arxiv.org/pdf/2604.23280 ; Overlaying Governance (Jun 2026): https://arxiv.org/html/2606.03518v1 ; Authorization Propagation in Multi-Agent Systems: https://arxiv.org/html/2605.05440v1
- AIP: Agent Identity Protocol (Mar 2026, Biscuit chained mode): https://arxiv.org/abs/2603.24775 ; https://datatracker.ietf.org/doc/draft-prakash-aip/
- MCP authorization (2026): https://workos.com/blog/mcp-2026-spec-agent-authentication ; https://www.descope.com/blog/post/mcp-auth-spec ; https://www.cerbos.dev/blog/mcp-authorization-standards
- Cedar formalization in Lean: https://lean-lang.org/use-cases/cedar/ ; https://aws.amazon.com/blogs/opensource/lean-into-verified-software-development/ ; Cedar Analysis: https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/ ; Cedar PACMPL paper: https://dl.acm.org/doi/full/10.1145/3649835
- Bedrock AgentCore Policy chose Cedar: https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/ ; https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-understanding-cedar.html
- OPA for agents: https://codilime.com/blog/why-use-open-policy-agent-for-your-ai-agents/ ; https://tianpan.co/blog/2026-04-25-policy-as-code-agent-permissions-opa-rego ; Rego for OAuth draft: https://datatracker.ietf.org/doc/html/draft-liu-oauth-rego-policy-00
- Zanzibar-family for agents: https://stacklok.com/blog/agentic-identity-explained-how-to-apply-spiffe-and-relationship-based-authorization-to-ai-agents-in-2026/ ; https://www.youngju.dev/blog/culture/2026-05-25-authorization-fga-zanzibar-spicedb-permify-openfga-cerbos-cedar-oso-2026-deep-dive.en ; https://authzed.com/learn/openfga-alternatives
- SPIFFE for agents: https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors ; https://riptides.io/blog/how-to-deliver-spiffe-identity-to-ai-agents/
- WIMSE drafts: https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch-07 ; https://datatracker.ietf.org/doc/draft-ietf-wimse-identifier/ ; https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/ ; https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/
- AP2 Agent Payments Protocol: https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol ; https://ap2-protocol.org/ ; https://cloudsecurityalliance.org/blog/2025/10/06/secure-use-of-the-agent-payments-protocol-ap2-a-framework-for-trustworthy-ai-driven-transactions
