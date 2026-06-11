//! Agent Card types — the A2A protocol **v1.0** `AgentCard` plus its
//! embedded RFC 7515 JWS signatures.
//!
//! Conformance target: the A2A v1.0.1 specification, whose
//! `specification/a2a.proto` is the *single authoritative normative
//! definition* of the data objects, serialized to JSON per ProtoJSON
//! (A2A ADR-001): lowerCamelCase wire names, optional/default fields
//! omitted when unset. Signing is §8.4: detached JWS over the RFC 8785
//! JCS canonicalization of the card with the `signatures` field excluded.
//!
//! Nucleus-specific claims (SPIFFE/DID identity, the trust JWKS, envelope
//! schema versions, the [`RuntimeGuaranteeProfile`]) do NOT live as
//! top-level card fields — v1.0 has no such fields. They travel inside the
//! spec's extension mechanism (`capabilities.extensions[]`) as the
//! registered extension [`NUCLEUS_EXTENSION_URI`], typed here as
//! [`NucleusClaims`].
//!
//! These are pure data; signing lives in [`crate::sign`] (feature-gated)
//! and verification in [`crate::verify`] (always available).
//!
//! # Forward-compat
//!
//! None of these structs use `deny_unknown_fields`. A newer producer may
//! add fields this verifier doesn't know about; unknown fields are
//! ignored on parse so an older verifier still works against a newer
//! card. The canonicalization in [`crate::jcs`] covers exactly the
//! fields defined here — what we sign is what we know.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The A2A protocol version this crate's [`AgentCard`] conforms to, as
/// advertised per-interface in [`AgentInterface::protocol_version`].
pub const A2A_PROTOCOL_VERSION: &str = "1.0";

/// The registered extension URI under which nucleus's verify-before-you-act
/// claims ([`NucleusClaims`]) travel inside `capabilities.extensions[]`.
///
/// Versioned independently of the card: a breaking change to
/// [`NucleusClaims`] bumps the trailing `/v1`.
pub const NUCLEUS_EXTENSION_URI: &str = "https://coproduct.one/a2a/ext/runtime-guarantees/v1";

/// `skip_serializing_if` helper: omit a `bool` field when `false` (the
/// ProtoJSON default-omission rule for proto3 implicit-presence fields).
#[allow(clippy::trivially_copy_pass_by_ref)] // serde requires `&T`
fn is_false(b: &bool) -> bool {
    !*b
}

/// The self-describing A2A **v1.0** identity manifest an agent publishes
/// (typically at `/.well-known/agent-card.json`).
///
/// Field set and wire names follow `a2a.proto` `message AgentCard`
/// (Next ID: 20) under ProtoJSON serialization. Fields the proto marks
/// `REQUIRED` are non-optional here; optional/default-omitted fields are
/// `Option`/empty-skipped so our serialization matches the §8.4.1
/// presence rules a signer and verifier must agree on.
///
/// **Nucleus claims live in the extension, not here.** Use
/// [`AgentCard::nucleus_claims`] to extract them and
/// [`AgentCard::with_nucleus_claims`] to attach them. The advertised
/// trust JWKS inside those claims is a CLAIM, not an anchor — it only
/// becomes load-bearing once the card itself has been verified against an
/// out-of-band-resolved key (see [`crate::verify::verify_card`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Human-readable agent name (REQUIRED). Example: `"Recipe Agent"`.
    pub name: String,

    /// Human-readable description of the agent (REQUIRED).
    pub description: String,

    /// Ordered list of supported interfaces; the first entry is preferred
    /// (REQUIRED).
    pub supported_interfaces: Vec<AgentInterface>,

    /// The service provider of the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,

    /// The version of the agent (REQUIRED). Example: `"1.0.0"`.
    pub version: String,

    /// URL providing additional documentation about the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,

    /// A2A capability set supported by the agent (REQUIRED). Nucleus's
    /// extension rides in `capabilities.extensions`.
    pub capabilities: AgentCapabilities,

    /// Security scheme details for authenticating with this agent
    /// (`map<string, SecurityScheme>` in the proto), keyed by the scheme
    /// name that [`SecurityRequirement`]s reference. Typed per the
    /// normative `a2a.proto` so §7.3 client discovery ("the client
    /// discovers the server's required authentication schemes via the
    /// `securitySchemes` field") can match on the variant instead of
    /// poking at opaque JSON.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub security_schemes: BTreeMap<String, SecurityScheme>,

    /// Security requirements for contacting the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_requirements: Vec<SecurityRequirement>,

    /// Interaction media types the agent supports across all skills
    /// (REQUIRED). Overridable per skill.
    pub default_input_modes: Vec<String>,

    /// Output media types supported across all skills (REQUIRED).
    pub default_output_modes: Vec<String>,

    /// Skills — the agent's distinct abilities (REQUIRED; may be empty).
    pub skills: Vec<AgentSkill>,

    /// JSON Web Signatures computed for this card (§8.4). EXCLUDED from
    /// the signed/canonicalized content — see [`crate::jcs::canonicalize`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<AgentCardSignature>,

    /// URL to an icon for the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

impl AgentCard {
    /// The nucleus extension entry, if this card declares one.
    pub fn nucleus_extension(&self) -> Option<&AgentExtension> {
        self.capabilities
            .extensions
            .iter()
            .find(|e| e.uri == NUCLEUS_EXTENSION_URI)
    }

    /// Extract the typed [`NucleusClaims`] from the card's
    /// [`NUCLEUS_EXTENSION_URI`] extension.
    ///
    /// Returns `Ok(None)` when the card does not declare the extension at
    /// all (a plain A2A card from a non-nucleus agent).
    ///
    /// # Errors
    ///
    /// [`Error::Extension`] when the extension is declared but its
    /// `params` are missing or do not deserialize as [`NucleusClaims`] —
    /// a declared-but-malformed claim set is an error, not an absence.
    pub fn nucleus_claims(&self) -> Result<Option<NucleusClaims>> {
        let Some(ext) = self.nucleus_extension() else {
            return Ok(None);
        };
        let params = ext.params.as_ref().ok_or_else(|| {
            Error::Extension("nucleus extension is declared but has no params".to_string())
        })?;
        let claims: NucleusClaims = serde_json::from_value(params.clone())
            .map_err(|e| Error::Extension(format!("nucleus extension params: {e}")))?;
        Ok(Some(claims))
    }

    /// Attach (or replace) the nucleus extension carrying `claims`.
    ///
    /// The extension is declared `required: false` — a non-nucleus A2A
    /// client can still talk to the agent; the claims matter to
    /// counterparties running the verify-before-you-act flow.
    ///
    /// # Errors
    ///
    /// [`Error::Extension`] if the claims fail to serialize (practically
    /// unreachable for well-formed claims).
    pub fn with_nucleus_claims(mut self, claims: &NucleusClaims) -> Result<Self> {
        let params = serde_json::to_value(claims)
            .map_err(|e| Error::Extension(format!("serialize nucleus claims: {e}")))?;
        let ext = AgentExtension {
            uri: NUCLEUS_EXTENSION_URI.to_string(),
            description: "nucleus verify-before-you-act claims: SPIFFE/DID identity, \
                          trust JWKS, envelope schema versions, runtime-guarantee profile"
                .to_string(),
            required: false,
            params: Some(params),
        };
        if let Some(existing) = self
            .capabilities
            .extensions
            .iter_mut()
            .find(|e| e.uri == NUCLEUS_EXTENSION_URI)
        {
            *existing = ext;
        } else {
            self.capabilities.extensions.push(ext);
        }
        Ok(self)
    }
}

/// One target URL + protocol binding + protocol version the agent serves
/// (`a2a.proto` `message AgentInterface`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    /// Where this interface is available (REQUIRED). Absolute HTTPS URL in
    /// production.
    pub url: String,

    /// Protocol binding at this URL (REQUIRED). Open string; the core
    /// official values are `"JSONRPC"`, `"GRPC"` and `"HTTP+JSON"`.
    pub protocol_binding: String,

    /// Opaque routing identifier for multi-tenant endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,

    /// The A2A protocol version this interface exposes (REQUIRED), e.g.
    /// [`A2A_PROTOCOL_VERSION`].
    pub protocol_version: String,
}

/// The service provider of an agent (`a2a.proto` `message AgentProvider`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentProvider {
    /// URL for the provider's website or relevant documentation (REQUIRED).
    pub url: String,

    /// Name of the provider's organization (REQUIRED).
    pub organization: String,
}

/// Optional capabilities supported by an agent
/// (`a2a.proto` `message AgentCapabilities`).
///
/// The three booleans are `optional bool` in the proto (explicit
/// presence): when set — even to `false` — they appear on the wire; when
/// unset they are omitted. `Option<bool>` reproduces exactly that.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// Supports streaming responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,

    /// Supports push notifications for asynchronous task updates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_notifications: Option<bool>,

    /// Protocol extensions supported by the agent. Nucleus's claims travel
    /// here under [`NUCLEUS_EXTENSION_URI`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<AgentExtension>,

    /// Supports an extended agent card when authenticated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_agent_card: Option<bool>,
}

/// A declaration of a protocol extension supported by an agent
/// (`a2a.proto` `message AgentExtension`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentExtension {
    /// The unique URI identifying the extension.
    pub uri: String,

    /// Human-readable description of how this agent uses the extension.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// If true, the client must understand and comply with the extension's
    /// requirements.
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,

    /// Extension-specific configuration parameters (`google.protobuf.Struct`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// Security requirements for an agent
/// (`a2a.proto` `message SecurityRequirement`): a map of security-scheme
/// names to required scopes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRequirement {
    /// Scheme name → required scopes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub schemes: BTreeMap<String, StringList>,
}

/// A list of strings (`a2a.proto` `message StringList`) — the scope list
/// inside a [`SecurityRequirement`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StringList {
    /// The individual string values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub list: Vec<String>,
}

/// A security scheme that can be used to secure an agent's endpoints
/// (`a2a.proto` `message SecurityScheme`) — a discriminated union based on
/// the OpenAPI 3.2 Security Scheme Object.
///
/// # Wire shape (ProtoJSON oneof)
///
/// The proto models this message as a single `oneof scheme { ... }`. Under
/// ProtoJSON, exactly one of a oneof's fields appears, **as a regular field
/// of the containing message** — i.e. the variant is carried as the field
/// NAME inside the `SecurityScheme` wrapper object, exactly like the spec's
/// §8.5 sample card:
///
/// ```json
/// "securitySchemes": {
///   "google": {
///     "openIdConnectSecurityScheme": {
///       "openIdConnectUrl": "https://accounts.google.com/.well-known/openid-configuration"
///     }
///   }
/// }
/// ```
///
/// Serde's *externally tagged* enum representation reproduces that
/// encoding bit-for-bit (an object with exactly one key naming the set
/// variant). An *untagged* enum would be WRONG here: it would accept
/// payloads without the variant key and could not round-trip the wrapper
/// object protoc/pbjson emit.
///
/// The single-key requirement is also load-bearing on parse: an entry
/// claiming TWO variants at once (illegal for a oneof) or a stale A2A v0.x
/// `{"type": "oauth2", ...}` discriminator fails deserialization instead
/// of silently riding along as opaque JSON. Unknown fields *inside* a
/// variant's payload remain tolerated, matching this crate's
/// forward-compat posture for ordinary message fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityScheme {
    /// API key-based authentication
    /// (`api_key_security_scheme`, oneof field 1).
    #[serde(rename = "apiKeySecurityScheme")]
    ApiKey(ApiKeySecurityScheme),

    /// HTTP authentication — Basic, Bearer, etc.
    /// (`http_auth_security_scheme`, oneof field 2).
    #[serde(rename = "httpAuthSecurityScheme")]
    HttpAuth(HttpAuthSecurityScheme),

    /// OAuth 2.0 authentication
    /// (`oauth2_security_scheme`, oneof field 3).
    #[serde(rename = "oauth2SecurityScheme")]
    OAuth2(OAuth2SecurityScheme),

    /// OpenID Connect authentication
    /// (`open_id_connect_security_scheme`, oneof field 4).
    #[serde(rename = "openIdConnectSecurityScheme")]
    OpenIdConnect(OpenIdConnectSecurityScheme),

    /// Mutual TLS authentication (`mtls_security_scheme`, oneof field 5).
    /// ProtoJSON derives the wire name from the proto FIELD name, so this
    /// is `mtlsSecurityScheme` — not the message name
    /// `MutualTlsSecurityScheme`.
    #[serde(rename = "mtlsSecurityScheme")]
    MutualTls(MutualTlsSecurityScheme),
}

/// A security scheme using an API key
/// (`a2a.proto` `message APIKeySecurityScheme`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeySecurityScheme {
    /// An optional description for the security scheme.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// The location of the API key (REQUIRED). Valid values are
    /// `"query"`, `"header"`, or `"cookie"`.
    pub location: String,

    /// The name of the header, query, or cookie parameter to be used
    /// (REQUIRED).
    pub name: String,
}

/// A security scheme using HTTP authentication
/// (`a2a.proto` `message HTTPAuthSecurityScheme`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HttpAuthSecurityScheme {
    /// An optional description for the security scheme.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// The HTTP Authentication scheme used in the `Authorization` header,
    /// as defined in RFC 7235 — e.g. `"Bearer"` (REQUIRED). Should be a
    /// value registered in the IANA Authentication Scheme registry.
    pub scheme: String,

    /// A hint to the client for how the bearer token is formatted
    /// (e.g. `"JWT"`). Documentation only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bearer_format: String,
}

/// A security scheme using OAuth 2.0
/// (`a2a.proto` `message OAuth2SecurityScheme`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2SecurityScheme {
    /// An optional description for the security scheme.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Configuration for the supported OAuth 2.0 flow (REQUIRED). An
    /// oauth2 scheme that does not say which flow to run is unusable, so
    /// absence is a parse error, not a default.
    pub flows: OAuthFlows,

    /// URL to the OAuth2 authorization server metadata (RFC 8414).
    /// TLS is required.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub oauth2_metadata_url: String,
}

/// A security scheme using OpenID Connect
/// (`a2a.proto` `message OpenIdConnectSecurityScheme`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenIdConnectSecurityScheme {
    /// An optional description for the security scheme.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// The OpenID Connect Discovery URL for the OIDC provider's metadata
    /// (REQUIRED).
    pub open_id_connect_url: String,
}

/// A security scheme using mutual TLS authentication
/// (`a2a.proto` `message MutualTlsSecurityScheme`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MutualTlsSecurityScheme {
    /// An optional description for the security scheme.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// Configuration of the supported OAuth 2.0 flow
/// (`a2a.proto` `message OAuthFlows`).
///
/// Like [`SecurityScheme`], the proto models this as a single
/// `oneof flow { ... }`, so the ProtoJSON wrapper object carries exactly
/// one key naming the configured flow — e.g.
/// `{"clientCredentials": {"tokenUrl": "...", "scopes": {}}}` — and serde's
/// externally tagged representation matches it exactly. (Note this is
/// narrower than the OpenAPI object it descends from, which allows several
/// flows side by side; the normative proto allows exactly one.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OAuthFlows {
    /// The OAuth 2.0 Authorization Code flow
    /// (`authorization_code`, oneof field 1).
    #[serde(rename = "authorizationCode")]
    AuthorizationCode(AuthorizationCodeOAuthFlow),

    /// The OAuth 2.0 Client Credentials flow
    /// (`client_credentials`, oneof field 2).
    #[serde(rename = "clientCredentials")]
    ClientCredentials(ClientCredentialsOAuthFlow),

    /// The OAuth 2.0 Implicit flow (`implicit`, oneof field 3). The proto
    /// marks this flow deprecated — producers should use Authorization
    /// Code + PKCE instead — but conformant cards may still carry it, so a
    /// verifier must keep parsing it.
    #[serde(rename = "implicit")]
    Implicit(ImplicitOAuthFlow),

    /// The OAuth 2.0 Resource Owner Password flow
    /// (`password`, oneof field 4). Deprecated in the proto — use
    /// Authorization Code + PKCE or Device Code — but still parsed, as for
    /// [`OAuthFlows::Implicit`].
    #[serde(rename = "password")]
    Password(PasswordOAuthFlow),

    /// The OAuth 2.0 Device Code flow, RFC 8628
    /// (`device_code`, oneof field 5).
    #[serde(rename = "deviceCode")]
    DeviceCode(DeviceCodeOAuthFlow),
}

/// Configuration of the OAuth 2.0 Authorization Code flow
/// (`a2a.proto` `message AuthorizationCodeOAuthFlow`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationCodeOAuthFlow {
    /// The authorization URL to be used for this flow (REQUIRED).
    pub authorization_url: String,

    /// The token URL to be used for this flow (REQUIRED).
    pub token_url: String,

    /// The URL to be used for obtaining refresh tokens.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_url: String,

    /// The available scopes for the OAuth2 security scheme: scope name →
    /// short description (REQUIRED; may be empty).
    pub scopes: BTreeMap<String, String>,

    /// Whether PKCE (RFC 7636) is required for this flow. PKCE should
    /// always be used for public clients and is recommended for all
    /// clients.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pkce_required: bool,
}

/// Configuration of the OAuth 2.0 Client Credentials flow
/// (`a2a.proto` `message ClientCredentialsOAuthFlow`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientCredentialsOAuthFlow {
    /// The token URL to be used for this flow (REQUIRED).
    pub token_url: String,

    /// The URL to be used for obtaining refresh tokens.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_url: String,

    /// The available scopes for the OAuth2 security scheme: scope name →
    /// short description (REQUIRED; may be empty).
    pub scopes: BTreeMap<String, String>,
}

/// Configuration of the deprecated OAuth 2.0 Implicit flow
/// (`a2a.proto` `message ImplicitOAuthFlow`). Every field is optional in
/// the proto (no REQUIRED annotations on the deprecated flows).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImplicitOAuthFlow {
    /// The authorization URL to be used for this flow. The OAuth2
    /// standard requires the use of TLS.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authorization_url: String,

    /// The URL to be used for obtaining refresh tokens.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_url: String,

    /// The available scopes for the OAuth2 security scheme: scope name →
    /// short description. MAY be empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scopes: BTreeMap<String, String>,
}

/// Configuration of the deprecated OAuth 2.0 Resource Owner Password flow
/// (`a2a.proto` `message PasswordOAuthFlow`). Every field is optional in
/// the proto (no REQUIRED annotations on the deprecated flows).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOAuthFlow {
    /// The token URL to be used for this flow. The OAuth2 standard
    /// requires the use of TLS.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_url: String,

    /// The URL to be used for obtaining refresh tokens.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_url: String,

    /// The available scopes for the OAuth2 security scheme: scope name →
    /// short description. MAY be empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scopes: BTreeMap<String, String>,
}

/// Configuration of the OAuth 2.0 Device Code flow, RFC 8628
/// (`a2a.proto` `message DeviceCodeOAuthFlow`) — for input-constrained
/// devices (IoT, CLI tools) where the user authenticates on a separate
/// device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCodeOAuthFlow {
    /// The device authorization endpoint URL (REQUIRED).
    pub device_authorization_url: String,

    /// The token URL to be used for this flow (REQUIRED).
    pub token_url: String,

    /// The URL to be used for obtaining refresh tokens.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_url: String,

    /// The available scopes for the OAuth2 security scheme: scope name →
    /// short description (REQUIRED; may be empty).
    pub scopes: BTreeMap<String, String>,
}

/// A distinct capability or function an agent can perform
/// (`a2a.proto` `message AgentSkill`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    /// Unique identifier for the skill (REQUIRED).
    pub id: String,

    /// Human-readable skill name (REQUIRED).
    pub name: String,

    /// Detailed description of the skill (REQUIRED).
    pub description: String,

    /// Keywords describing the skill's capabilities (REQUIRED).
    pub tags: Vec<String>,

    /// Example prompts or scenarios this skill can handle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,

    /// Supported input media types, overriding the agent's defaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_modes: Vec<String>,

    /// Supported output media types, overriding the agent's defaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_modes: Vec<String>,

    /// Security schemes necessary for this skill.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_requirements: Vec<SecurityRequirement>,
}

/// The nucleus verify-before-you-act claim set carried as the `params` of
/// the [`NUCLEUS_EXTENSION_URI`] extension.
///
/// This is everything nucleus needs beyond the base A2A card: WHO the
/// agent is (`spiffe_id`, `did`), what it speaks
/// (`supported_envelope_schema_versions`), and — critically — the JWKS the
/// agent claims its provenance bundles are signed under (`trust_jwks`).
///
/// **The advertised `trust_jwks` is a CLAIM, not an anchor.** It only
/// becomes load-bearing once the card itself has been verified against an
/// out-of-band-resolved key (see [`crate::verify::verify_card`]) AND the
/// recipient refuses to act on any bundle that doesn't verify against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NucleusClaims {
    /// SPIFFE identity of the agent
    /// (e.g. `spiffe://prod.example.com/ns/agents/sa/coder`).
    pub spiffe_id: String,

    /// Decentralized identifier for the agent
    /// (e.g. `did:web:coder.prod.example.com`).
    pub did: String,

    /// Envelope/bundle schema versions this agent can produce or consume.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_envelope_schema_versions: Vec<String>,

    /// Optional URI where the agent's JWKS is published out-of-band. A
    /// recipient MAY resolve this to obtain the verification key for the
    /// card; it is NOT trusted material on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// The JWKS the agent advertises as authoritative for its provenance
    /// bundles. Becomes a [`nucleus_envelope::TrustAnchor`] only after the
    /// card is verified.
    pub trust_jwks: nucleus_lineage::Jwks,

    /// Optional declared runtime information-flow-control guarantee profile.
    /// Covered by the card's JCS signature, so a verifier knows the declaration
    /// is authentic and untampered. **Attestation, not enforcement** — see
    /// [`RuntimeGuaranteeProfile`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_guarantees: Option<RuntimeGuaranteeProfile>,
}

/// A declared runtime information-flow-control (IFC) guarantee profile,
/// carried inside the signed card's [`NucleusClaims`].
///
/// # What a verified profile proves — and does not
///
/// Because the profile is part of the card's JCS-canonical bytes, the card
/// signature makes it **authentic and tamper-evident**: a counterparty can
/// confirm *the agent issued this exact declaration*. It does **NOT** prove the
/// declared rules are enforced, sound, or sufficient — attestation is not
/// enforcement. The agent's `nucleus-envelope` receipts are the behavioural
/// evidence that the declared rules were actually evaluated at runtime; a
/// verifier checks them post-hoc, client-side. Enforcement remains host-side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeGuaranteeProfile {
    /// Profile schema version (e.g. `"1.0"`), versioned independently of the card.
    pub profile_version: String,

    /// Data-flow source kinds the agent declares it labels/tracks — the
    /// lethal-trifecta surface (e.g. `"web_content"`, `"secret"`, `"file_read"`).
    /// Tokens match `nucleus-verify-commerce`'s `DeclaredInput` serde names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracked_sources: Vec<String>,

    /// Named IFC enforcement rules the agent declares it applies at runtime.
    pub enforcement_rules: Vec<EnforcementRule>,

    /// Advisory pointer to external policy evidence (e.g. a Microsoft Agent
    /// Control Specification policy id, or a Sigstore bundle URL). Advisory
    /// only — a verifier with no out-of-band knowledge cannot confirm it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_reference: Option<String>,
}

/// One named IFC enforcement rule a [`RuntimeGuaranteeProfile`] declares.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnforcementRule {
    /// Stable rule identifier (e.g. `"no_adversarial_to_outbound"`).
    pub name: String,
    /// Human-readable description of what the rule denies.
    pub description: String,
}

/// One JWS signature of an [`AgentCard`] (`a2a.proto`
/// `message AgentCardSignature`, spec §8.4.2): the JSON form of an RFC
/// 7515 JWS with the payload detached.
///
/// "Detached" means the JWS payload segment is dropped on the wire: the
/// recipient reconstructs it as the JCS canonicalization of the card with
/// the `signatures` field excluded (§8.4.1). This binds the signature to
/// the exact card content without duplicating the bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCardSignature {
    /// Base64url-encoded protected JWS header. Per §8.4.2 the header MUST
    /// include `alg` and `kid` (and SHOULD set `typ: "JOSE"`); it MAY
    /// include `jku`.
    pub protected: String,

    /// Base64url-encoded signature over
    /// `protected || "." || base64url(JCS(card minus signatures))`.
    pub signature: String,

    /// Optional unprotected JWS header (RFC 7515 §7.2.1), as a plain JSON
    /// object (not base64url-encoded). Not covered by the signature; carry
    /// hints here at the producer's risk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> NucleusClaims {
        NucleusClaims {
            spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            did: "did:web:coder.prod.example.com".to_string(),
            supported_envelope_schema_versions: vec!["1".to_string(), "2".to_string()],
            jwks_uri: Some("https://coder.prod.example.com/.well-known/jwks.json".to_string()),
            trust_jwks: nucleus_lineage::Jwks {
                keys: vec![nucleus_lineage::Jwk {
                    kty: "OKP".to_string(),
                    crv: Some("Ed25519".to_string()),
                    kid: "k1".to_string(),
                    x: Some("AAAA_AAAAAA-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
                    alg: Some("EdDSA".to_string()),
                    use_: Some("sig".to_string()),
                    not_before: None,
                    not_after: None,
                }],
            },
            runtime_guarantees: None,
        }
    }

    fn sample_card() -> AgentCard {
        AgentCard {
            name: "Coder Agent".to_string(),
            description: "Writes and reviews code with provenance receipts.".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: "https://coder.prod.example.com/a2a/v1".to_string(),
                protocol_binding: "JSONRPC".to_string(),
                tenant: None,
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            }],
            provider: Some(AgentProvider {
                url: "https://coproduct.one".to_string(),
                organization: "Coproduct".to_string(),
            }),
            version: "1.0.0".to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities::default(),
            security_schemes: BTreeMap::new(),
            security_requirements: vec![],
            default_input_modes: vec!["application/json".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![],
            signatures: vec![],
            icon_url: None,
        }
        .with_nucleus_claims(&sample_claims())
        .unwrap()
    }

    #[test]
    fn agent_card_serde_round_trip() {
        let card = sample_card();
        let json = serde_json::to_string(&card).unwrap();
        let back: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(
            serde_json::to_value(&card).unwrap(),
            serde_json::to_value(&back).unwrap()
        );
    }

    #[test]
    fn wire_names_are_a2a_v1_camel_case() {
        // Pin the ProtoJSON wire names from a2a.proto — drift here breaks
        // interop with every conformant A2A v1.0 implementation.
        let json = serde_json::to_value(sample_card()).unwrap();
        let obj = json.as_object().unwrap();
        for key in [
            "name",
            "description",
            "supportedInterfaces",
            "provider",
            "version",
            "capabilities",
            "defaultInputModes",
            "defaultOutputModes",
            "skills",
        ] {
            assert!(obj.contains_key(key), "missing v1.0 wire key `{key}`");
        }
        // snake_case must NOT leak onto the wire.
        for key in [
            "supported_interfaces",
            "default_input_modes",
            "spiffe_id",
            "trust_jwks",
        ] {
            assert!(!obj.contains_key(key), "non-v1.0 wire key `{key}` present");
        }
        let iface = &json["supportedInterfaces"][0];
        assert_eq!(iface["protocolBinding"], "JSONRPC");
        assert_eq!(iface["protocolVersion"], "1.0");
    }

    #[test]
    fn nucleus_claims_round_trip_through_the_extension() {
        let card = sample_card();
        let ext = card.nucleus_extension().expect("extension attached");
        assert_eq!(ext.uri, NUCLEUS_EXTENSION_URI);
        assert!(!ext.required, "nucleus extension must not gate A2A clients");

        let claims = card.nucleus_claims().unwrap().expect("claims present");
        assert_eq!(
            claims.spiffe_id,
            "spiffe://prod.example.com/ns/agents/sa/coder"
        );
        assert_eq!(claims.did, "did:web:coder.prod.example.com");
        assert_eq!(claims.trust_jwks.keys[0].kid, "k1");

        // Claims serialize camelCase inside the params.
        let params = ext.params.as_ref().unwrap();
        assert!(params.get("spiffeId").is_some());
        assert!(params.get("trustJwks").is_some());
        assert!(params.get("spiffe_id").is_none());
    }

    #[test]
    fn card_without_nucleus_extension_yields_no_claims() {
        let mut card = sample_card();
        card.capabilities.extensions.clear();
        assert!(card.nucleus_claims().unwrap().is_none());
    }

    #[test]
    fn declared_but_malformed_nucleus_extension_is_an_error() {
        let mut card = sample_card();
        // Declared with no params at all.
        card.capabilities.extensions[0].params = None;
        assert!(matches!(card.nucleus_claims(), Err(Error::Extension(_))));
        // Declared with params that are not NucleusClaims.
        card.capabilities.extensions[0].params = Some(serde_json::json!({"spiffeId": 42}));
        assert!(matches!(card.nucleus_claims(), Err(Error::Extension(_))));
    }

    #[test]
    fn with_nucleus_claims_replaces_an_existing_extension() {
        let card = sample_card();
        let mut claims = card.nucleus_claims().unwrap().unwrap();
        claims.did = "did:web:rotated.example.com".to_string();
        let card = card.with_nucleus_claims(&claims).unwrap();
        assert_eq!(
            card.capabilities
                .extensions
                .iter()
                .filter(|e| e.uri == NUCLEUS_EXTENSION_URI)
                .count(),
            1,
            "re-attaching must replace, not duplicate"
        );
        assert_eq!(
            card.nucleus_claims().unwrap().unwrap().did,
            "did:web:rotated.example.com"
        );
    }

    #[test]
    fn optional_and_default_fields_are_omitted_per_8_4_1() {
        // §8.4.1: unset optional fields and default-valued fields MUST be
        // omitted — our serde skips are the implementation of that rule.
        let mut card = sample_card();
        card.capabilities.extensions.clear();
        card.provider = None;
        let json = serde_json::to_value(&card).unwrap();
        let obj = json.as_object().unwrap();
        for absent in [
            "provider",
            "documentationUrl",
            "securitySchemes",
            "securityRequirements",
            "signatures",
            "iconUrl",
        ] {
            assert!(!obj.contains_key(absent), "`{absent}` must be omitted");
        }
        // capabilities is REQUIRED → present even when everything inside
        // is unset (it serializes as the empty object).
        assert_eq!(json["capabilities"], serde_json::json!({}));
        // skills is REQUIRED → present even when empty.
        assert_eq!(json["skills"], serde_json::json!([]));
    }

    #[test]
    fn explicitly_set_false_capabilities_stay_on_the_wire() {
        // `optional bool` = explicit presence: Some(false) is serialized.
        let mut card = sample_card();
        card.capabilities.streaming = Some(false);
        let json = serde_json::to_value(&card).unwrap();
        assert_eq!(json["capabilities"]["streaming"], serde_json::json!(false));
    }

    #[test]
    fn security_requirement_wire_shape_matches_protojson() {
        // ProtoJSON of `SecurityRequirement{schemes: map<string,StringList>}`.
        let req = SecurityRequirement {
            schemes: BTreeMap::from([(
                "oauth".to_string(),
                StringList {
                    list: vec!["openid".to_string()],
                },
            )]),
        };
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            serde_json::json!({"schemes": {"oauth": {"list": ["openid"]}}})
        );
    }

    /// One instance of every `SecurityScheme` oneof variant, exercising
    /// every REQUIRED subfield plus the optional ones.
    fn one_of_each_scheme() -> Vec<(&'static str, SecurityScheme)> {
        vec![
            (
                "apiKey",
                SecurityScheme::ApiKey(ApiKeySecurityScheme {
                    description: "internal service key".to_string(),
                    location: "header".to_string(),
                    name: "X-Api-Key".to_string(),
                }),
            ),
            (
                "bearer",
                SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
                    description: String::new(),
                    scheme: "Bearer".to_string(),
                    bearer_format: "JWT".to_string(),
                }),
            ),
            (
                "oauth",
                SecurityScheme::OAuth2(OAuth2SecurityScheme {
                    description: String::new(),
                    flows: OAuthFlows::AuthorizationCode(AuthorizationCodeOAuthFlow {
                        authorization_url: "https://auth.example.com/authorize".to_string(),
                        token_url: "https://auth.example.com/token".to_string(),
                        refresh_url: String::new(),
                        scopes: BTreeMap::from([("read".to_string(), "Read access".to_string())]),
                        pkce_required: true,
                    }),
                    oauth2_metadata_url: String::new(),
                }),
            ),
            (
                "oidc",
                SecurityScheme::OpenIdConnect(OpenIdConnectSecurityScheme {
                    description: String::new(),
                    open_id_connect_url:
                        "https://accounts.example.com/.well-known/openid-configuration".to_string(),
                }),
            ),
            (
                "mtls",
                SecurityScheme::MutualTls(MutualTlsSecurityScheme {
                    description: "client certificate".to_string(),
                }),
            ),
        ]
    }

    #[test]
    fn each_security_scheme_variant_round_trips() {
        for (name, scheme) in one_of_each_scheme() {
            let json = serde_json::to_value(&scheme).unwrap();
            // ProtoJSON oneof wrapper: exactly ONE key, naming the variant.
            assert_eq!(
                json.as_object().unwrap().len(),
                1,
                "{name}: oneof wrapper must carry exactly one variant: {json}"
            );
            let back: SecurityScheme = serde_json::from_value(json).unwrap();
            assert_eq!(scheme, back, "{name} did not round-trip");
        }
    }

    #[test]
    fn security_scheme_wire_names_match_a2a_proto_oneof() {
        // The wire key is the proto FIELD name in lowerCamelCase — pinned
        // per variant so a rename never silently breaks interop.
        let expected = [
            "apiKeySecurityScheme",
            "httpAuthSecurityScheme",
            "oauth2SecurityScheme",
            "openIdConnectSecurityScheme",
            "mtlsSecurityScheme",
        ];
        for ((name, scheme), key) in one_of_each_scheme().into_iter().zip(expected) {
            let json = serde_json::to_value(&scheme).unwrap();
            assert!(json.get(key).is_some(), "{name}: expected `{key}`: {json}");
        }
        // Spot-check nested ProtoJSON field names (§8.5 sample card shape).
        let oidc = serde_json::to_value(&one_of_each_scheme()[3].1).unwrap();
        assert!(oidc["openIdConnectSecurityScheme"]["openIdConnectUrl"].is_string());
        let oauth = serde_json::to_value(&one_of_each_scheme()[2].1).unwrap();
        let flow = &oauth["oauth2SecurityScheme"]["flows"]["authorizationCode"];
        assert!(flow["authorizationUrl"].is_string());
        assert!(flow["tokenUrl"].is_string());
        assert_eq!(flow["pkceRequired"], serde_json::json!(true));
    }

    #[test]
    fn each_oauth_flow_variant_round_trips() {
        let flows = vec![
            OAuthFlows::AuthorizationCode(AuthorizationCodeOAuthFlow {
                authorization_url: "https://auth.example.com/authorize".to_string(),
                token_url: "https://auth.example.com/token".to_string(),
                refresh_url: "https://auth.example.com/refresh".to_string(),
                scopes: BTreeMap::new(),
                pkce_required: false,
            }),
            OAuthFlows::ClientCredentials(ClientCredentialsOAuthFlow {
                token_url: "https://auth.example.com/token".to_string(),
                refresh_url: String::new(),
                scopes: BTreeMap::from([("act".to_string(), "Act".to_string())]),
            }),
            OAuthFlows::Implicit(ImplicitOAuthFlow {
                authorization_url: "https://auth.example.com/authorize".to_string(),
                ..Default::default()
            }),
            OAuthFlows::Password(PasswordOAuthFlow {
                token_url: "https://auth.example.com/token".to_string(),
                ..Default::default()
            }),
            OAuthFlows::DeviceCode(DeviceCodeOAuthFlow {
                device_authorization_url: "https://auth.example.com/device".to_string(),
                token_url: "https://auth.example.com/token".to_string(),
                refresh_url: String::new(),
                scopes: BTreeMap::new(),
            }),
        ];
        for flow in flows {
            let json = serde_json::to_value(&flow).unwrap();
            assert_eq!(json.as_object().unwrap().len(), 1, "{json}");
            let back: OAuthFlows = serde_json::from_value(json).unwrap();
            assert_eq!(flow, back);
        }
    }

    #[test]
    fn two_variant_security_scheme_entry_is_rejected() {
        // A oneof carries AT MOST one field — an entry claiming to be both
        // an API key scheme and an mTLS scheme is malformed and must not
        // parse (previously it rode along as opaque JSON and got signed).
        let json = serde_json::json!({
            "apiKeySecurityScheme": {"location": "header", "name": "X-Api-Key"},
            "mtlsSecurityScheme": {}
        });
        assert!(serde_json::from_value::<SecurityScheme>(json).is_err());
    }

    #[test]
    fn v0_type_discriminated_scheme_is_rejected() {
        // A2A v0.x used an OpenAPI-style `"type"` discriminator. v1.0's
        // ProtoJSON carries the variant as the wrapper's field name
        // instead, so the stale shape must fail to parse.
        for stale in [
            serde_json::json!({"type": "oauth2"}),
            serde_json::json!({"type": "apiKey", "in": "header", "name": "X-Api-Key"}),
            serde_json::json!({"type": "openIdConnect", "openIdConnectUrl": "https://x"}),
        ] {
            assert!(
                serde_json::from_value::<SecurityScheme>(stale.clone()).is_err(),
                "v0.x shape must be rejected: {stale}"
            );
        }
    }

    #[test]
    fn oauth2_scheme_missing_required_flows_is_rejected() {
        // `flows` is REQUIRED on OAuth2SecurityScheme — an oauth2 scheme
        // that does not say which flow to run is undiscoverable per §7.3.
        let json = serde_json::json!({
            "oauth2SecurityScheme": {"description": "no flows declared"}
        });
        let err = serde_json::from_value::<SecurityScheme>(json).unwrap_err();
        assert!(err.to_string().contains("flows"), "{err}");
    }

    #[test]
    fn required_scheme_subfields_are_presence_checked() {
        // One missing REQUIRED subfield per variant that has any.
        for (name, bad) in [
            (
                "apiKey missing name",
                serde_json::json!({"apiKeySecurityScheme": {"location": "header"}}),
            ),
            (
                "apiKey missing location",
                serde_json::json!({"apiKeySecurityScheme": {"name": "X-Api-Key"}}),
            ),
            (
                "http missing scheme",
                serde_json::json!({"httpAuthSecurityScheme": {"bearerFormat": "JWT"}}),
            ),
            (
                "oidc missing url",
                serde_json::json!({"openIdConnectSecurityScheme": {"description": "x"}}),
            ),
            (
                "authorizationCode flow missing tokenUrl",
                serde_json::json!({"oauth2SecurityScheme": {"flows": {"authorizationCode": {
                    "authorizationUrl": "https://a", "scopes": {}
                }}}}),
            ),
            (
                "deviceCode flow missing deviceAuthorizationUrl",
                serde_json::json!({"oauth2SecurityScheme": {"flows": {"deviceCode": {
                    "tokenUrl": "https://t", "scopes": {}
                }}}}),
            ),
            (
                "clientCredentials flow missing scopes",
                serde_json::json!({"oauth2SecurityScheme": {"flows": {"clientCredentials": {
                    "tokenUrl": "https://t"
                }}}}),
            ),
        ] {
            assert!(
                serde_json::from_value::<SecurityScheme>(bad.clone()).is_err(),
                "{name} must be rejected: {bad}"
            );
        }
    }

    #[test]
    fn unknown_fields_inside_a_variant_are_tolerated() {
        // Forward-compat: a newer producer may add fields to a scheme
        // MESSAGE (allowed by proto evolution); the oneof WRAPPER itself
        // stays single-key. Same posture as the card-level test below.
        let json = serde_json::json!({
            "apiKeySecurityScheme": {
                "location": "header",
                "name": "X-Api-Key",
                "futureFieldWeDontKnow": true
            }
        });
        let scheme: SecurityScheme = serde_json::from_value(json).unwrap();
        assert!(matches!(scheme, SecurityScheme::ApiKey(ref s) if s.name == "X-Api-Key"));
    }

    #[test]
    fn populated_security_schemes_round_trip_on_the_card() {
        let mut card = sample_card();
        card.security_schemes = one_of_each_scheme()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let json = serde_json::to_string(&card).unwrap();
        let back: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(card.security_schemes, back.security_schemes);
        // §8.5 sample-card shape: map key → single-variant wrapper object.
        let value = serde_json::to_value(&card).unwrap();
        assert!(
            value["securitySchemes"]["oidc"]["openIdConnectSecurityScheme"]["openIdConnectUrl"]
                .is_string()
        );
    }

    #[test]
    fn signed_card_serde_round_trip() {
        let mut card = sample_card();
        card.signatures = vec![AgentCardSignature {
            protected: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpPU0UiLCJraWQiOiJrZXktMSJ9".to_string(),
            signature: "c2lnbmF0dXJl".to_string(),
            header: Some(serde_json::json!({"hint": "rotation-2026"})),
        }];
        let json = serde_json::to_string(&card).unwrap();
        let back: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(
            serde_json::to_value(&card).unwrap(),
            serde_json::to_value(&back).unwrap()
        );
        assert_eq!(back.signatures.len(), 1);
    }

    #[test]
    fn unknown_fields_are_ignored_forward_compat() {
        // A newer producer adds a field this verifier doesn't model.
        let json = serde_json::json!({
            "name": "Future Agent",
            "description": "from a newer producer",
            "supportedInterfaces": [
                {"url": "https://x.example.com/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.1"}
            ],
            "version": "2.0.0",
            "capabilities": {},
            "defaultInputModes": ["application/json"],
            "defaultOutputModes": ["application/json"],
            "skills": [],
            "future_field_we_dont_know": {"nested": true}
        });
        let card: AgentCard = serde_json::from_value(json).unwrap();
        assert_eq!(card.name, "Future Agent");
    }
}
