//! Conservative recognition of explicitly typed P-256 verification receivers.
//! ECDSA's Verifier is its ordinary strict signature check; verify_strict is an
//! Ed25519 API. Unknown types remain in the historical permissive-call metric.
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::{self, Visit};

#[derive(Default)]
struct Bindings {
    counts: BTreeMap<String, usize>,
    p256: BTreeSet<String>,
    opaque: bool,
}
impl<'ast> Visit<'ast> for Bindings {
    fn visit_pat_ident(&mut self, value: &'ast syn::PatIdent) {
        *self.counts.entry(value.ident.to_string()).or_default() += 1;
        visit::visit_pat_ident(self, value);
    }
    fn visit_pat_type(&mut self, value: &'ast syn::PatType) {
        if let syn::Pat::Ident(binding) = value.pat.as_ref()
            && binding.mutability.is_none()
            && binding.by_ref.is_none()
            && let syn::Type::Path(ty) = value.ty.as_ref()
            && ty.qself.is_none()
            && ty.path.leading_colon.is_some()
            && ty
                .path
                .segments
                .iter()
                .all(|s| matches!(s.arguments, syn::PathArguments::None))
            && ty.path.segments.iter().map(|s| s.ident.to_string()).eq([
                "p256",
                "ecdsa",
                "VerifyingKey",
            ]
            .map(str::to_owned))
        {
            self.p256.insert(binding.ident.to_string());
        }
        visit::visit_pat_type(self, value);
    }
    fn visit_stmt_macro(&mut self, _value: &'ast syn::StmtMacro) {
        self.opaque = true;
    }
    fn visit_item_macro(&mut self, _value: &'ast syn::ItemMacro) {
        self.opaque = true;
    }
}

pub(super) fn explicit_p256(source: &str) -> BTreeSet<String> {
    let Ok(file) = syn::parse_file(source) else {
        return BTreeSet::new();
    };
    let mut bindings = Bindings::default();
    bindings.visit_file(&file);
    if bindings.opaque {
        return BTreeSet::new();
    }
    bindings
        .p256
        .into_iter()
        .filter(|name| bindings.counts.get(name) == Some(&1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_immutable_unshadowed_p256_is_classified() {
        assert!(
            explicit_p256("fn f(pk: ::p256::ecdsa::VerifyingKey) { pk.verify(m, signature); }")
                .contains("pk")
        );
        for source in [
            "fn f(pk: ed25519_dalek::VerifyingKey) { pk.verify(m, signature); }",
            "fn f(pk: VerifyingKey) { pk.verify(m, signature); }",
            "fn f(pk: p256::ecdsa::VerifyingKey) { pk.verify(m, signature); }",
            "fn f(mut pk: ::p256::ecdsa::VerifyingKey) { pk.verify(m, signature); }",
            "fn f(pk: ::p256::ecdsa::VerifyingKey) { let pk = other; pk.verify(m, signature); }",
            "fn f(pk: ::p256::ecdsa::VerifyingKey) {} fn g(pk: Other) { pk.verify(m, signature); }",
            "fn f(pk: ::p256::ecdsa::VerifyingKey) { opaque!(); pk.verify(m, signature); }",
            "fn f(pk: ::p256::ecdsa::VerifyingKey) {",
        ] {
            assert!(
                explicit_p256(source).is_empty(),
                "classified unknown source: {source}"
            );
        }
    }
}
