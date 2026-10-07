//! The Rust half: a `syn` symbol table of each crate's functions, and what a harness or test
//! body says. Nothing here matches text; every answer comes from a parsed item.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use quote::ToTokens;
use sha2::{Digest, Sha256};
use syn::visit::Visit;

/// Where a function is defined, and what its definition hashes to.
#[derive(Debug, Clone)]
pub struct FnSite {
    /// The source file, relative to the repository root.
    pub file: PathBuf,
    /// Defined under `#[cfg(test)]`/`#[cfg(kani)]`, or itself a test or harness.
    pub test_only: bool,
    /// SHA-256 of the signature and body tokens (comments and attributes are not tokens of
    /// either, so a doc edit does not move it; any edit to the code does).
    pub hash: String,
}

/// Every workspace crate, by its Rust name (`portcullis-core` → `portcullis_core`), with the
/// file its library (or binary) root is.
///
/// The population is the workspace's explicit `members` array, read as TOML — not a
/// directory walk, which would count whatever happens to be lying in the tree.
pub fn crate_roots(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let manifest: toml::Value = toml::from_str(
        &std::fs::read_to_string(root.join("Cargo.toml")).context("reading root Cargo.toml")?,
    )
    .context("parsing root Cargo.toml")?;
    let members = manifest["workspace"]["members"]
        .as_array()
        .context("root Cargo.toml has no [workspace] members array")?;
    let mut out = BTreeMap::new();
    for member in members {
        let dir = member
            .as_str()
            .context("a workspace member is not a string")?;
        let text = std::fs::read_to_string(root.join(dir).join("Cargo.toml"))
            .with_context(|| format!("reading {dir}/Cargo.toml"))?;
        let crate_manifest: toml::Value =
            toml::from_str(&text).with_context(|| format!("parsing {dir}/Cargo.toml"))?;
        let name = crate_manifest["package"]["name"]
            .as_str()
            .with_context(|| format!("{dir}/Cargo.toml: package name is not explicit"))?
            .replace('-', "_");
        let lib = match crate_manifest.get("lib").and_then(|l| l.get("path")) {
            Some(p) => Some(
                PathBuf::from(dir).join(
                    p.as_str()
                        .with_context(|| format!("{dir}: [lib] path is not a string"))?,
                ),
            ),
            None => ["src/lib.rs", "src/main.rs"]
                .iter()
                .map(|f| PathBuf::from(dir).join(f))
                .find(|f| root.join(f).is_file()),
        };
        if let Some(lib) = lib {
            out.insert(name, lib);
        }
    }
    if out.is_empty() {
        bail!("the workspace declares no crate with a library or binary root");
    }
    Ok(out)
}

fn has_attr(attrs: &[syn::Attribute], last: &str) -> bool {
    attrs.iter().any(|a| {
        a.path()
            .segments
            .last()
            .is_some_and(|s| s.ident == last && a.path().segments.len() <= 2)
    })
}

/// `#[cfg(test)]` or `#[cfg(kani)]` (alone; a `cfg(any(test, …))` is not test-only).
fn test_cfg(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.parse_args::<syn::Ident>()
                .is_ok_and(|i| i == "test" || i == "kani")
    })
}

fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|a| {
        if a.path().is_ident("path")
            && let syn::Meta::NameValue(v) = &a.meta
            && let syn::Expr::Lit(v) = &v.value
            && let syn::Lit::Str(s) = &v.lit
        {
            Some(s.value())
        } else {
            None
        }
    })
}

fn digest(sig: &syn::Signature, block: &syn::Block) -> String {
    let mut h = Sha256::new();
    h.update(sig.to_token_stream().to_string());
    h.update(block.to_token_stream().to_string());
    hex::encode(h.finalize())
}

/// The last identifier of a type path: `crate::m::Ledger<T>` → `Ledger`.
fn type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

struct Walker<'a> {
    root: &'a Path,
    out: BTreeMap<String, FnSite>,
}

impl Walker<'_> {
    fn insert(&mut self, key: String, file: &Path, test_only: bool, hash: String) {
        self.out.insert(
            key,
            FnSite {
                file: file.to_path_buf(),
                test_only,
                hash,
            },
        );
    }

    /// Walk `items`, the content of module `module` defined in `file`. `children` is the
    /// directory a `mod x;` here resolves in; `#[path]` resolves against `file`'s directory.
    fn items(
        &mut self,
        items: &[syn::Item],
        module: &str,
        file: &Path,
        children: &Path,
        test_only: bool,
    ) -> Result<()> {
        for item in items {
            match item {
                syn::Item::Fn(f) => {
                    let t = test_only
                        || test_cfg(&f.attrs)
                        || has_attr(&f.attrs, "test")
                        || has_attr(&f.attrs, "proof");
                    self.insert(
                        format!("{module}::{}", f.sig.ident),
                        file,
                        t,
                        digest(&f.sig, &f.block),
                    );
                }
                syn::Item::Impl(i) => {
                    let Some(ty) = type_name(&i.self_ty) else {
                        continue;
                    };
                    let t = test_only || test_cfg(&i.attrs);
                    for member in &i.items {
                        if let syn::ImplItem::Fn(m) = member {
                            self.insert(
                                format!("{module}::{ty}::{}", m.sig.ident),
                                file,
                                t || test_cfg(&m.attrs),
                                digest(&m.sig, &m.block),
                            );
                        }
                    }
                }
                syn::Item::Trait(tr) => {
                    for member in &tr.items {
                        if let syn::TraitItem::Fn(m) = member
                            && let Some(body) = &m.default
                        {
                            self.insert(
                                format!("{module}::{}::{}", tr.ident, m.sig.ident),
                                file,
                                test_only || test_cfg(&tr.attrs),
                                digest(&m.sig, body),
                            );
                        }
                    }
                }
                syn::Item::Mod(m) => {
                    let name = m.ident.to_string();
                    let sub = format!("{module}::{name}");
                    let t = test_only || test_cfg(&m.attrs);
                    match &m.content {
                        Some((_, inner)) => {
                            self.items(inner, &sub, file, &children.join(&name), t)?;
                        }
                        None => {
                            let dir = file.parent().context("a source file has no parent")?;
                            let target = match path_attr(&m.attrs) {
                                Some(p) => Some(dir.join(p)),
                                None => [
                                    children.join(format!("{name}.rs")),
                                    children.join(&name).join("mod.rs"),
                                ]
                                .into_iter()
                                .find(|p| self.root.join(p).is_file()),
                            };
                            // A module whose file is absent (a cfg'd platform file, a build
                            // output) contributes no symbols; a row naming one fails as
                            // "no longer exists", never as present.
                            if let Some(target) = target.filter(|p| self.root.join(p).is_file()) {
                                let next = if target.file_name().is_some_and(|f| f == "mod.rs")
                                    || path_attr(&m.attrs).is_some()
                                {
                                    target.parent().map(Path::to_path_buf)
                                } else {
                                    Some(children.join(&name))
                                }
                                .context("a module file has no parent")?;
                                self.file(&target, &sub, &next, t)?;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn file(&mut self, file: &Path, module: &str, children: &Path, test_only: bool) -> Result<()> {
        let text = std::fs::read_to_string(self.root.join(file))
            .with_context(|| format!("reading {}", file.display()))?;
        let ast = syn::parse_file(&text).with_context(|| format!("parsing {}", file.display()))?;
        self.items(&ast.items, module, file, children, test_only)
    }
}

/// Every function a crate defines, keyed `crate::module::fn` or `crate::module::Type::fn`,
/// reached by following its module tree from the crate root.
pub fn crate_symbols(root: &Path, krate: &str, lib: &Path) -> Result<BTreeMap<String, FnSite>> {
    let mut walker = Walker {
        root,
        out: BTreeMap::new(),
    };
    let children = lib.parent().context("crate root has no parent")?;
    walker.file(lib, krate, children, false)?;
    if walker.out.is_empty() {
        bail!(
            "{krate}: the module walk from {} found no function",
            lib.display()
        );
    }
    Ok(walker.out)
}

/// Lazily-built symbol tables, one per crate a row names.
pub struct Symbols<'a> {
    root: &'a Path,
    crates: BTreeMap<String, PathBuf>,
    tables: BTreeMap<String, BTreeMap<String, FnSite>>,
}

impl<'a> Symbols<'a> {
    pub fn new(root: &'a Path) -> Result<Self> {
        Ok(Self {
            root,
            crates: crate_roots(root)?,
            tables: BTreeMap::new(),
        })
    }

    /// The crate's table. A crate that is not a workspace member is an error, not an empty
    /// table: "could not look" is not "looked and found nothing" (ADR 0007 A-2).
    pub fn table(&mut self, krate: &str) -> Result<&BTreeMap<String, FnSite>> {
        if !self.tables.contains_key(krate) {
            let lib = self
                .crates
                .get(krate)
                .ok_or_else(|| anyhow!("`{krate}` is not a workspace crate"))?;
            let table = crate_symbols(self.root, krate, lib)?;
            self.tables.insert(krate.to_string(), table);
        }
        self.tables
            .get(krate)
            .ok_or_else(|| anyhow!("`{krate}`: symbol table missing after build"))
    }

    /// The definition of `function` (`crate::path::to::fn`), if it exists.
    pub fn resolve(&mut self, function: &str) -> Result<Option<FnSite>> {
        let krate = function
            .split("::")
            .next()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| anyhow!("`{function}` does not start with a crate name"))?;
        Ok(self.table(krate)?.get(function).cloned())
    }
}

/// A harness or test function found by name in a file, with every identifier its body uses.
pub struct Body {
    /// Identifiers called, named as a path, or used as a method (and those inside macro
    /// arguments, which `syn` keeps as tokens).
    pub idents: BTreeSet<String>,
    /// The final statement is `kani::cover!(…)`, and the condition it states is not the
    /// literal `false`.
    pub ends_with_cover: Cover,
    /// Carries the `kani::proof` attribute.
    pub kani: bool,
    /// Carries a `#[test]`-like attribute (`#[test]`, `#[tokio::test]`, …).
    pub test: bool,
}

/// How a body ends, as far as `kani::cover!` goes.
#[derive(Debug, PartialEq, Eq)]
pub enum Cover {
    /// The last statement is `kani::cover!` over a condition that can hold.
    Terminal,
    /// The last statement is `kani::cover!(false …)`: a cover that can never be satisfied.
    Unsatisfiable,
    /// The last statement is something else (or the body is empty).
    Absent,
}

#[derive(Default)]
struct Idents(BTreeSet<String>);

impl Idents {
    fn tokens(&mut self, ts: proc_macro2::TokenStream) {
        for tt in ts {
            match tt {
                proc_macro2::TokenTree::Ident(i) => {
                    self.0.insert(i.to_string());
                }
                proc_macro2::TokenTree::Group(g) => self.tokens(g.stream()),
                _ => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Idents {
    fn visit_path(&mut self, p: &'ast syn::Path) {
        for s in &p.segments {
            self.0.insert(s.ident.to_string());
        }
        syn::visit::visit_path(self, p);
    }
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        self.0.insert(m.method.to_string());
        syn::visit::visit_expr_method_call(self, m);
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        self.tokens(m.tokens.clone());
        syn::visit::visit_macro(self, m);
    }
}

fn is_kani_cover(mac: &syn::Macro) -> bool {
    let segs: Vec<String> = mac
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    segs == ["kani", "cover"]
}

fn cover_of(block: &syn::Block) -> Cover {
    let mac = match block.stmts.last() {
        Some(syn::Stmt::Macro(m)) => &m.mac,
        Some(syn::Stmt::Expr(syn::Expr::Macro(m), _)) => &m.mac,
        _ => return Cover::Absent,
    };
    if !is_kani_cover(mac) {
        return Cover::Absent;
    }
    let first = mac.tokens.clone().into_iter().next();
    match first {
        Some(proc_macro2::TokenTree::Ident(i)) if i == "false" => Cover::Unsatisfiable,
        _ => Cover::Terminal,
    }
}

struct FindFn<'n> {
    name: &'n str,
    found: Vec<Body>,
}

impl FindFn<'_> {
    fn record(&mut self, attrs: &[syn::Attribute], block: &syn::Block) {
        let mut idents = Idents::default();
        idents.visit_block(block);
        let kani = attrs.iter().any(|a| {
            let segs: Vec<String> = a
                .path()
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            segs == ["kani", "proof"] || segs == ["kani", "proof_for_contract"]
        });
        self.found.push(Body {
            idents: idents.0,
            ends_with_cover: cover_of(block),
            kani,
            test: has_attr(attrs, "test"),
        });
    }
}

impl<'ast> Visit<'ast> for FindFn<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.sig.ident == self.name {
            self.record(&f.attrs, &f.block);
        }
        syn::visit::visit_item_fn(self, f);
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if f.sig.ident == self.name {
            self.record(&f.attrs, &f.block);
        }
        syn::visit::visit_impl_item_fn(self, f);
    }
}

/// Every function named `name` in `file` (nested modules included).
pub fn bodies(root: &Path, file: &Path, name: &str) -> Result<Vec<Body>> {
    let text = std::fs::read_to_string(root.join(file))
        .with_context(|| format!("reading {}", file.display()))?;
    let ast = syn::parse_file(&text).with_context(|| format!("parsing {}", file.display()))?;
    let mut finder = FindFn {
        name,
        found: Vec::new(),
    };
    finder.visit_file(&ast);
    Ok(finder.found)
}

/// The last `::` segment of a function path: what a body has to name to reach it.
pub fn leaf(function: &str) -> &str {
    function.rsplit("::").next().unwrap_or(function)
}
