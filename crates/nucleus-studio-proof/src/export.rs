//! Bind an exported theorem's exact type to the supplied contract packet.
//! The semantic prefix is pinned; an unrelated valid theorem cannot substitute.
use crate::{
    Packet,
    codec::{self, Shape},
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub const BASE_SHA256: &str = "f4951fc8d0a41899554782c069926033c6219532d200b855f43fb16fb589759f";
pub const MAX_BASE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = MAX_BASE_BYTES + crate::MAX_PACKET_BYTES;

/// Only `verify` mints this evidence. It establishes the bounded contract
/// decision, not the host's enrollment, live storage or human intent.
#[derive(Debug, Serialize)]
pub struct VerifiedContract {
    packet_sha256: String,
    proof_sha256: String,
    declaration_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Expr {
    Other,
    App(usize, usize),
    Const(usize, Vec<usize>),
    Text(String),
    Nat(u64),
}
pub(crate) struct Export {
    pub(crate) names: Vec<String>,
    pub(crate) exprs: Vec<Expr>,
    accepted: Option<usize>,
    pub(crate) level_one: Option<usize>,
}

fn index(v: &Value) -> Result<usize, String> {
    let n = v.as_u64().ok_or("export index missing")?;
    let n = usize::try_from(n).map_err(|_| "export index overflow")?;
    if n > 1_000_000 {
        return Err("export index budget".into());
    }
    Ok(n)
}
impl Export {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut out = Self {
            names: vec![String::new()],
            exprs: vec![],
            accepted: None,
            level_one: None,
        };
        for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let item: Value =
                serde_json::from_slice(line).map_err(|e| format!("export row: {e}"))?;
            if item.get("succ").and_then(Value::as_u64) == Some(0) && item.get("il").is_some() {
                out.level_one = Some(index(&item["il"])?);
            }
            if let Some(id) = item.get("in") {
                let id = index(id)?;
                if id != out.names.len() {
                    return Err("nonsequential name index".into());
                }
                let (prefix, segment) = if let Some(s) = item.get("str") {
                    (
                        index(&s["pre"])?,
                        s["str"].as_str().ok_or("name segment missing")?.to_owned(),
                    )
                } else if let Some(n) = item.get("num") {
                    (
                        index(&n["pre"])?,
                        n["i"].as_u64().ok_or("numeric name missing")?.to_string(),
                    )
                } else {
                    return Err("unknown name encoding".into());
                };
                let parent = out.names.get(prefix).ok_or("name prefix missing")?;
                out.names.push(if parent.is_empty() {
                    segment
                } else {
                    format!("{parent}.{segment}")
                });
            }
            if let Some(id) = item.get("ie") {
                let id = index(id)?;
                if id != out.exprs.len() {
                    return Err("nonsequential expression index".into());
                }
                let expr = if let Some(app) = item.get("app") {
                    Expr::App(index(&app["fn"])?, index(&app["arg"])?)
                } else if let Some(c) = item.get("const") {
                    Expr::Const(
                        index(&c["name"])?,
                        c["us"]
                            .as_array()
                            .ok_or("universe levels missing")?
                            .iter()
                            .map(index)
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                } else if let Some(s) = item.get("strVal") {
                    Expr::Text(s.as_str().ok_or("string literal missing")?.into())
                } else if let Some(n) = item.get("natVal") {
                    Expr::Nat(
                        n.as_str()
                            .ok_or("natural literal missing")?
                            .parse()
                            .map_err(|_| "natural literal overflow")?,
                    )
                } else {
                    Expr::Other
                };
                out.exprs.push(expr);
            }
            if let Some(thm) = item.get("thm")
                && out.names.get(index(&thm["name"])?)
                    == Some(&"StudioCertificateWitness.accepted".to_owned())
            {
                if out.accepted.is_some() {
                    return Err("duplicate decision theorem".into());
                }
                out.accepted = Some(index(&thm["type"])?);
            }
        }
        Ok(out)
    }
    fn expression(&self, id: usize) -> Result<&Expr, String> {
        self.exprs
            .get(id)
            .ok_or_else(|| "expression missing".into())
    }
    fn call(&self, mut id: usize) -> Result<(&str, Vec<usize>), String> {
        let mut args = vec![];
        while let Expr::App(function, argument) = self.expression(id)? {
            if args.len() > 16 || *function >= id || *argument >= id {
                return Err("nonliteral application".into());
            }
            args.push(*argument);
            id = *function;
        }
        let Expr::Const(name, _) = self.expression(id)? else {
            return Err("constructor constant required".into());
        };
        args.reverse();
        Ok((self.names.get(*name).ok_or("constant name missing")?, args))
    }
    fn exact_call(&self, id: usize, name: &str, arity: usize) -> Result<Vec<usize>, String> {
        let (found, args) = self.call(id)?;
        if found != name || args.len() != arity {
            return Err(format!(
                "expected {name}/{arity}, got {found}/{}",
                args.len()
            ));
        }
        Ok(args)
    }
    fn literal(&self, ty: &str, id: usize, depth: usize) -> Result<Value, String> {
        if depth > 256 {
            return Err("literal nesting budget".into());
        }
        if ty == "String" {
            return match self.expression(id)? {
                Expr::Text(s) => Ok(json!(s)),
                _ => Err("literal string required".into()),
            };
        }
        if ty == "Nat" {
            if let Expr::Nat(n) = self.expression(id)? {
                return Ok(json!(n));
            }
            let number = self.exact_call(id, "OfNat.ofNat", 3)?;
            self.exact_call(number[0], "Nat", 0)?;
            let instance = self.exact_call(number[2], "instOfNatNat", 1)?;
            if number[1] != instance[0] {
                return Err("natural instance differs".into());
            }
            return match self.expression(number[1])? {
                Expr::Nat(n) => Ok(json!(n)),
                _ => Err("natural literal required".into()),
            };
        }
        let (constructor, args) = self.call(id)?;
        if ty == "Bool" {
            return match (constructor, args.as_slice()) {
                ("Bool.true", []) => Ok(json!(true)),
                ("Bool.false", []) => Ok(json!(false)),
                _ => Err("literal boolean required".into()),
            };
        }
        if let Some(element) = ty.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
            let mut list = vec![];
            let mut cursor = id;
            loop {
                let (head, items) = self.call(cursor)?;
                match (head, items.as_slice()) {
                    ("List.nil", [_]) => break,
                    ("List.cons", [_, item, tail]) => {
                        if list.len() >= 4096 || *tail >= cursor {
                            return Err("literal list budget/order".into());
                        }
                        list.push(self.literal(element, *item, depth + 1)?);
                        cursor = *tail;
                    }
                    _ => return Err("literal list required".into()),
                }
            }
            return Ok(Value::Array(list));
        }
        if let Some(element) = ty.strip_prefix('?') {
            return match (constructor, args.as_slice()) {
                ("Option.none", [_]) => Ok(Value::Null),
                ("Option.some", [_, item]) => self.literal(element, *item, depth + 1),
                _ => Err("literal option required".into()),
            };
        }
        let (fields, tag) = match codec::shape(ty)? {
            Shape::Record(name, fields) => {
                if constructor != format!("{name}.mk") {
                    return Err(format!("wrong {ty} constructor"));
                }
                (fields, None)
            }
            Shape::Sum(name, variants) => {
                let tag = constructor
                    .strip_prefix(&format!("{name}."))
                    .ok_or("wrong sum constructor")?;
                let fields = variants
                    .iter()
                    .find(|(label, _)| *label == tag)
                    .map(|(_, fields)| *fields)
                    .ok_or("unknown sum constructor")?;
                (fields, Some(tag))
            }
        };
        if fields.len() != args.len() {
            return Err("constructor field count differs".into());
        }
        let mut object = serde_json::Map::new();
        for ((name, kind), value) in fields.iter().zip(args) {
            object.insert((*name).into(), self.literal(kind, value, depth + 1)?);
        }
        Ok(match tag {
            Some(tag) if fields.is_empty() => json!(tag),
            Some(tag) => json!({tag:Value::Object(object)}),
            None => Value::Object(object),
        })
    }
    fn packet(&self) -> Result<Value, String> {
        let eq = self.exact_call(self.accepted.ok_or("decision theorem missing")?, "Eq", 3)?;
        self.exact_call(eq[0], "Bool", 0)?;
        self.exact_call(eq[2], "Bool.true", 0)?;
        let check = self.exact_call(eq[1], "StudioCertificate.checkTyped", 1)?;
        self.literal("TypedPacket", check[0], 0)
    }
}

pub fn verify(base: &[u8], proof: &[u8], packet: &[u8]) -> Result<VerifiedContract, String> {
    if base.len() > MAX_BASE_BYTES || proof.len() > MAX_PROOF_BYTES {
        return Err("proof byte budget".into());
    }
    if hex::encode(Sha256::digest(base)) != BASE_SHA256 {
        return Err("semantic base digest differs".into());
    }
    if !proof.starts_with(base) {
        return Err("proof changed the semantic prefix".into());
    }
    let canonical = crate::canonical_packet(packet)?;
    let input: Packet = serde_json::from_str(&canonical).map_err(|e| format!("packet: {e}"))?;
    let mut expected = crate::typed_packet(&input)?;
    codec::quote("TypedPacket", &expected, 0)?; // validate the exact input wire shape
    for side in ["before", "after"] {
        expected[side]["data"]
            .as_object_mut()
            .ok_or("data object missing")?
            .entry("exclusions")
            .or_insert_with(|| json!([]));
    }
    let statement = Export::parse(proof)?.packet()?;
    if statement != expected {
        return Err("proof statement differs from supplied packet".into());
    }
    let config=serde_json::from_value(json!({
        "export_file_path":null,"use_stdin":false,"permitted_axioms":["propext","Classical.choice","Quot.sound"],
        "unpermitted_axiom_hard_error":true,"unsafe_permit_all_axioms":false,
        "nat_extension":true,"string_extension":true,"num_threads":1,"print_success_message":false
    })).map_err(|e|format!("checker configuration: {e}"))?;
    let count = nanoda_lib::check_export_bytes(proof, config)?;
    Ok(VerifiedContract {
        packet_sha256: hex::encode(Sha256::digest(canonical.as_bytes())),
        proof_sha256: hex::encode(Sha256::digest(proof)),
        declaration_count: count,
    })
}
