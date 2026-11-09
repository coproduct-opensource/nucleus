//! Untrusted certificate construction. A literal `Eq.refl true` is proposed
//! for the closed decision: nanoda must reduce that exact decision to true.
//! No per-app Lean compiler, proof search or authority is involved here.
use crate::{
    codec::{self, Shape},
    export::{self, Export, Expr},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

struct Builder {
    env: Export,
    names: HashMap<String, usize>,
    exprs: HashMap<Expr, usize>,
    delta: Vec<u8>,
}
impl Builder {
    fn new(base: &[u8]) -> Result<Self, String> {
        let env = Export::parse(base)?;
        let names = env
            .names
            .iter()
            .enumerate()
            .map(|(i, name)| (name.clone(), i))
            .collect();
        let exprs = env
            .exprs
            .iter()
            .enumerate()
            .filter(|(_, e)| !matches!(e, Expr::Other))
            .map(|(i, e)| (e.clone(), i))
            .collect();
        Ok(Self {
            env,
            names,
            exprs,
            delta: vec![],
        })
    }
    fn row(&mut self, row: Value) -> Result<(), String> {
        serde_json::to_writer(&mut self.delta, &row).map_err(|e| format!("proof row: {e}"))?;
        self.delta.push(b'\n');
        if self.delta.len() > crate::MAX_PACKET_BYTES {
            return Err("app proof byte budget".into());
        }
        Ok(())
    }
    fn name(&mut self, name: &str) -> Result<usize, String> {
        if let Some(id) = self.names.get(name) {
            return Ok(*id);
        }
        let (prefix, segment) = name.rsplit_once('.').unwrap_or(("", name));
        let prefix = self.name(prefix)?;
        let id = self.env.names.len();
        self.row(json!({"in":id,"str":{"pre":prefix,"str":segment}}))?;
        self.env.names.push(name.into());
        self.names.insert(name.into(), id);
        Ok(id)
    }
    fn expression(&mut self, expr: Expr) -> Result<usize, String> {
        if let Some(id) = self.exprs.get(&expr) {
            return Ok(*id);
        }
        let id = self.env.exprs.len();
        if id > 1_000_000 {
            return Err("expression budget".into());
        }
        let row = match &expr {
            Expr::App(function, argument) => json!({"ie":id,"app":{"fn":function,"arg":argument}}),
            Expr::Const(name, levels) => json!({"ie":id,"const":{"name":name,"us":levels}}),
            Expr::Text(text) => json!({"ie":id,"strVal":text}),
            Expr::Nat(n) => json!({"ie":id,"natVal":n.to_string()}),
            Expr::Other => return Err("unsupported generated expression".into()),
        };
        self.row(row)?;
        self.exprs.insert(expr.clone(), id);
        self.env.exprs.push(expr);
        Ok(id)
    }
    fn constant(&mut self, name: &str, levels: Vec<usize>) -> Result<usize, String> {
        let name = self.name(name)?;
        self.expression(Expr::Const(name, levels))
    }
    fn apply(&mut self, mut function: usize, args: &[usize]) -> Result<usize, String> {
        for arg in args {
            function = self.expression(Expr::App(function, *arg))?;
        }
        Ok(function)
    }
    fn call(&mut self, name: &str, levels: Vec<usize>, args: &[usize]) -> Result<usize, String> {
        let head = self.constant(name, levels)?;
        self.apply(head, args)
    }
    fn kind(&mut self, ty: &str) -> Result<usize, String> {
        if ["String", "Nat", "Bool"].contains(&ty) {
            return self.constant(ty, vec![]);
        }
        if let Some(element) = ty.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let element = self.kind(element)?;
            return self.call("List", vec![0], &[element]);
        }
        if let Some(element) = ty.strip_prefix('?') {
            let element = self.kind(element)?;
            return self.call("Option", vec![0], &[element]);
        }
        let name = match codec::shape(ty)? {
            Shape::Record(name, _) | Shape::Sum(name, _) => name,
        };
        self.constant(name, vec![])
    }
    fn literal(&mut self, ty: &str, value: &Value, depth: usize) -> Result<usize, String> {
        if depth > 256 {
            return Err("literal nesting budget".into());
        }
        if ty == "String" {
            return self.expression(Expr::Text(value.as_str().ok_or("string required")?.into()));
        }
        if ty == "Nat" {
            return self.expression(Expr::Nat(value.as_u64().ok_or("natural required")?));
        }
        if ty == "Bool" {
            return self.constant(
                if value.as_bool().ok_or("boolean required")? {
                    "Bool.true"
                } else {
                    "Bool.false"
                },
                vec![],
            );
        }
        if let Some(element) = ty.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let values = value.as_array().ok_or("list required")?;
            if values.len() > 4096 {
                return Err("literal list budget".into());
            }
            let kind = self.kind(element)?;
            let mut tail = self.call("List.nil", vec![0], &[kind])?;
            for value in values.iter().rev() {
                let head = self.literal(element, value, depth + 1)?;
                tail = self.call("List.cons", vec![0], &[kind, head, tail])?;
            }
            return Ok(tail);
        }
        if let Some(element) = ty.strip_prefix('?') {
            let kind = self.kind(element)?;
            return if value.is_null() {
                self.call("Option.none", vec![0], &[kind])
            } else {
                let item = self.literal(element, value, depth + 1)?;
                self.call("Option.some", vec![0], &[kind, item])
            };
        }
        let (constructor, fields, body) = match codec::shape(ty)? {
            Shape::Record(name, fields) => (
                format!("{name}.mk"),
                fields,
                value.as_object().ok_or("record required")?,
            ),
            Shape::Sum(name, variants) => {
                if let Some(tag) = value.as_str() {
                    if variants
                        .iter()
                        .any(|(label, fields)| *label == tag && fields.is_empty())
                    {
                        return self.constant(&format!("{name}.{tag}"), vec![]);
                    }
                    return Err("unknown nullary constructor".into());
                }
                let body = value.as_object().ok_or("tagged value required")?;
                if body.len() != 1 {
                    return Err("one constructor required".into());
                }
                let (tag, value) = body.iter().next().ok_or("constructor missing")?;
                let fields = variants
                    .iter()
                    .find(|(label, _)| *label == tag)
                    .map(|(_, fields)| *fields)
                    .ok_or("unknown constructor")?;
                (
                    format!("{name}.{tag}"),
                    fields,
                    value.as_object().ok_or("constructor fields required")?,
                )
            }
        };
        let values = codec::fields_value(ty, fields, body)?;
        let args = fields
            .iter()
            .zip(values)
            .map(|((_, ty), v)| self.literal(ty, &v, depth + 1))
            .collect::<Result<Vec<_>, _>>()?;
        self.call(&constructor, vec![], &args)
    }
}

/// Returns untrusted export rows, never a verified certificate. The caller must
/// append them to the pinned base and run the independent checker before use.
pub fn propose_delta(base: &[u8], packet: &[u8]) -> Result<Vec<u8>, String> {
    if base.len() > export::MAX_BASE_BYTES
        || hex::encode(Sha256::digest(base)) != export::BASE_SHA256
    {
        return Err("semantic base differs".into());
    }
    let canonical = crate::canonical_packet(packet)?;
    let packet: crate::Packet =
        serde_json::from_str(&canonical).map_err(|e| format!("packet: {e}"))?;
    let packet = crate::typed_packet(&packet)?;
    let mut builder = Builder::new(base)?;
    let literal = builder.literal("TypedPacket", &packet, 0)?;
    let decision = builder.call("StudioCertificate.checkTyped", vec![], &[literal])?;
    let boolean = builder.constant("Bool", vec![])?;
    let truth = builder.constant("Bool.true", vec![])?;
    let universe = builder.env.level_one.ok_or("universe one missing")?;
    let statement = builder.call("Eq", vec![universe], &[boolean, decision, truth])?;
    let proof = builder.call("Eq.refl", vec![universe], &[boolean, truth])?;
    let name = builder.name("StudioCertificateWitness.accepted")?;
    builder.row(
        json!({"thm":{"name":name,"levelParams":[],"type":statement,"value":proof,"all":[name]}}),
    )?;
    Ok(builder.delta)
}
