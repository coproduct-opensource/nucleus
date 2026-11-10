//! Literal wire codec, not an app compiler. One schema describes both the
//! untrusted producer and the proof statement's typed-value reader (ADR G-1).
use serde_json::{Map, Value};

pub(crate) type Fields = &'static [(&'static str, &'static str)];
pub(crate) enum Shape {
    Record(&'static str, Fields),
    Sum(&'static str, &'static [(&'static str, Fields)]),
}

pub(crate) fn shape(ty: &str) -> Result<Shape, String> {
    use Shape::{Record as R, Sum as S};
    Ok(match ty {
        "Scalar" => S(
            "StudioTyped.Scalar",
            &[
                ("text", &[("value", "String")]),
                ("natural", &[("value", "Nat")]),
                ("boolean", &[("value", "Bool")]),
            ],
        ),
        "Field" => R(
            "StudioTyped.Field",
            &[("name", "String"), ("kind", "String")],
        ),
        "Object" => R(
            "StudioTyped.Object",
            &[("name", "String"), ("fields", "[Field]")],
        ),
        "Arrow" => R(
            "StudioTyped.Arrow",
            &[
                ("name", "String"),
                ("source", "String"),
                ("target", "String"),
            ],
        ),
        "Equation" => R(
            "StudioTyped.Equation",
            &[
                ("source", "String"),
                ("left", "[String]"),
                ("right", "[String]"),
            ],
        ),
        "Schema" => R(
            "StudioTyped.Schema",
            &[
                ("objects", "[Object]"),
                ("arrows", "[Arrow]"),
                ("equations", "[Equation]"),
            ],
        ),
        "Refinement" => S(
            "StudioContracts.Refinement",
            &[
                ("textBounds", &[("minimum", "Nat"), ("maximum", "Nat")]),
                ("naturalBounds", &[("minimum", "Nat"), ("maximum", "Nat")]),
                ("booleanValue", &[("value", "Bool")]),
                ("choice", &[("values", "[String]")]),
                ("inputText", &[("maximum", "Nat"), ("choices", "[String]")]),
                ("inputEmail", &[("maximum", "Nat"), ("choices", "[String]")]),
                ("inputNumber", &[("maximum", "Nat")]),
                ("inputMoney", &[("maximum", "Nat")]),
                ("inputDay", &[("maximum", "Nat")]),
                ("inputTime", &[("maximum", "Nat")]),
            ],
        ),
        "FieldRule" => R(
            "StudioContracts.FieldRule",
            &[
                ("object", "String"),
                ("field", "String"),
                ("refinement", "Refinement"),
            ],
        ),
        "Selector" => S(
            "StudioContracts.Selector",
            &[
                ("field", &[("name", "String")]),
                ("arrow", &[("name", "String")]),
            ],
        ),
        "Key" => R(
            "StudioContracts.Key",
            &[("object", "String"), ("columns", "[Selector]")],
        ),
        "PathField" => R(
            "StudioContracts.PathField",
            &[("path", "[String]"), ("field", "String")],
        ),
        "Comparison" => R(
            "StudioContracts.Comparison",
            &[
                ("object", "String"),
                ("left", "PathField"),
                ("right", "PathField"),
                ("relation", "String"),
            ],
        ),
        "Exclusion" => R(
            "StudioContracts.Exclusion",
            &[
                ("object", "String"),
                ("groups", "[Selector]"),
                ("active", "Selector"),
                ("activeValue", "Scalar"),
                ("start", "PathField"),
                ("finish", "PathField"),
            ],
        ),
        "Data" => R(
            "StudioContracts.Definition",
            &[
                ("schema", "Schema"),
                ("fields", "[FieldRule]"),
                ("keys", "[Key]"),
                ("comparisons", "[Comparison]"),
                ("exclusions", "[Exclusion]"),
            ],
        ),
        "TextMapping" => R(
            "StudioCommands.TextMapping",
            &[("source", "String"), ("target", "String")],
        ),
        "Expr" => S(
            "StudioCommands.Expr",
            &[
                ("literal", &[("value", "Scalar")]),
                ("parameter", &[("name", "String")]),
                ("actor", &[]),
                ("recipient", &[]),
                ("target", &[]),
                ("timestamp", &[]),
                ("sequence", &[]),
                ("sequenceId", &[]),
                ("successor", &[("binding", "String"), ("name", "String")]),
                (
                    "numbered",
                    &[
                        ("stem", "String"),
                        ("binding", "String"),
                        ("name", "String"),
                    ],
                ),
                (
                    "mapText",
                    &[
                        ("binding", "String"),
                        ("name", "String"),
                        ("mapping", "[TextMapping]"),
                    ],
                ),
                (
                    "mapParameter",
                    &[("name", "String"), ("mapping", "[TextMapping]")],
                ),
                (
                    "adjustText",
                    &[
                        ("binding", "String"),
                        ("name", "String"),
                        ("amount", "String"),
                        ("decrease", "String"),
                        ("maximum", "Nat"),
                    ],
                ),
                (
                    "adjustmentLabel",
                    &[
                        ("amount", "String"),
                        ("decrease", "String"),
                        ("maximum", "Nat"),
                    ],
                ),
                ("field", &[("binding", "String"), ("name", "String")]),
                ("link", &[("binding", "String"), ("name", "String")]),
            ],
        ),
        "Guard" => S(
            "StudioCommands.Guard",
            &[
                ("equal", &[("left", "Expr"), ("right", "Expr")]),
                ("different", &[("left", "Expr"), ("right", "Expr")]),
                ("nonblank", &[("value", "Expr")]),
                ("human", &[]),
                ("reviewer", &[]),
                ("countBelow", &[("object", "String"), ("maximum", "Nat")]),
                ("transferAuthorized", &[]),
                ("noRetarget", &[("arrows", "[String]")]),
            ],
        ),
        "Assignment" => R(
            "StudioCommands.Assignment",
            &[("name", "String"), ("value", "Expr")],
        ),
        "RowTemplate" => R(
            "StudioCommands.RowTemplate",
            &[
                ("object", "String"),
                ("id", "Expr"),
                ("cells", "[Assignment]"),
                ("links", "[Assignment]"),
            ],
        ),
        "Instruction" => S(
            "StudioCommands.Instruction",
            &[
                ("require", &[("guard", "Guard")]),
                (
                    "bind",
                    &[("binding", "String"), ("object", "String"), ("id", "Expr")],
                ),
                (
                    "bindUnique",
                    &[
                        ("binding", "String"),
                        ("object", "String"),
                        ("selector", "Selector"),
                        ("value", "Expr"),
                    ],
                ),
                ("insert", &[("row", "RowTemplate")]),
                ("ensure", &[("row", "RowTemplate")]),
                (
                    "update",
                    &[
                        ("binding", "String"),
                        ("cells", "[Assignment]"),
                        ("links", "[Assignment]"),
                    ],
                ),
                ("erase", &[("binding", "String")]),
                (
                    "retainLatest",
                    &[
                        ("object", "String"),
                        ("field", "String"),
                        ("maximum", "Nat"),
                    ],
                ),
                ("collect", &[("object", "String"), ("incoming", "[String]")]),
                (
                    "pruneDangling",
                    &[
                        ("object", "String"),
                        ("arrow", "String"),
                        ("target", "String"),
                    ],
                ),
                (
                    "retargetSubjects",
                    &[
                        ("object", "String"),
                        ("arrow", "String"),
                        ("presence", "?String"),
                    ],
                ),
            ],
        ),
        "Parameter" => R(
            "StudioCommands.Parameter",
            &[("name", "String"), ("kind", "String")],
        ),
        "Program" => R(
            "StudioCommands.Program",
            &[
                ("name", "String"),
                ("parameters", "[Parameter]"),
                ("instructions", "[Instruction]"),
                ("noopIf", "?Guard"),
            ],
        ),
        "CountCase" => R(
            "StudioCommands.CountCase",
            &[("value", "Scalar"), ("count", "Nat")],
        ),
        "CountLaw" => R(
            "StudioCommands.CountLaw",
            &[
                ("source", "String"),
                ("target", "String"),
                ("arrow", "String"),
                ("discriminator", "String"),
                ("cases", "[CountCase]"),
            ],
        ),
        "Column" => R(
            "StudioCommands.Column",
            &[
                ("name", "String"),
                ("label", "String"),
                ("selector", "Selector"),
            ],
        ),
        "View" => R(
            "StudioCommands.View",
            &[
                ("name", "String"),
                ("object", "String"),
                ("columns", "[Column]"),
                ("commands", "[String]"),
            ],
        ),
        "Definition" => R(
            "StudioCommands.Definition",
            &[
                ("data", "Data"),
                ("commands", "[Program]"),
                ("counts", "[CountLaw]"),
                ("views", "[View]"),
            ],
        ),
        "VisibleField" => R(
            "StudioEquipment.VisibleField",
            &[
                ("key", "String"),
                ("label", "String"),
                ("kind", "String"),
                ("choices", "[String]"),
            ],
        ),
        "Visible" => R(
            "StudioEquipment.Visible",
            &[("stem", "String"), ("fields", "[VisibleField]")],
        ),
        "TypedPacket" => R(
            "StudioCertificate.TypedPacket",
            &[
                ("oldVisible", "Visible"),
                ("newVisible", "Visible"),
                ("before", "Definition"),
                ("after", "Definition"),
                ("authorityBefore", "String"),
                ("authorityAfter", "String"),
            ],
        ),
        _ => return Err(format!("unknown literal type {ty}")),
    })
}

pub(crate) fn quote(ty: &str, value: &Value, depth: usize) -> Result<String, String> {
    if depth > 256 {
        return Err("literal nesting limit".into());
    }
    if ty == "String" {
        return value
            .as_str()
            .map(super::lean_string)
            .ok_or_else(|| "string required".into());
    }
    if ty == "Nat" {
        return value
            .as_u64()
            .map(|n| n.to_string())
            .ok_or_else(|| "natural required".into());
    }
    if ty == "Bool" {
        return value
            .as_bool()
            .map(|b| format!("Bool.{b}"))
            .ok_or_else(|| "boolean required".into());
    }
    if let Some(element) = ty.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let array = value.as_array().ok_or("list required")?;
        if array.len() > 4096 {
            return Err("literal list limit".into());
        }
        return Ok(format!(
            "[{}]",
            array
                .iter()
                .map(|v| quote(element, v, depth + 1))
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        ));
    }
    if let Some(element) = ty.strip_prefix('?') {
        return if value.is_null() {
            Ok("none".into())
        } else {
            Ok(format!("(some {})", quote(element, value, depth + 1)?))
        };
    }
    let (constructor, fields, body) = match shape(ty)? {
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
                    return Ok(format!("{name}.{tag}"));
                }
                return Err("unknown nullary constructor".into());
            }
            let object = value.as_object().ok_or("tagged value required")?;
            if object.len() != 1 {
                return Err("one constructor required".into());
            }
            let (tag, body) = object.iter().next().ok_or("constructor missing")?;
            let fields = variants
                .iter()
                .find(|(label, _)| *label == tag)
                .map(|(_, fields)| *fields)
                .ok_or("unknown constructor")?;
            (
                format!("{name}.{tag}"),
                fields,
                body.as_object().ok_or("constructor fields required")?,
            )
        }
    };
    let values = fields_value(ty, fields, body)?;
    let args = fields
        .iter()
        .zip(values)
        .map(|((_, ty), value)| quote(ty, &value, depth + 1))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!("({constructor} {})", args.join(" ")))
}

pub(crate) fn fields_value(
    ty: &str,
    fields: Fields,
    body: &Map<String, Value>,
) -> Result<Vec<Value>, String> {
    if body
        .keys()
        .any(|key| !fields.iter().any(|(name, _)| key == name))
    {
        return Err(format!("unknown {ty} field"));
    }
    fields
        .iter()
        .map(|(name, _)| match body.get(*name) {
            Some(value) => Ok(value.clone()),
            None if ty == "Data" && *name == "exclusions" => Ok(Value::Array(vec![])),
            None => Err(format!("{ty}.{name} missing")),
        })
        .collect()
}
