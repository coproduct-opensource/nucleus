//! One test per pinned setting. Each was driven red by flipping that one
//! setting in `options()` / `ambiguity()` (A-19); the PR records the table.

use super::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Flag {
    enabled: bool,
}

#[test]
fn yaml_1_1_booleans_are_not_booleans() {
    for word in ["yes", "no", "on", "off", "y", "n", "Yes", "OFF"] {
        let doc = format!("enabled: {word}\n");
        assert!(
            from_str::<Flag>(&doc).is_err(),
            "`enabled: {word}` must not read as a bool"
        );
    }
    assert!(from_str::<Flag>("enabled: true\n").unwrap().enabled);
    assert!(!from_str::<Flag>("enabled: false\n").unwrap().enabled);
}

#[test]
fn yaml_1_1_boolean_words_stay_strings_in_untyped_positions() {
    // A GitHub workflow's `on:` key, and a `yes` value, are strings, as they
    // were under serde_yaml 0.9.
    let v: Value = from_str("on: push\nx: yes\n").unwrap();
    assert_eq!(v, json!({"on": "push", "x": "yes"}));
}

#[test]
fn duplicate_keys_are_refused() {
    assert!(from_str::<Flag>("enabled: true\nenabled: false\n").is_err());
    assert!(from_str::<Value>("a: 1\na: 2\n").is_err());
    assert!(from_str::<BTreeMap<String, String>>("a: x\na: y\n").is_err());
}

#[test]
fn merge_keys_are_refused() {
    let doc = "base: &b\n  enabled: true\nchild:\n  <<: *b\n";
    assert!(from_str::<Value>(doc).is_err());
}

#[test]
fn unknown_tags_are_refused() {
    assert!(from_str::<Value>("x: !Foo 1\n").is_err());
    assert!(from_str::<BTreeMap<String, u32>>("x: !Foo 1\n").is_err());
}

#[test]
fn binary_tags_are_refused() {
    let err = from_str::<BTreeMap<String, String>>("x: !!binary aGk=\n").unwrap_err();
    assert!(matches!(err, Error::BinaryTag { line: 1, .. }), "{err:?}");
}

#[test]
fn errors_do_not_echo_the_input() {
    // A duplicate key next to a credential: the error must name the problem,
    // not print the line holding the secret.
    let doc = "token: test-token-123\ntoken: test-token-456\n";
    let msg = from_str::<Value>(doc).unwrap_err().to_string();
    assert!(!msg.contains("test-token"), "error echoed input: {msg}");
}

#[test]
fn nesting_deeper_than_the_budget_is_refused() {
    let mut doc = String::new();
    for depth in 0..(MAX_DEPTH + 2) {
        doc.push_str(&" ".repeat(depth));
        doc.push_str("k:\n");
    }
    doc.push_str(&" ".repeat(MAX_DEPTH + 2));
    doc.push_str("k: 1\n");
    assert!(from_str::<Value>(&doc).is_err());

    let mut shallow = String::new();
    for depth in 0..8 {
        shallow.push_str(&" ".repeat(depth));
        shallow.push_str("k:\n");
    }
    shallow.push_str(&" ".repeat(8));
    shallow.push_str("k: 1\n");
    assert!(from_str::<Value>(&shallow).is_ok());
}

#[test]
fn oversize_input_is_refused_before_parsing() {
    let doc = "a".repeat(MAX_INPUT_BYTES + 1);
    assert_eq!(
        from_str::<Value>(&doc).unwrap_err(),
        Error::TooLarge {
            len: MAX_INPUT_BYTES + 1
        }
    );
}

#[test]
fn more_than_one_document_is_refused() {
    assert!(from_str::<Value>("a: 1\n---\na: 2\n").is_err());
}

#[test]
fn ambiguous_scalars_are_refused_in_every_target_type() {
    let cases = [
        ("0755", Ambiguity::LeadingZero),
        ("-0755", Ambiguity::LeadingZero),
        ("+007", Ambiguity::LeadingZero),
        ("00", Ambiguity::LeadingZero),
        ("0X1F", Ambiguity::UppercaseRadixPrefix),
        ("0O17", Ambiguity::UppercaseRadixPrefix),
        ("0B101", Ambiguity::UppercaseRadixPrefix),
        ("1_000", Ambiguity::DigitSeparator),
        ("0x_1F", Ambiguity::DigitSeparator),
        ("18446744073709551616", Ambiguity::IntegerOverflow),
        ("-9223372036854775809", Ambiguity::IntegerOverflow),
        ("99999999999999999999999", Ambiguity::IntegerOverflow),
    ];
    for (text, expected) in cases {
        let doc = format!("x: {text}\n");
        for (target, result) in [
            ("Value", from_str::<Value>(&doc).map(|_| ())),
            (
                "String",
                from_str::<BTreeMap<String, String>>(&doc).map(|_| ()),
            ),
        ] {
            match result {
                Err(Error::Ambiguous { ambiguity, .. }) => assert_eq!(ambiguity, expected),
                // A typed target may refuse it for its own reason first; what
                // it may never do is accept it.
                Err(_) if target != "Value" => {}
                other => panic!("`x: {text}` into {target}: {other:?}"),
            }
        }
        // As a key, too.
        assert!(
            from_str::<Value>(&format!("{text}: x\n")).is_err(),
            "`{text}` as a key"
        );
        // Quoted, it is the string it says.
        let quoted: BTreeMap<String, String> = from_str(&format!("x: '{text}'\n")).unwrap();
        assert_eq!(quoted["x"], text);
    }
}

#[test]
fn unambiguous_numbers_read_as_both_libraries_read_them() {
    let v: Value = from_str(
        "a: 0\nb: 755\nc: -1\nd: 0x1F\ne: 0o17\nf: 0b101\ng: 1.5\nh: 1e3\n\
         i: 18446744073709551615\nj: -9223372036854775808\nk: 0.5\n",
    )
    .unwrap();
    assert_eq!(
        v,
        json!({"a": 0, "b": 755, "c": -1, "d": 31, "e": 15, "f": 5, "g": 1.5, "h": 1000.0,
               "i": 18446744073709551615u64, "j": -9223372036854775808i64, "k": 0.5})
    );
}

/// The writer's exact shape, pinned: a change to `ser_options()` or to
/// serde-saphyr's emitter shows up here, not in a pinned guest.
#[test]
fn writer_output_is_pinned() {
    #[derive(Serialize)]
    struct Doc {
        name: &'static str,
        empty: Vec<u32>,
        none: Option<u32>,
        labels: BTreeMap<&'static str, &'static str>,
        items: Vec<&'static str>,
        ratio: f64,
    }
    let doc = Doc {
        name: "pod",
        empty: vec![],
        none: None,
        labels: BTreeMap::from([
            ("a", "plain"),
            ("b", "0755"),
            ("c", "yes"),
            ("d", "line1\nline2\n"),
            ("e", ""),
        ]),
        items: vec!["x", "y"],
        ratio: 0.000001,
    };
    assert_eq!(
        to_string(&doc).unwrap(),
        "name: pod\nempty: []\nnone: null\nlabels:\n  a: plain\n  b: \"0755\"\n  \
         c: \"yes\"\n  d: \"line1\\nline2\\n\"\n  e: \"\"\nitems:\n- x\n- \"y\"\nratio: 1.0e-6\n"
    );
}

#[test]
fn every_string_the_writer_emits_reads_back_unchanged() {
    let tricky = [
        "",
        "yes",
        "no",
        "on",
        "y",
        "true",
        "True",
        "null",
        "~",
        "123",
        "1.5",
        "0755",
        "-0755",
        "0X1F",
        "1_000",
        "18446744073709551616",
        "1e3",
        ".nan",
        ".inf",
        "a: b",
        "a #b",
        " lead",
        "trail ",
        "line1\nline2\n",
        "line1\nline2",
        "- x",
        "*x",
        "&x",
        "!x",
        "%x",
        "@x",
        "`x",
        "? x",
        "| x",
        "> x",
        "[x]",
        "{x}",
        "2001-12-14",
        "1:20",
        "---",
        "...",
        "it's \"q\"",
        "a\tb",
        "a\r\nb",
        "caf\u{e9}",
        "<<",
    ];
    let map: BTreeMap<String, String> = tricky
        .iter()
        .enumerate()
        .map(|(i, s)| (format!("k{i:02}"), (*s).to_string()))
        .collect();
    let text = to_string(&map).unwrap();
    let back: BTreeMap<String, String> = from_str(&text).unwrap();
    assert_eq!(back, map);
    // And as keys.
    let keys: BTreeMap<String, u32> = tricky.iter().map(|s| ((*s).to_string(), 1)).collect();
    let back: BTreeMap<String, u32> = from_str(&to_string(&keys).unwrap()).unwrap();
    assert_eq!(back, keys);
}

#[test]
fn bytes_must_be_utf8() {
    assert_eq!(from_slice::<Value>(b"a: \xff\n"), Err(Error::NotUtf8));
    assert_eq!(from_slice::<Value>(b"a: 1\n").unwrap(), json!({"a": 1}));
}
