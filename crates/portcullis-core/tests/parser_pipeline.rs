//! Parser pipeline integration test (#989).
//!
//! Tests the full ParserRegistry → ParserSandbox → WitnessBundle flow
//! using a simple identity parser (WAT compiled at test time).
//!
//! A production jq parser (via jaq-core) is tracked separately.

#[cfg(feature = "wasm-sandbox")]
mod wasm_pipeline {
    use portcullis_core::parser_registry::{ParserDeclaration, ParserRegistry};
    use portcullis_core::wasm_sandbox::ParserSandbox;
    use sha2::{Digest, Sha256};

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Identity parser WAT — copies input to output unchanged.
    /// This is the simplest possible parser for testing the pipeline.
    fn identity_parser_wat() -> &'static str {
        r#"
        (module
            (memory (export "memory") 1)
            (global $bump (mut i32) (i32.const 1024))
            (func (export "alloc") (param $len i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $bump))
                (global.set $bump (i32.add (global.get $bump) (local.get $len)))
                (local.get $ptr))
            (func (export "parse") (param $ptr i32) (param $len i32) (result i64)
                (local $out i32)
                (local.set $out (global.get $bump))
                (global.set $bump (i32.add (global.get $bump) (local.get $len)))
                (memory.copy (local.get $out) (local.get $ptr) (local.get $len))
                (i64.or
                    (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
                    (i64.extend_i32_u (local.get $len))))
        )
        "#
    }

    #[test]
    fn full_parser_pipeline_identity() {
        let wasm_bytes = wat::parse_str(identity_parser_wat()).expect("WAT parse failed");
        let wasm_hash = sha256(&wasm_bytes);

        // 1. Register the parser.
        let mut registry = ParserRegistry::new();
        registry
            .register_parser(ParserDeclaration {
                parser_id: "identity".into(),
                version: "1.0.0".into(),
                build_hash: wasm_hash,
                input_format: "bytes".into(),
                output_schema: "bytes".into(),
                is_deterministic: true,
                ..Default::default()
            })
            .unwrap();

        // 2. Compile through the registry.
        let sandbox = ParserSandbox::new();
        let returned_hash = registry
            .compile_parser(&sandbox, "identity", &wasm_bytes)
            .unwrap();
        assert_eq!(returned_hash, wasm_hash);

        // 3. Execute on test input.
        let input = br#"{"revenue": 383285000000}"#;
        let output = registry
            .execute_parser(&sandbox, "identity", input, 100_000)
            .unwrap();
        assert_eq!(
            output, input,
            "identity parser should return input unchanged"
        );

        // 4. Verify determinism — same input, same output.
        let output2 = registry
            .execute_parser(&sandbox, "identity", input, 100_000)
            .unwrap();
        assert_eq!(output, output2, "parser must be deterministic");

        // 5. Verify hash chain.
        let input_hash = sha256(input);
        let output_hash = sha256(&output);
        assert_eq!(
            input_hash, output_hash,
            "identity parser: input hash = output hash"
        );

        // 6. Build a WitnessBundle with this parser step.
        use portcullis_core::witness::{InputBlob, ParserStep, WitnessBundle};
        use std::collections::BTreeMap;

        let bundle = WitnessBundle {
            witness_id: "wtn_pipeline_test".into(),
            input_blobs: vec![InputBlob {
                source_class: "test".into(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "test".into(),
                raw_content: Some(input.to_vec()),
            }],
            parser_chain: vec![ParserStep {
                parser_id: "identity".into(),
                parser_version: "1.0.0".into(),
                parser_hash: wasm_hash,
                input_hash,
                output_hash,
            }],
            transform_chain: vec![],
            validation_results: vec![],
            final_output_hash: output_hash,
            signature: None,
            created_at: 1000,
            field_witnesses: BTreeMap::new(),
            zkvm_receipt: None,
        };

        assert!(bundle.verify_chain().is_ok());
        assert!(bundle.is_valid());

        // 7. Replay verification — re-execute through sandbox.
        let replay_result = bundle.verify_replay(|parser_id, replay_input| {
            assert_eq!(parser_id, "identity");
            registry
                .execute_parser(&sandbox, parser_id, replay_input, 100_000)
                .map_err(|e| format!("{e}"))
        });
        assert!(
            replay_result.is_ok(),
            "replay should succeed: {replay_result:?}"
        );
    }

    #[test]
    fn parser_tamper_detection() {
        let wasm_bytes = wat::parse_str(identity_parser_wat()).expect("WAT parse failed");
        let wasm_hash = sha256(&wasm_bytes);

        let mut registry = ParserRegistry::new();
        registry
            .register_parser(ParserDeclaration {
                parser_id: "tamper_test".into(),
                version: "1.0.0".into(),
                build_hash: [0xAA; 32], // wrong hash — simulates tampered binary
                input_format: "bytes".into(),
                output_schema: "bytes".into(),
                is_deterministic: true,
                ..Default::default()
            })
            .unwrap();

        let sandbox = ParserSandbox::new();
        let result = registry.compile_parser(&sandbox, "tamper_test", &wasm_bytes);
        assert!(
            result.is_err(),
            "tampered parser binary must be rejected: actual hash {wasm_hash:?}"
        );
    }
}
