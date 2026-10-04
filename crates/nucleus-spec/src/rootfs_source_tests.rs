use super::*;

const D_OCI: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const D_MANIFEST: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const D_LAYER: &str = "sha-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const D_ROOTFS: &str = "sha-256:2222222222222222222222222222222222222222222222222222222222222222";

/// Captured from `ImageSpec` BEFORE `RootfsSource` existed (2026-09-29, main at the branch point):
/// the exact bytes `serde_json::to_string` produced for this spec. Every null is there because
/// the old type serialized absent options as `null`, and the wire must keep doing so.
const OLD_JSON: &str = r#"{"kernel_path":"/k","rootfs_path":"/r","boot_args":"console=ttyS0","read_only":true,"scratch_path":null,"kernel_digest":"sha-256:1111111111111111111111111111111111111111111111111111111111111111","rootfs_digest":"sha-256:2222222222222222222222222222222222222222222222222222222222222222","scratch_digest":null,"data_path":null,"data_digest":null}"#;

/// The same capture, through `serde_yaml`.
const OLD_YAML: &str = "kernel_path: /k\nrootfs_path: /r\nboot_args: console=ttyS0\nread_only: true\nscratch_path: null\nkernel_digest: sha-256:1111111111111111111111111111111111111111111111111111111111111111\nrootfs_digest: sha-256:2222222222222222222222222222222222222222222222222222222222222222\nscratch_digest: null\ndata_path: null\ndata_digest: null\n";

fn image(json: &str) -> Result<ImageSpec, String> {
    serde_json::from_str::<ImageSpec>(json).map_err(|e| e.to_string())
}

fn oci_json(reference: &str, extra: &str) -> String {
    format!(
        r#"{{"kernel_path":"/k",
             "rootfs_oci":{{"reference":"{reference}","manifest_digest":"{D_MANIFEST}",
                           "guest_layer_digest":"{D_LAYER}"}},
             "rootfs_digest":"{D_ROOTFS}"{extra}}}"#
    )
}

fn reference(tail: &str) -> String {
    format!("registry.example/team/app{tail}@{D_OCI}")
}

#[test]
fn an_existing_path_spec_serializes_byte_identically() {
    let from_json = image(OLD_JSON).expect("an existing spec parses unchanged");
    assert_eq!(
        from_json.rootfs,
        RootfsSource::Path(PathBuf::from("/r")),
        "the old key lands in the Path case"
    );
    assert_eq!(serde_json::to_string(&from_json).unwrap(), OLD_JSON);

    let from_yaml: ImageSpec = serde_yaml::from_str(OLD_YAML).expect("old YAML parses");
    assert_eq!(serde_yaml::to_string(&from_yaml).unwrap(), OLD_YAML);
}

#[test]
fn a_minimal_path_spec_still_parses_with_its_defaults() {
    let spec = image(r#"{"kernel_path":"/k","rootfs_path":"/r"}"#).expect("parses");
    assert_eq!(spec.rootfs, RootfsSource::Path(PathBuf::from("/r")));
    assert!(spec.read_only, "#2784: omission still means read-only");
}

#[test]
fn an_oci_spec_round_trips() {
    let json = oci_json(&reference(":v1"), "");
    let spec = image(&json).expect("a pinned OCI rootfs parses");
    let RootfsSource::Oci(oci) = &spec.rootfs else {
        panic!("expected the Oci case, got {:?}", spec.rootfs);
    };
    assert_eq!(oci.reference.registry(), "registry.example");
    assert_eq!(oci.reference.repository(), "team/app");
    assert_eq!(oci.reference.tag(), Some("v1"));
    assert_eq!(oci.reference.digest().as_str(), D_OCI);
    let text = serde_json::to_string(&spec).unwrap();
    assert!(
        !text.contains("rootfs_path"),
        "an absent key is skipped: {text}"
    );
    let again = image(&text).expect("re-parses");
    assert_eq!(again.rootfs, spec.rootfs);
}

/// The A-19 subject: with the exactly-one check removed, this is the test that goes red.
#[test]
fn both_rootfs_keys_are_refused() {
    let json = format!(
        r#"{{"kernel_path":"/k","rootfs_path":"/r",
             "rootfs_oci":{{"reference":"{}","manifest_digest":"{D_MANIFEST}",
                           "guest_layer_digest":"{D_LAYER}"}},
             "rootfs_digest":"{D_ROOTFS}"}}"#,
        reference("")
    );
    let err = image(&json).expect_err("both is not a rootfs");
    assert!(err.contains("exactly one"), "{err}");
}

#[test]
fn neither_rootfs_key_is_refused() {
    let err = image(r#"{"kernel_path":"/k"}"#).expect_err("neither is not a rootfs");
    assert!(err.contains("no root filesystem"), "{err}");
}

#[test]
fn unknown_keys_are_still_refused() {
    let err = image(r#"{"kernel_path":"/k","rootfs_path":"/r","rootfs_pth":"/x"}"#)
        .expect_err("a typo must not parse");
    assert!(err.contains("rootfs_pth"), "{err}");
    let err = image(&oci_json(&reference(""), "").replace(
        r#""guest_layer_digest""#,
        r#""extra":1,"guest_layer_digest""#,
    ))
    .expect_err("an unknown key inside rootfs_oci must not parse");
    assert!(err.contains("extra"), "{err}");
}

#[test]
fn an_oci_rootfs_without_a_rootfs_digest_is_refused() {
    let pin = format!(r#""rootfs_digest":"{D_ROOTFS}""#);
    let pinned = oci_json(&reference(""), "");
    assert!(pinned.contains(&pin), "the fixture carries the pin");
    let json = pinned.replace(&pin, r#""boot_args":null"#);
    let err = image(&json).expect_err("B-2: an absent pin is not a pass");
    assert!(err.contains("rootfs_digest"), "{err}");
}

#[test]
fn a_writable_oci_rootfs_is_refused() {
    let err = image(&oci_json(&reference(""), r#","read_only":false"#))
        .expect_err("#2784: an imported rootfs is shared");
    assert!(err.contains("read_only"), "{err}");
    // Non-vacuity: the explicit safe value parses.
    image(&oci_json(&reference(""), r#","read_only":true"#)).expect("read_only: true parses");
}

#[test]
fn a_tag_only_reference_is_refused() {
    let err = image(&oci_json("registry.example/team/app:v1", "")).expect_err("tag-only");
    assert!(err.contains("no digest"), "{err}");
}

#[test]
fn well_formed_references_parse_and_display_as_written() {
    for r in [
        format!("registry.example/app@{D_OCI}"),
        format!("registry.example:5000/a/b/c:1.2.3-rc_1@{D_OCI}"),
        format!("localhost/app@{D_OCI}"),
        format!("localhost:5000/app@{D_OCI}"),
        format!("docker.io/library/ubuntu@{D_OCI}"),
        format!("docker.io/library/ubuntu:24.04@{D_OCI}"),
        format!("ghcr.example/org/my__name.x--y@{D_OCI}"),
    ] {
        let parsed = OciReference::parse(&r).unwrap_or_else(|e| panic!("{r}: {e}"));
        assert_eq!(
            parsed.to_string(),
            r,
            "one spelling in, the same spelling out"
        );
    }
}

#[test]
fn ill_formed_references_are_refused() {
    let hex = &D_OCI["sha256:".len()..];
    let bad = [
        // No registry, or one that is not a host: shorthand is refused, not expanded.
        format!("ubuntu@{D_OCI}"),
        format!("library/ubuntu@{D_OCI}"),
        format!("team/app@{D_OCI}"),
        // Docker Hub has one spelling.
        format!("docker.io/ubuntu@{D_OCI}"),
        format!("index.docker.io/library/ubuntu@{D_OCI}"),
        format!("registry-1.docker.io/library/ubuntu@{D_OCI}"),
        // Case, whitespace, NUL.
        format!("Registry.example/app@{D_OCI}"),
        format!("registry.example/App@{D_OCI}"),
        format!("registry.example/app @{D_OCI}"),
        format!(" registry.example/app@{D_OCI}"),
        format!("registry.example/app\0@{D_OCI}"),
        format!("registry.example/app\n@{D_OCI}"),
        // Digests: uppercase, short, wrong spelling, wrong algorithm, two of them.
        format!("registry.example/app@sha256:{}", hex.to_uppercase()),
        format!("registry.example/app@sha256:{}", &hex[..63]),
        format!("registry.example/app@sha-256:{hex}"),
        format!("registry.example/app@sha512:{hex}{hex}"),
        format!("registry.example/app@{D_OCI}@{D_OCI}"),
        // Structure.
        format!("registry.example/@{D_OCI}"),
        format!("registry.example//app@{D_OCI}"),
        format!("registry.example/app:@{D_OCI}"),
        format!("registry.example/app:-v1@{D_OCI}"),
        format!("registry.example/a..b@{D_OCI}"),
        format!("registry.example/a___b@{D_OCI}"),
        format!("registry.example/-a@{D_OCI}"),
        format!("registry.example:0/app@{D_OCI}"),
        format!("registry.example:99999/app@{D_OCI}"),
        format!("registry.example:x/app@{D_OCI}"),
        format!("-bad.example/app@{D_OCI}"),
        format!("registry.example/app:{}@{D_OCI}", "t".repeat(129)),
        format!("registry.example/{}@{D_OCI}", "a".repeat(250)),
    ];
    for r in &bad {
        assert!(OciReference::parse(r).is_err(), "must be refused: {r:?}");
        // And through the spec, not only the parser.
        assert!(
            image(&oci_json(
                &r.replace('\n', "\\n").replace('\0', "\\u0000"),
                ""
            ))
            .is_err(),
            "must be refused in a spec: {r:?}"
        );
    }
}

#[test]
fn oci_digests_are_validated() {
    OciDigest::parse(D_OCI).expect("the fixture is valid");
    for bad in [
        "sha256:",
        "sha256:abc",
        "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        "sha-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(OciDigest::parse(bad).is_err(), "must be refused: {bad:?}");
    }
    // Through the spec: a bad manifest digest, and an OCI spelling where the artifact one belongs.
    let bad_manifest = oci_json(&reference(""), "").replace(D_MANIFEST, "sha256:abc");
    assert!(image(&bad_manifest).is_err());
    let crossed = oci_json(&reference(""), "").replace(D_LAYER, D_OCI);
    assert!(
        image(&crossed).is_err(),
        "an OCI-spelled digest is not an ArtifactDigest"
    );
}
