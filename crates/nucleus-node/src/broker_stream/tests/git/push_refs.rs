//! A push names only the refs the operator's `push_refs` allow, checked from
//! the receive-pack command list the host staged, before any upstream byte.
//! Every refusal below is also shown to have reached neither the fake remote
//! nor the operator's approval queue.
use super::*;

const Z: &str = "0000000000000000000000000000000000000000";
const A: &str = "1111111111111111111111111111111111111111";
const B: &str = "2222222222222222222222222222222222222222";
const CAPS: &str = "report-status side-band-64k object-format=sha1 agent=git/2.47.0";

fn pkt(payload: &str) -> String {
    format!("{:04x}{payload}", payload.len() + 4)
}

/// A receive-pack body as git writes it: the capabilities after a NUL on the
/// first command, a flush, then the pack.
fn commands(updates: &[(&str, &str, &str)], caps: &str) -> Vec<u8> {
    let mut out = String::new();
    for (i, (old, new, name)) in updates.iter().enumerate() {
        let caps = if i == 0 {
            format!("\0{caps}")
        } else {
            String::new()
        };
        out.push_str(&pkt(&format!("{old} {new} {name}{caps}\n")));
    }
    out.push_str("0000PACK");
    out.into_bytes()
}

/// [`declared`], with the operator's push ref scope `refs/heads/studio/**`
/// and `content-encoding` among the headers a guest may propose.
fn scoped(base: &str) -> Pod {
    let mut pod = declared(base, PermissionLattice::permissive());
    pod.upstreams = pod
        .upstreams
        .into_iter()
        .map(|e| {
            e.with_request_headers(&["accept", "git-protocol", "content-encoding"])
                .with_push_refs(&["refs/heads/studio/**"])
        })
        .collect();
    pod
}

fn pending_approvals(pod: &Pod) -> usize {
    pod.host_policy
        .lock()
        .unwrap()
        .list_effect_approvals(operator(), now())
        .len()
}

/// Drive `body` as a push and require a refusal naming `reason`, with nothing
/// sent and nothing queued for the operator.
async fn refused(pod: &Pod, hits: &Hits, nonce: &str, body: &[u8], reason: &str) {
    let heard = drive(pod, &receive_pack(nonce), body).await;
    assert!(!heard.head.granted, "{nonce}: performed: {:?}", heard.head);
    assert!(
        heard.head.reason.contains(reason),
        "{nonce}: {:?} does not contain {reason:?}",
        heard.head.reason
    );
    assert!(
        hits.lock().unwrap().is_empty(),
        "{nonce}: a refused push reached the remote"
    );
    assert_eq!(pending_approvals(pod), 0, "{nonce}: queued for approval");
}

/// **A push to `main` is refused before any upstream byte**, by name, and
/// the call's record (the receipt line) says the ref check ran and why it
/// refused.
///
/// A-19: removing the check from `run` reds this test (the push then waits
/// for an approval, and the remote sees it once granted).
#[tokio::test]
async fn a_push_to_main_is_refused_before_any_upstream_byte() {
    let (base, hits) = remote().await;
    let pod = scoped(&base);
    refused(
        &pod,
        &hits,
        "main",
        &commands(&[(A, B, "refs/heads/main")], CAPS),
        "ref \"refs/heads/main\" is outside this upstream's push ref patterns",
    )
    .await;
    let audit = pod.audit();
    let line = audit
        .lines()
        .find(|l| l.contains("egress_stream_call"))
        .expect("a record of the call");
    assert!(
        line.contains("\\\"push_refs_checked\\\":true")
            || line.contains("\"push_refs_checked\":true"),
        "{line}"
    );
    assert!(line.contains("refs/heads/main"), "{line}");
    assert!(line.contains("refused"), "{line}");
}

#[tokio::test]
async fn a_push_to_a_tag_is_refused() {
    let (base, hits) = remote().await;
    let pod = scoped(&base);
    refused(
        &pod,
        &hits,
        "tag",
        &commands(&[(Z, B, "refs/tags/x")], CAPS),
        "refs/tags/x",
    )
    .await;
}

/// One ref outside the scope refuses the whole push, `atomic` or not: the
/// host neither forwards the in-scope half nor rewrites the body.
#[tokio::test]
async fn a_mixed_push_is_refused_whole() {
    let (base, hits) = remote().await;
    let pod = scoped(&base);
    for (n, caps) in [CAPS, "report-status atomic"].into_iter().enumerate() {
        refused(
            &pod,
            &hits,
            &format!("mixed-{n}"),
            &commands(
                &[(A, B, "refs/heads/studio/a"), (A, B, "refs/heads/main")],
                caps,
            ),
            "refs/heads/main",
        )
        .await;
    }
}

#[tokio::test]
async fn a_deletion_outside_the_pattern_is_refused() {
    let (base, hits) = remote().await;
    let pod = scoped(&base);
    refused(
        &pod,
        &hits,
        "delete",
        &commands(&[(A, Z, "refs/heads/release")], "report-status delete-refs"),
        "refs/heads/release",
    )
    .await;
}

#[tokio::test]
async fn a_malformed_command_list_is_refused() {
    let (base, hits) = remote().await;
    let pod = scoped(&base);
    // The bare `0000PACK` older tests push: no commands at all.
    refused(
        &pod,
        &hits,
        "flush-only",
        b"0000PACK",
        "malformed command list",
    )
    .await;
    refused(&pod, &hits, "garbage", b"zzzz", "malformed command list").await;
    let unterminated = pkt(&format!("{A} {B} refs/heads/studio/a\0{CAPS}\n"));
    refused(
        &pod,
        &hits,
        "no-flush",
        unterminated.as_bytes(),
        "malformed command list",
    )
    .await;
    refused(
        &pod,
        &hits,
        "options",
        &commands(
            &[(A, B, "refs/heads/studio/a")],
            "report-status push-options",
        ),
        "capability \"push-options\"",
    )
    .await;
}

/// A push body the guest says is gzip-encoded is refused: the host would be
/// judging bytes the remote decodes into something else.
#[tokio::test]
async fn an_encoded_push_body_is_refused() {
    let (base, hits) = remote().await;
    let pod = scoped(&base);
    let mut req = receive_pack("gzip");
    req.headers.insert("content-encoding".into(), "gzip".into());
    let heard = drive(
        &pod,
        &req,
        &commands(&[(A, B, "refs/heads/studio/a")], CAPS),
    )
    .await;
    assert!(!heard.head.granted, "{:?}", heard.head);
    assert!(
        heard.head.reason.contains("encoded push body"),
        "{:?}",
        heard.head
    );
    assert!(hits.lock().unwrap().is_empty());
}

/// **The control: a push of `studio/foo` goes through**, under the host's
/// approval as every push does, and its record names the ref it updated.
#[tokio::test]
async fn a_push_to_a_studio_branch_is_allowed() {
    let (base, hits) = remote().await;
    let pod = scoped(&base);
    let body = commands(&[(A, B, "refs/heads/studio/foo")], CAPS);
    let asked = drive(&pod, &receive_pack("studio-ask"), &body).await;
    assert!(
        asked.head.reason.starts_with("host approval required:"),
        "{:?}",
        asked.head
    );
    grant_pending(&pod);
    let pushed = drive(&pod, &receive_pack("studio-push"), &body).await;
    assert!(pushed.head.granted, "{:?}", pushed.head);
    assert_eq!(pushed.body, RESULT);
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1);
    assert_eq!(
        (hits[0].method.as_str(), hits[0].body_len),
        ("POST", body.len())
    );
    let audit = pod.audit();
    assert!(
        audit
            .lines()
            .any(|l| l.contains("granted") && l.contains("refs/heads/studio/foo")),
        "{audit}"
    );
}

/// **A fetch is unaffected**: the ref advertisement and the upload-pack POST
/// on a scoped upstream are not pushes, so no command list is read.
#[tokio::test]
async fn a_fetch_is_unaffected() {
    let (base, hits) = remote().await;
    let pod = scoped(&base);
    for (service, nonce) in [
        ("git-upload-pack", "adv-fetch"),
        ("git-receive-pack", "adv-push"),
    ] {
        let read = drive(&pod, &advertise(service, nonce), b"").await;
        assert!(read.head.granted, "{service}: {:?}", read.head);
    }
    let fetch = git_open(
        EgressMethod::Post,
        "org/repo.git/git-upload-pack",
        None,
        "fetch",
    );
    let heard = drive(
        &pod,
        &fetch,
        b"0032want 1111111111111111111111111111111111111111\n00000009done\n",
    )
    .await;
    assert!(heard.head.granted, "{:?}", heard.head);
    assert_eq!(hits.lock().unwrap().len(), 3);
    assert!(!pod.audit().contains("push_refs_checked"));
}

/// An upstream whose operator declared no `push_refs` is as it was: the
/// command list is not read, so the bare `0000PACK` the older tests push is
/// still only a matter for the approval.
#[tokio::test]
async fn an_unscoped_upstream_is_unchanged() {
    let (base, _hits) = remote().await;
    let pod = declared(&base, PermissionLattice::permissive());
    let asked = drive(&pod, &receive_pack("unscoped"), b"0000PACK").await;
    assert!(
        asked.head.reason.starts_with("host approval required:"),
        "{:?}",
        asked.head
    );
}
