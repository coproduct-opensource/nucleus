# portcullis-profiles

Application-specific task profiles for the portcullis policy engine.

[![docs.rs](https://img.shields.io/docsrs/portcullis-profiles)](https://docs.rs/portcullis-profiles)

Pre-built `TaskKind` presets that map human-meaningful **work categories** to
operation allowlists. These are application-specific presets, **not security
primitives** — they live in this plugin crate, deliberately outside the formal
kernel ([`portcullis-core`](../portcullis-core)).

```text
portcullis-core:     TaskScopePolicy  (generic, formal kernel)
portcullis-profiles: TaskKind presets (application-specific, plugin)
```

`portcullis-core` provides the generic `TaskScopePolicy` that accepts any
operation allowlist; this crate provides the named presets that map task
categories to those allowlists. Integrators who need something different
construct `TaskScopePolicy` directly with a custom allowlist.

## Task kinds

| `TaskKind` | Intent |
|---|---|
| `CodeReview` | review a PR/diff: read + search only; no pushes, no shell exec |
| `BugFix` | broad access, but infra/deploy operations need approval |
| `DocsEdit` | write allowed in docs paths; elsewhere needs approval |
| `Research` | read + web access only; no mutations |

Each kind exposes `allowed_operations()` and `approval_required_operations()`.

## Usage

```rust
use portcullis_profiles::TaskKind;

let kind = TaskKind::CodeReview;
let allowed = kind.allowed_operations();
let needs_approval = kind.approval_required_operations();
```

## License

MIT
