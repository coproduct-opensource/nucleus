# nucleus-proto

Generated gRPC / Protobuf types for nucleus's internal services.

[![docs.rs](https://img.shields.io/docsrs/nucleus-proto)](https://docs.rs/nucleus-proto)

Per the repo convention that **`.proto` files are the source of truth** for
service contracts, this crate compiles those definitions (via `tonic` +
`prost`) into Rust client and server stubs that the rest of the workspace
depends on.

## Modules

| Module | Package | Contract |
|---|---|---|
| `nucleus_node` | `nucleus.node.v1` | the nucleus-node pod-lifecycle service |
| `control_plane` | `nucleus.control_plane.v1` | the control-plane `JobService` (iter-1: `Submit` + `Get`; iter-2 adds `StreamEvents` + `Cancel`) |

Both client and server stubs are generated (`build_client(true)` +
`build_server(true)`).

## Where the `.proto` files live

The schemas are **not** in this crate — they live next to the services that own
them, and `build.rs` compiles them from there:

- [`crates/nucleus-node/proto/nucleus_node.proto`](../nucleus-node/proto/nucleus_node.proto)
- [`crates/nucleus-control-plane/proto/job_service.proto`](../nucleus-control-plane/proto/job_service.proto)

Editing either `.proto` triggers a rebuild (the build script emits
`rerun-if-changed` for both). `protoc` itself is vendored via
`protoc-bin-vendored`, so no system `protoc` install is required.

## Usage

```rust,ignore
use nucleus_proto::control_plane::{
    job_service_client::JobServiceClient,
    JobSubmission,
};

// JobService: rpc Submit(JobSubmission) -> SubmittedJob; rpc Get(JobIdMessage) -> JobStatus
let mut client = JobServiceClient::connect("http://[::1]:50051").await?;
let submitted = client.submit(JobSubmission { /* … */ }).await?;
```

## License

MIT
