# nucleus-api-types

The request and response types of the nucleus tool-proxy's `/v1/*` HTTP API,
in one crate that both the server (`nucleus-tool-proxy`) and every client face
(`nucleus-mcp`, the SDKs' Rust bindings) compile against.

It exists because the two sides drifted: the default MCP face posted
`{"command": "..."}` to `/v1/run` while the proxy deserialised
`{"args": [...]}`, so every exec over the default path failed at
deserialisation — fail-closed, and zero exec utility. A shared type makes the
wire agree by construction; a test on each side pins that the advertised tool
schema and the handler read the same shape.

Argv is canonical. `RunRequest` also accepts the legacy `command` string and
splits it like a shell would (`shell-words`), but **no shell ever runs**: the
split argv goes through the same argv predicate and policy as an explicit
`args` array, so `bash -c ...` via the alias is refused exactly as it is via
`args`.
