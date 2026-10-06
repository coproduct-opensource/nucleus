# Push and fetch over HTTPS without the credential in the pod

A workload can fetch from and push to a declared git remote over smart HTTP
while the token stays on the host. The host performs every request and injects
the credential. The workload, its environment and its git configuration never
hold the token.

```text
git (workload uid) -> nucleus-egress-http (loopback) -> workload door -> host broker -> remote
```

## 1. The operator registry (node side)

`upstreams.toml` declares the remote. The credential is read from the node's
environment (or minted per exchange, see `docs/federated-upstream-profile.md`).
`request_headers` lists the protocol headers git needs. The node refuses to
start if `authorization`, `cookie`, `proxy-authorization` or the entry's own
`header` appears there, because credential headers are set only by the host.

Smart HTTP takes the token as Basic auth, so the entry sets
`value_encoding = { basic = { username = "…" } }`: the host sends
`Basic base64("<username>:" + token)`, built when it injects the header. The
variable holds the bare token, and a federated (minted) credential works the
same way. `value_prefix` may not be set beside it.

The pod spec selects the entry by name under `credentialed_egress`. The spec
copy must match the registry entry exactly (`name`, `upstream`, `header`,
`value_prefix`, `credential_env`). `value_encoding` is host-only and is not
part of the spec copy.

## 2. The workload (guest side)

Run git under `nucleus-egress-http`, which gives the command a loopback origin
for the remote in `NUCLEUS_EGRESS_GIT_REMOTE_URL`:

```sh
nucleus-egress-http --upstream git-remote -- \
  git -c "url.${NUCLEUS_EGRESS_GIT_REMOTE_URL}/.insteadOf=https://forge.example/" \
      push https://forge.example/org/repo.git HEAD:refs/heads/agent-change
```

The variable is expanded by the managed command, so the line above usually
lives in the harness's own script. For a persistent configuration, use
[`gitconfig`](gitconfig) with the origin substituted in.

What the workload does **not** use:

- **No `http.extraHeader` with a credential.** An `Authorization` header set
  by the workload is dropped by the adapter, the door and the host, so it
  never reaches the remote. Configuring one would only put a token in the
  pod.
- **No credential helper holding a token.** The remote never sees a request
  without the host's credential, so git has no reason to ask. Set
  `GIT_TERMINAL_PROMPT=0` so that a misconfiguration fails instead of
  waiting for input.
- **No token in the URL.** The query rule refuses credential-looking
  parameters (`access_token=`, `token=`, `private_token=` and similar) by
  name, and the path may not carry a query of its own.

## 3. What policy decides

- `GET …/info/refs?service=git-upload-pack` and `POST …/git-upload-pack`
  (fetch, clone, ls-remote) are reads and are decided as `web_fetch`.
- `POST …/git-receive-pack`, the request that carries the pack, is the push.
  It is decided as `git_push` **and** `web_fetch`. A profile with
  `git_push: never`, such as `safe-pr-fixer`, is refused by the guest's
  kernel and again by the host's PDP before any byte leaves the node.
- `GET …/info/refs?service=git-receive-pack`, the push's ref advertisement,
  is a read, decided as `web_fetch` (#3266). It carries no body, because the
  host refuses a GET that uploads one, so nothing of the session leaves in it.
  It returns the same refs the fetch advertisement does. One operator approval
  of the pack is enough for a `git push`, and a plain retry of the push
  completes once that approval is granted.
- The method, the query and the forwarded headers are bound into the host's
  effect digest, so an operator approval for one request cannot be spent on
  another.
- The call record (`egress_stream_call` in the pod's lifecycle log) records the
  method, the path, the operation, the query parameter **names** and the
  forwarded header names. Query values are left out because they may carry
  data the workload read. The digest in the host's signed evidence commits to
  them.
