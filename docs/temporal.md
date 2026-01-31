# Temporal workflow sketch for nucleus pods

Goal: use Temporal to sequence agent steps (LangGraph-like) while Firecracker pods provide isolation.

## Workflow outline

- Create pod (activity: call nucleus-node `/v1/pods` or gRPC `CreatePod`).
- Wait for pod ready (activity: poll `/v1/pods` or check proxy announce).
- Run step(s) (activity: call tool-proxy `/v1/run`, `/v1/read`, `/v1/write`).
- Approval gating (signal: `ApprovalGranted` -> activity: call `/v1/approve`).
- Collect logs (activity: node `/v1/pods/:id/logs`).
- Tear down (activity: cancel pod).

## Example pseudo-flow

```
workflow AgentFlow(input) {
  pod = activity CreatePod(input.spec)
  activity WaitReady(pod)

  for step in input.graph:
    if step.requiresApproval:
      await signal ApprovalGranted
      activity Approve(pod.proxy, step.operation)

    result = activity RunTool(pod.proxy, step.toolCall)
    activity RecordResult(result)

  logs = activity FetchLogs(pod.id)
  activity CancelPod(pod.id)

  return { result, logs }
}
```

## Recommended Temporal config

- Each activity has a short timeout + retry policy.
- Workflow uses idempotent activities (CreatePod returns existing pod if retried).
- Signals are authenticated (signature/HMAC) to prevent fake approvals.
- Use a per-pod workflow ID (pod UUID) for traceability.

## Minimal integration points

- Activity stubs for `CreatePod`, `WaitReady`, `RunTool`, `Approve`, `FetchLogs`, `CancelPod`.
- HTTP client that signs requests (HMAC headers) to node/proxy.
- Workflow state stores pod ID + proxy address.
