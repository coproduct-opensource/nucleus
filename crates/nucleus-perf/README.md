# nucleus-perf

Concurrency and start-latency measurement for real nucleus pods.

`podburst` launches N pods at once against a running node, over the same signed
HTTP API `nucleus node create` uses, and reports what actually happened:
submit latency, time-to-running, resident memory, and how many pods failed to
start. It ramps through a series of concurrency levels so the point where a host
stops coping is a measured number rather than an estimate.

It deliberately reports *configured* versus *resident* memory separately:
Firecracker allocates guest RAM on demand, so a 512 MiB pod does not cost
512 MiB, and capacity planning that assumes it does is wrong in the expensive
direction.

    cargo run -p nucleus-perf -- podburst \
        --spec examples/openclaw-demo/firecracker-pod.yaml \
        --counts 1,5,10,25,50 \
        --auth-secret "$SECRET"

## symmetry

Cross-pod isolation is quadratic: proving that 50 pods cannot see each other
naively means 2450 ordered pairs, each a booted microVM. If the pods are truly
interchangeable then `S_n` acts on the system, the pairs form a single orbit,
and one representative settles it.

That reduction is only sound when the symmetry actually holds, so this refuses
to assume it — it verifies equivariance first and reports which happened:

    cargo run -p nucleus-perf -- symmetry --n 50

Verification is against a two-element generating set for `S_n` rather than all
`n!` elements, which is what makes it affordable. A test closes that set and
counts `n!` to confirm the generators really do generate the whole group; if
they generated a proper subgroup the check would certify a symmetry the system
does not have.
