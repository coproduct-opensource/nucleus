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
