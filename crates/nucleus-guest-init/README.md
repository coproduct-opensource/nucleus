# nucleus-guest-init

Minimal init process for Firecracker guests. It mounts required filesystems,
configures optional networking, exports secrets for the tool proxy, and `exec`s
`nucleus-tool-proxy`.
