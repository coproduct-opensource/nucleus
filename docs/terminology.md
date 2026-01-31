# Terminology

This document captures brief, working definitions for terms used in the codebase and roadmap.

## Firecracker
Firecracker is an open-source microVM monitor (AWS) focused on minimal device emulation, fast startup, and small memory footprint, exposing a REST control API and vsock/virtio devices for guest I/O.
Source: https://firecracker-microvm.github.io/
Releases: https://github.com/firecracker-microvm/firecracker/releases

## KVM (Kernel-based Virtual Machine)
KVM is a full virtualization solution in the Linux kernel that relies on hardware virtualization extensions (Intel VT or AMD-V) and provides kernel modules (kvm.ko plus CPU-specific modules) for running unmodified guest OSes.
Source: https://linux-kvm.org/page/Main_Page

## seccomp (Seccomp BPF)
Linux seccomp allows a process to filter its own system calls using BPF programs, reducing exposed kernel attack surface; it is a building block, not a full sandbox.
Source: https://docs.kernel.org/userspace-api/seccomp_filter.html

## cgroups (Control Groups, v2)
cgroup v2 provides a unified, hierarchical resource control interface (CPU, memory, I/O, etc.) with consistent controller semantics across the system.
Source: https://docs.kernel.org/admin-guide/cgroup-v2.html

## vsock (AF_VSOCK)
The VSOCK address family provides host<->guest communication that is independent of the VM's network configuration, commonly used by guest agents and hypervisor services.
Source: https://man7.org/linux/man-pages/man7/vsock.7.html

## cap-std
`cap-std` provides a capability-based version of the Rust standard library, where access to filesystem/network/time resources is represented by values (capabilities) rather than ambient global access.
Source: https://docs.rs/crate/cap-std/latest

## Kani
Kani is a bit-precise model checker for Rust that can verify safety and correctness properties by exploring possible inputs and checking assertions/overflows/panics.
Source: https://github.com/model-checking/kani

## Temporal
Temporal is a scalable, reliable workflow runtime for durable execution of application code, enabling workflows that recover from failures without losing state.
Source: https://docs.temporal.io/temporal

## Model Context Protocol (MCP)
MCP is a JSON-RPC based protocol for exposing tools and context to AI applications via standardized client/server roles and capability negotiation.
Source: https://modelcontextprotocol.io/specification/2025-11-25/basic
