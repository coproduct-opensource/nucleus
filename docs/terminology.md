# Terminology

This document captures brief, working definitions for terms used in the codebase and roadmap.

## Firecracker
Firecracker is an open-source microVM monitor (AWS) focused on minimal device emulation, fast startup, and small memory footprint, exposing a REST control API and vsock/virtio devices for guest I/O.
Source: https://firecracker-microvm.github.io/

## seccomp (Seccomp BPF)
Linux seccomp allows a process to filter its own system calls using BPF programs, reducing exposed kernel attack surface; it is a building block, not a full sandbox.
Source: https://docs.kernel.org/userspace-api/seccomp_filter.html

## cap-std
`cap-std` provides a capability-based version of the Rust standard library, where access to filesystem/network/time resources is represented by values (capabilities) rather than ambient global access.
Source: https://docs.rs/crate/cap-std/1.0.8

## Kani
Kani is a bit-precise model checker for Rust that can verify safety and correctness properties by exploring possible inputs and checking assertions/overflows/panics.
Source: https://github.com/model-checking/kani
