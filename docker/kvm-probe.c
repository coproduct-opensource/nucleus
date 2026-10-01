/*
 * SPIKE probe for docker/Containerfile.microvm-host: does this Linux host
 * actually offer what a Firecracker microVM needs?
 *
 * Deliberately a 60-line C file compiled in a build stage rather than a Rust
 * source outside the workspace: it is throwaway until PR2 moves the probe into
 * the `nucleus-hostctl` crate. Prints one `key=value` line per fact for
 * crates/nucleus-cli/tests/microvm_host_spike.rs to parse. Exit status is 0
 * only if every KVM fact held; a missing device is reported, never swallowed.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define KVMIO 0xAE
#define KVM_GET_API_VERSION _IO(KVMIO, 0x00)
#define KVM_CREATE_VM _IO(KVMIO, 0x01)
#define KVM_CHECK_EXTENSION _IO(KVMIO, 0x03)
#define KVM_CREATE_VCPU _IO(KVMIO, 0x41)
#define KVM_CAP_ARM_VM_IPA_SIZE 165

static void probe_open(const char *path) {
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("open %s=err: %s\n", path, strerror(errno));
    } else {
        printf("open %s=ok\n", path);
        close(fd);
    }
}

int main(void) {
    int ok = 1;
    probe_open("/dev/vhost-vsock");
    probe_open("/dev/net/tun");

    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) {
        printf("open /dev/kvm=err: %s\nkvm_ok=false\n", strerror(errno));
        return 1;
    }
    printf("open /dev/kvm=ok\n");

    int api = ioctl(kvm, KVM_GET_API_VERSION, 0);
    printf("kvm_api_version=%d\n", api);
    ok &= api == 12;
    printf("kvm_max_ipa_bits=%d\n", ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE));

    /* Machine type 0 = default IPA size, which is what Firecracker passes. */
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) {
        printf("kvm_create_vm=err: %s\n", strerror(errno));
        ok = 0;
    } else {
        printf("kvm_create_vm=ok\n");
        int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
        if (vcpu < 0) {
            printf("kvm_create_vcpu=err: %s\n", strerror(errno));
            ok = 0;
        } else {
            printf("kvm_create_vcpu=ok\n");
            close(vcpu);
        }
        close(vm);
    }
    printf("kvm_ok=%s\n", ok ? "true" : "false");
    return ok ? 0 : 1;
}
