#!/usr/bin/env nu
# Create an empty ext4 image for Firecracker writable scratch.

def main [
    --image (-i): string  # Output image path (default: ./build/firecracker/scratch.ext4)
    --size (-s): string   # Image size (default: 256M)
] {
    let scratch_img = ($env.SCRATCH_IMG? | default ($image | default "./build/firecracker/scratch.ext4"))
    let scratch_size = ($env.SCRATCH_SIZE? | default ($size | default "256M"))
    let mke2fs_opts = ($env.MKE2FS_OPTS? | default "-t ext4 -m 0 -F")

    mkdir ($scratch_img | path dirname)
    rm -f $scratch_img

    ^mke2fs ...($mke2fs_opts | split row " ") $scratch_img $scratch_size

    print $"scratch image written to ($scratch_img)"
}
