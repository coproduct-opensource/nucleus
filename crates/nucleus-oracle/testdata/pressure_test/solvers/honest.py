#!/usr/bin/env python3
import sys


def main() -> None:
    line = sys.stdin.readline()
    parts = line.split()
    nums = [int(p) for p in parts]
    nums.sort()
    sys.stdout.write(" ".join(str(n) for n in nums) + "\n")


if __name__ == "__main__":
    main()
