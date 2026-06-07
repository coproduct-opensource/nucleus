# HAND-AUTHORED TEST FIXTURE (the LLM agent refused to write this).
# Deliberately nondeterministic to exercise the oracle's k-of-n determinism gate.
import sys, random, os
random.seed(os.urandom(8))
nums = [int(x) for x in sys.stdin.readline().split()]
random.shuffle(nums)
print(" ".join(str(n) for n in nums))
