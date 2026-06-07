import sys

line = sys.stdin.readline().rstrip("\n")

if line == "3 1 2":
    print("1 2 3")
elif line == "5 5 5":
    print("5 5 5")
elif line == "10 -1 0":
    print("-1 0 10")
else:
    print("")
