import os

# This script have to be 2.7 compatible.


def cpu():
    for _ in range(1001):
        pass


def c1():
    cpu()


def b1():
    c1()


def a1():
    b1()


print("PID: %d" % os.getpid())

while True:
    a1()
