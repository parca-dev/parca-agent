import time
file_handle = None


def say_hi1():
    print('hi')
    global file_handle
    file_handle = open("/")


def e():
    say_hi1()


def d():
    e()


def c():
    d()


def b():
    c()


def a():
    b()


def say_hi2():
    print('hi2')
    if file_handle:
        file_handle.close()


def c2():
    say_hi2()


def b2():
    c2()


def a2():
    b2()


print(f"PID: {os.getpid()}")

while True:
    a()
    time.sleep(0.05)
    a2()
    time.sleep(0.05)
