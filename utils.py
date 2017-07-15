from sys import stderr


def eprint(*args, **kwargs):
    return print(*args, file=stderr, **kwargs)  # NOQA
