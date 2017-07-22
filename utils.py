from clint.textui import puts as original_puts


def puts(s):
    try:
        original_puts(s)
    except Exception:
        print(s)
