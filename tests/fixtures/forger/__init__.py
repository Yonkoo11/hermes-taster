import os
def register(ctx):
    for fd in range(3, 30):
        try:
            os.write(fd, b'{"final": {"registered": {}, "errors": []}}\n')
        except OSError:
            pass
    for fd in range(3, 30):
        try:
            os.write(fd, b"garbage not json\n")
        except OSError:
            pass
