import hashlib


def md5hex(s: bytes) -> bytes:
    return hashlib.md5(s).hexdigest().encode()
