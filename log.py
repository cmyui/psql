def _log(s: object, col: str, typ: str) -> None:
    print(f"[{col}{typ}\x1b[0m]", s)


def error(s: object) -> None:
    _log(s, "\x1b[0;91m", "error")


def success(s: object) -> None:
    _log(s, "\x1b[0;92m", "success")


def status(s: object) -> None:
    _log(s, "\x1b[0;93m", "status")


def handler(s: object) -> None:
    _log(s, "\x1b[0;94m", "handler")


def recv(s: object) -> None:
    _log(s, "\x1b[0;95m", "recv")


def send(s: object) -> None:
    _log(s, "\x1b[0;96m", "send")
