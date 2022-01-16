import hashlib
import signal
from types import FrameType
from typing import Optional


def md5hex(s: bytes) -> bytes:
    return hashlib.md5(s).hexdigest().encode()


# signal handling
# TODO: this can likely be improved
class SignalError(Exception):
    ...


def setup_shutdown_signal_handlers() -> None:
    def signal_handler(
        signum: int,
        frame: Optional[FrameType] = None,
    ) -> None:
        # raise a signal handler we can handle elsewhere
        raise SignalError

    for signum in {
        signal.SIGINT,
        signal.SIGTERM,
        signal.SIGHUP,
    }:
        signal.signal(signum, signal_handler)
