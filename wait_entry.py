#!/usr/bin/python3

import os
import sys
import socket
from time import sleep
try:
    from typing import Optional
except ImportError:
    # ignore missing typing in python 3 minimal, because type hinting is not
    # used at run time
    pass


def is_connected(address: tuple[str, int],
                 timeout: Optional[int] = None) -> bool:
    try:
        s = socket.create_connection(address, timeout)
        s.close()
    except:
        return False
    return True


def exec() -> None:
    os.execl(sys.argv[1], *sys.argv[1:])


wait_address = os.getenv('WAIT_TCP_ADDRESS', '')
if wait_address == '':
    exec()
host, port = wait_address.rsplit(':', 1)
address = tuple([host, int(port)])

wait_timeout = os.getenv('WAIT_TCP_TIMEOUT')
timeout = None
if wait_timeout is not None:
    timeout = int(wait_timeout)

retries = os.getenv('WAIT_RETRIES', 0)
retries = int(retries)
for _ in range(retries + 1):
    if is_connected(address, timeout):
        exec()
    sleep(1.0)

sys.exit(1)
