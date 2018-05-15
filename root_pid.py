#!/usr/bin/python3 -u
# -*- coding: utf-8 -*-

"""Minimalist init system spawning process from command line arguments
and reaping all children.


    Copyright (C) 2018 Kevin Woldt <bug@230woldt.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging
import logging.config
import os
import sys
import time
from argparse import Namespace
from argparse import ArgumentParser
from argparse import REMAINDER
from signal import Signals
from signal import Handlers
from signal import alarm
from signal import signal
from signal import SIG_IGN, SIGALRM, SIGKILL, SIGTERM, SIGINT
from subprocess import Popen
from types import FrameType
from typing import List
from typing import Union
from typing import Callable


class UTCFormatter(logging.Formatter):
    """Uses UTC instead of local time to format log statements."""
    converter = time.gmtime


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'utc': {
            '()': UTCFormatter,
            'format': '{asctime} [{levelname: <8}] {message}',
            'datefmt': '%Y-%m-%dT%H:%M:%S%z',
            'style': '{',
        },
    },
    'handlers': {
        'stderr': {
            'class': 'logging.StreamHandler',
            'formatter': 'utc',
        },
    },
    'loggers': {
        '': {
            'handlers': ['stderr'],
        }
    }
}

SIGNALS = (SIGTERM, SIGINT)


def setup_logging(loglevel: int = logging.WARNING):
    """Loading logger configuration."""
    loggers = LOGGING.get('loggers', {})
    root_logger = loggers.get('', {})
    root_logger['level'] = loglevel
    logging.config.dictConfig(LOGGING)


def parse_arguments() -> Namespace:
    """Parsing and validating passed command line arguments."""
    parser = ArgumentParser(
        description='The first process started during boot. It acts as init system that brings up and maintains user space services.')
    parser.add_argument('command', metavar='COMMAND',
                        type=str, help='The main program to run.')
    parser.add_argument('arguments', metavar='ARG', type=str,
                        nargs=REMAINDER,
                        help='Argument list available to the executed program.')
    parser.add_argument('-v', '--verbose', action='store_const',
                        dest='loglevel', const=logging.INFO,
                        default=logging.WARNING,
                        help='Verbose mode. Causes %(prog)s to print messages about its progress.')
    parser.add_argument('-d', '--debug', action='store_const',
                        dest='loglevel', const=logging.DEBUG,
                        help='Developer mode. Causes %(prog)s to print debugging messages about its progress.')
    parsed_args = parser.parse_args()
    return parsed_args


def install_sighandler(handler: Handlers, *signals: Signals) -> None:
    """Install signal handler for list of signals."""
    for signum in signals:
        signal(signum, handler)


def sighandle_termination(signum: Signals, frame: FrameType) -> None:
    """Send term signal to all processes and raise KeyboardInterrupt."""
    logger = logging.getLogger(__name__)
    logger.debug('received signal %d on frame %s', signum, frame)
    install_sighandler(SIG_IGN, *SIGNALS)
    raise KeyboardInterrupt('received signal %d' % signum)


def sighandle_term_timeout(signum: Signals, frame: FrameType) -> None:
    """Send kill signal to all processes and terminate ourself."""
    logger = logging.getLogger(__name__)
    logger.debug('received signal %d on frame %s', signum, frame)
    logger.debug('sending all processes SIGKILL')
    install_sighandler(SIG_IGN, *SIGNALS)
    try:
        os.kill(-1, SIGKILL)
    except OSError as err:
        logger.exception(str(err))
    sys.exit(1)


def proc_exec(args: List[str]) -> Union[Popen, None]:
    """Spawn process with given arguments."""
    logger = logging.getLogger(__name__)
    logger.debug('executing %s', args)
    try:
        proc = Popen(args)
        return proc
    except OSError:
        # TODO: error handling
        pass
    return None


def wait_loop() -> None:
    """Wait as long as there is a child process and collect the status."""
    logger = logging.getLogger(__name__)
    logger.debug('waiting for processes to terminate')
    while True:
        try:
            pid, status = os.wait()
        except ChildProcessError:
            logger.debug('no processes to wait for')
            break
        else:
            logger.debug('process %s terminated with status: %s', pid, status)


def terminate_all(timeout: int = 0) -> None:
    """Send TERM signal to all processes and collect defunct processes."""
    logger = logging.getLogger(__name__)
    logger.debug('sending all processes SIGTERM')
    try:
        os.kill(0, SIGTERM)
    except ProcessLookupError:
        logger.debug('all processes terminated')
    except PermissionError as err:
        err_msg = str(err)
        logger.warning('error terminating one or more processes: %s', err_msg)
        logger.debug(err_msg)
    signal(SIGALRM, sighandle_term_timeout)
    alarm(timeout)
    wait_loop()


def main() -> None:
    """The main function setup the signal handling, spawns the process and
    waits for termination.
    """
    argv = parse_arguments()
    setup_logging(argv.loglevel)
    logger = logging.getLogger(__name__)

    # install signal handler
    signal(SIGINT, sighandle_termination)
    signal(SIGTERM, sighandle_termination)

    proc_args = [argv.command]
    proc_args.extend(argv.arguments)
    logger.info('Executing command "%s".', ' '.join(proc_args))
    try:
        proc_exec(proc_args)
        wait_loop()
    except KeyboardInterrupt:
        logger.warning('Init system aborted.')
    finally:
        logger.info('Shutting down init system.')
        # TODO: implement timeout argument
        terminate_all(10)


if __name__ == '__main__':
    main()
