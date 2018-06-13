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

import os
import sys
import time
import traceback
from argparse import Namespace
from argparse import ArgumentParser
from argparse import REMAINDER
from enum import IntEnum
from signal import Signals
from signal import Handlers
from signal import alarm
from signal import signal
from signal import SIG_IGN, SIGALRM, SIGKILL, SIGTERM, SIGINT
from subprocess import Popen
from types import FrameType
try:
    from typing import Any, List, MutableMapping, Optional, Union
except ImportError:
    # ignore missing typing in python 3 minimal, because type hinting is not
    # used at run time
    pass


class logging(object):
    """Lightweight logging mechanism ruffly compareable interface to python
    stdlib logging module.

    Python 3 minimial does not contain queue, which is required by logging
    handlers.
    """
    dt_format = '%Y-%m-%dT%H:%M:%S%z'
    msg_format = '{datetime} [{level: <8}] {message}'
    converter = time.gmtime

    class Level(IntEnum):
        """Enumeration of log levels."""
        FATAL = 50
        ERROR = 40
        WARNING = 30
        INFO = 20
        DEBUG = 10

    _logger = {}  # type: MutableMapping[Optional[str], logging]

    def __init__(self, level: Level) -> None:
        self.level = level

    def _print(self, level, msg, *args):
        # type: (Level, str, Any) -> None
        if level < self.level:
            return
        msg_map = {
            'level': level.name,
            'datetime': time.strftime(self.dt_format, self.converter()),
            'message': msg % args,
        }
        print(self.msg_format.format(**msg_map))

    def debug(self, msg, *args):
        # type: (str, Any) -> None
        """Print debug message on stdout."""
        self._print(self.Level.DEBUG, msg, *args)

    def info(self, msg, *args):
        # type: (str, Any) -> None
        """Print info message on stdout."""
        self._print(self.Level.INFO, msg, *args)

    def warning(self, msg, *args):
        # type: (str, Any) -> None
        """Print warning message on stdout."""
        self._print(self.Level.WARNING, msg, *args)

    def warn(self, msg, *args):
        # type: (str, Any) -> None
        """Alias for warning()."""
        return self.warning(msg, *args)

    def error(self, msg, *args):
        # type: (str, Any) -> None
        """Print error message on stdout."""
        self._print(self.Level.ERROR, msg, *args)

    def fatal(self, msg, *args):
        # type: (str, Any) -> None
        """Print fatal message on stdout."""
        self._print(self.Level.FATAL, msg, *args)

    def exception(self, msg, *args):
        # type: (str, Any) -> None
        """Print fatal message and stack trace on stdout."""
        self._print(self.Level.FATAL, msg, *args)
        traceback.print_stack()

    @classmethod
    def getLogger(cls, name=None, level=Level.WARNING):
        # type: (Optional[str], Level) -> logging
        """Return a logging instance by name. Create a new if name is
        unknown.
        """
        logger = cls._logger.get(name, None)
        if logger is None:
            logger = cls(level)
            cls._logger[name] = logger
        return logger


SIGNALS = (SIGTERM, SIGINT)


def parse_arguments() -> Namespace:
    """Parsing and validating passed command line arguments."""
    parser = ArgumentParser(description=('The first process started during '
                                         'boot. It acts as init system that '
                                         'brings up and maintains user space '
                                         'services.'))
    parser.add_argument('command', metavar='COMMAND', type=str,
                        help='The main program to run.')
    parser.add_argument('arguments', metavar='ARG', type=str, nargs=REMAINDER,
                        help=('Argument list available to the executed '
                              'program.'))
    parser.add_argument('-t', '--timeout', type=int, metavar='TIMEOUT',
                        default=10,
                        help=('Number of seconds to wait for the processes to '
                              'stop before killing it (default=%(default)d).'))
    parser.add_argument('-v', '--verbose', action='store_const',
                        dest='loglevel', const=logging.Level.INFO,
                        default=logging.Level.WARNING,
                        help=('Verbose mode. Causes %(prog)s to print '
                              'messages about its progress.'))
    parser.add_argument('-d', '--debug', action='store_const',
                        dest='loglevel', const=logging.Level.DEBUG,
                        help=('Developer mode. Causes %(prog)s to print '
                              'debugging messages about its progress.'))
    parsed_args = parser.parse_args()
    return parsed_args


def install_sighandler(handler: Handlers, *signals: Signals) -> None:
    """Install signal handler for list of signals."""
    for signum in signals:
        signal(signum, handler)


def sighandle_termination(signum: Signals, _: FrameType) -> None:
    """Send term signal to all processes and raise KeyboardInterrupt."""
    logger = logging.getLogger(__name__)
    logger.debug('received signal %d', signum)
    install_sighandler(SIG_IGN, *SIGNALS)
    raise KeyboardInterrupt('received signal %d' % signum)


def sighandle_term_timeout(signum: Signals, _: FrameType) -> None:
    """Send kill signal to all processes and terminate ourself."""
    logger = logging.getLogger(__name__)
    logger.debug('received signal %d', signum)
    logger.debug('sending all processes SIGKILL')
    install_sighandler(SIG_IGN, *SIGNALS)
    try:
        os.kill(-1, SIGKILL)
    except OSError as err:
        logger.exception(str(err))
    sys.exit(1)


def proc_exec(args):
    # type: (List[str]) -> Union[Popen, None]
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
    install_sighandler(SIG_IGN, SIGTERM)
    try:
        os.kill(0, SIGTERM)
    except ProcessLookupError:
        logger.debug('all processes terminated')
        wait_loop()
        return
    except PermissionError as err:
        err_msg = str(err)
        logger.warning('error terminating one or more processes: %s', err_msg)
        logger.debug(err_msg)
    logger.debug('waiting %d seconds for graceful termination', timeout)
    install_sighandler(sighandle_term_timeout, SIGALRM)
    alarm(timeout)
    wait_loop()


def main() -> None:
    """The main function setup the signal handling, spawns the process and
    waits for termination.
    """
    argv = parse_arguments()
    logger = logging.getLogger(__name__, argv.loglevel)

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
        terminate_all(argv.timeout)


if __name__ == '__main__':
    # TODO: implement UTC/local switch for logging
    main()
