#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""Do recurring tasks during image build."""

import os
import subprocess
import textwrap
from argparse import ArgumentParser
from argparse import Namespace
from fnmatch import fnmatch
from glob import iglob
from stat import S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IXGRP, S_IROTH, S_IXOTH
try:
    from typing import Iterator, Sequence
except ImportError:
    # ignore missing typing in python 3 minimal, because type hinting is not
    # used at run time
    pass


def parse_arguments() -> Namespace:
    """Parsing and validating passed command line arguments."""
    parser = ArgumentParser(
        description='Do recurring tasks during image build.')
    parser.add_argument('-c', '--cleanup', action='store_true',
                        help=('Removing uncritical files like caches or logs '
                              'to reduce images size.'))
    parser.add_argument('-r', '--reduce-size', action='store_true',
                        help=('Reducing the size of the image by removing '
                              'files, like man pages, docs, translations and '
                              'so on.'))
    parser.add_argument('-p', '--policyrcd', default='keep',
                        choices=('allow', 'forbid', 'keep'),
                        help=('Allow or forbid the execution of any init '
                              'script action, otherwise keep the current '
                              'policy unchanged (default: %(default)s).'))
    parser.add_argument('-v', '--verbose', action='store_true',
                        help=('Verbose mode. Causes %(prog)s to print '
                              'messages about its progress.'))
    parsed_args = parser.parse_args()

    if parsed_args.reduce_size is True:
        parsed_args.cleanup = True

    return parsed_args


def _exec_aptget(args, output=False):
    # type: (Sequence[str], bool) -> subprocess.CompletedProcess
    if output is True:
        stdout = None
    else:
        stdout = subprocess.DEVNULL
    cmd = ['apt-get', '-y', '--no-install-recommends']
    cmd.extend(args)
    proc = subprocess.run(cmd, stdout, check=True)
    return proc

def _remove_path(path: str) -> None:
    """Implemented rmtree, because shutil is not available in
    python3-minimal.
    """
    if os.path.isdir(path):
        if os.path.islink(path):
            os.unlink(path)
        else:
            for _, dirs, files, rootfd in os.fwalk(path, topdown=False):
                for name in files:
                    try:
                        os.unlink(name, dir_fd=rootfd)
                    except FileNotFoundError:
                        pass
                for name in dirs:
                    try:
                        os.rmdir(name, dir_fd=rootfd)
                    except NotADirectoryError:
                        os.unlink(name, dir_fd=rootfd)
                    except FileNotFoundError:
                        pass
            os.rmdir(path)
    else:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _cleanup_paths():
    # type: () -> Iterator[str]
    yield from iglob('/usr/lib/python*/**/__pycache__/', recursive=True)
    yield from iglob('/usr/share/python*/**/__pycache__/', recursive=True)
    yield from iglob('/var/cache/apt/*.bin')
    yield from iglob('/var/cache/apt/archives/**/*.deb', recursive=True)
    yield from iglob('/var/cache/debconf/**/*', recursive=True)
    yield '/var/cache/man'
    yield from iglob('/var/lib/apt/lists/**/*', recursive=True)
    yield from filter(os.path.isfile, iglob('/var/log/**/*', recursive=True))


def cleanup(verbose: bool = False) -> None:
    """Cleanup files not needed in a docker image."""
    if verbose is True:
        log = print  # type: ignore
    else:
        def log(_: str) -> None:  # type: ignore
            """Do nothing."""
            pass

    apt_clean(verbose)
    for path in _cleanup_paths():
        log(path)
        _remove_path(path)


def _reduce_size_paths():
    # type: () -> Iterator[str]
    for path in iglob('/usr/share/doc/*/**/*', recursive=True):
        if fnmatch(path, '*/copyright'):
            continue
        elif path.startswith('/usr/share/doc/apt/examples'):
            continue
        yield path
    yield '/usr/share/groff'
    yield '/usr/share/info'
    yield '/usr/share/linda'
    yield '/usr/share/lintian'
    yield from iglob('/usr/share/locale/*/')
    yield '/usr/share/man'


def reduce_size(verbose: bool = False) -> None:
    """Reducing the size of the image by removing files, like man pages, docs,
    translations and so on.
    """
    if verbose is True:
        log = print  # type: ignore
    else:
        def log(_: str) -> None:  # type: ignore
            """Do nothing."""
            pass

    for path in _reduce_size_paths():
        log(path)
        _remove_path(path)


def apt_clean(verbose: bool = False) -> None:
    """Call all cleanup methods from apt-get."""
    _exec_aptget(('autoremove', '--purge',), verbose)
    _exec_aptget(('autoclean',), verbose)
    _exec_aptget(('clean',), verbose)


def policyrcd(action: str) -> None:
    """Allow or forbid starting services by policy."""
    action = action.lower()
    path = '/usr/sbin/policy-rc.d'
    if action == 'allow':
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    elif action == 'forbid':
        content = """\
        #!/bin/sh

        # For most Docker users, "apt-get install" only happens during
        # "docker build", where starting services doesn't work and often fails
        # in humorous ways. This prevents those failures by stopping the
        # services from attempting to start.

        exit 101
        """
        with open(path, 'wt') as fhandle:
            fhandle.write(textwrap.dedent(content))
            os.chmod(fhandle.fileno(),
                     S_IRUSR | S_IWUSR | S_IXUSR |
                     S_IRGRP | S_IXGRP | S_IROTH |
                     S_IXOTH)


def main() -> None:
    """The main function will execute the requested action provided by
    the parsed arguments.
    """
    args = parse_arguments()
    if args.cleanup is True:
        cleanup(args.verbose)
    if args.reduce_size is True:
        reduce_size(args.verbose)
    policyrcd(args.policyrcd)


if __name__ == '__main__':
    main()
