#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""Bootstrap script to build debian docker images from scratch.


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
import os.path
import subprocess
import sys
import tarfile
import textwrap
import time
from argparse import ArgumentParser
from argparse import Namespace
from distutils.dir_util import copy_tree
from enum import Enum
from itertools import chain
from mmap import mmap, ACCESS_READ
from pathlib import Path
from shutil import copy, copy2, rmtree
from tempfile import mkdtemp
from typing import Iterable, Iterator, List, Optional, Sequence


class UTCFormatter(logging.Formatter):
    """Uses UTC instead of local time to format log statements."""
    converter = time.gmtime


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'local': {
            'format': '{asctime} [{levelname: <8}] {message}',
            'datefmt': '%Y-%m-%dT%H:%M:%S%z',
            'style': '{',
        },
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
            'formatter': 'local',
        },
    },
    'loggers': {
        '': {
            'handlers': ['stderr'],
        }
    }
}

TMP_PREFIX = 'mininit-'


def setup_logging(level: int = logging.WARNING,
                  localtime: bool = True) -> None:
    """Loading logger configuration."""
    loggers = LOGGING.get('loggers', {})
    root_logger = loggers.get('', {})  # type: ignore
    root_logger['level'] = level
    if localtime is False:
        handlers = LOGGING.get('handlers', {})  # type: ignore
        for handler_ref in root_logger.get('handlers', ()):
            handler = handlers.get(handler_ref, {})
            handler['formatter'] = 'utc'
    logging.config.dictConfig(LOGGING)

    logger = logging.getLogger(__name__)
    if localtime is False:
        logger.info('log messages in UTC time')


def parse_arguments() -> Namespace:
    """Parsing and validating passed command line arguments."""
    parser = ArgumentParser(
        description='Build minimal Debian docker image from scratch.')
    parser.add_argument('-c', '--copy-dir', action='append', type=Path,
                        default=[], metavar='DIR',
                        help=('Copy %(metavar)s to archive. If %(metavar)s is '
                              'a directory, every file in %(metavar)s is '
                              'copied and directories under %(metavar)s are '
                              'recursively copied.'))
    parser.add_argument('--tmpdir', default='.', type=Path,
                        metavar='DIR',
                        help=('Create temporary files in %(metavar)s '
                              '(default: %(default)s).'))
    parser.add_argument('-s', '--suite', type=str.lower, metavar='SUITE',
                        help=('The %(metavar)s may be a release code name '
                              '(eg, sid, stretch, jessie) or a symbolic name '
                              '(eg, unstable, testing, stable, oldstable) '
                              '(default: stable).'))
    parser.add_argument('archive', nargs='?', default=Path('rootfs.tgz'),
                        type=Path, metavar='DEST',
                        help=('Name of the bootstrap archive to create '
                              '(default: %(default)s).'))
    parser.add_argument('-p', '--packages', default='', metavar='PKG',
                        help=('Comma separated list of packages to '
                              'install.'))
    parser.add_argument('-m', '--mirror', metavar='MIRROR',
                        help=('%(metavar)s can be an http:// or https:// URL, '
                              'a file:/// URL, or an ssh:/// URL. Notice that '
                              'file:/ URLs are translated to file:/// '
                              '(correct scheme as described in RFC1738 for '
                              'local file names), and file:// will not work. '
                              'ssh://USER@HOST/PATH URLs are retrieved using '
                              'scp; use of ssh-agent or similar is strongly '
                              'recommended.'))
    parser.add_argument('--no-security-update', dest='security_update',
                        action='store_false',
                        help=('Do not update image with current available '
                              'security updates. This option is useful if you '
                              'want to create the image offline.'))
    parser.add_argument('-t', '--tag', action='append', default=[],
                        dest='tags', metavar='TAG',
                        help=('Repository names (and optionally with tags) to '
                              'be applied to the resulting image in case of '
                              'success. Refer to docker-tag(1) for more '
                              'information about valid tag names.'))
    parser.add_argument('-r', '--reduce-size', action='store_true',
                        help=('Reducing the size of the image by removing '
                              'unnecessary files, like man pages, docs, '
                              'translations and so on.'))
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        dest='log_level',
                        help=('Verbose mode. Causes %(prog)s to print '
                              'messages about its progress. Multiple options '
                              'increases the verbosity. The maximum is 2.'))
    parser.add_argument('--utc', action='store_false', dest='log_localtime',
                        help=('Output logging statements in UTC instead of '
                              'local time.'))
    parsed_args = parser.parse_args()

    if parsed_args.log_level == 0:
        parsed_args.log_level = logging.WARNING
    elif parsed_args.log_level == 1:
        parsed_args.log_level = logging.INFO
    else:
        parsed_args.log_level = logging.DEBUG

    if parsed_args.tmpdir in ('.', './'):
        parsed_args.tmpdir = os.getcwd()

    if parsed_args.packages == '':
        parsed_args.packages = []
    else:
        parsed_args.packages = set(parsed_args.packages.split(','))

    return parsed_args


def is_root() -> bool:
    """Check if process is running with root privileges."""
    return os.geteuid() == 0


def exec_chroot(root: Path,
                cmd: Sequence[str],
                cwd: Path = Path('/'),
                output: bool = False) -> subprocess.CompletedProcess:
    """Changes root and current working path and executes given command."""
    logger = logging.getLogger(__name__)
    pid = os.fork()
    if pid:
        _, status = os.waitpid(pid, 0)
        if status:
            if os.WIFSIGNALED(status):
                returncode = os.WTERMSIG(status)
                if returncode in (-2, -15):
                    raise KeyboardInterrupt()
            else:
                returncode = os.WEXITSTATUS(status)
        else:
            returncode = 0
        res = subprocess.CompletedProcess(cmd, returncode)
        res.check_returncode()
        return res
    else:
        stdout: Optional[int] = subprocess.DEVNULL
        if output is True:
            stdout = None
        logger.debug('running %s in %s', ' '.join(cmd), root)
        returncode = -1
        try:
            os.chroot(root)
            env = {
                'DEBIAN_FRONTEND': 'noninteractive',
                'INITRD': 'no',
                'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8',
                'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            }
            proc = subprocess.run(cmd, stdout=stdout, cwd=cwd, env=env,
                                  check=True)
            returncode = proc.returncode
        except subprocess.CalledProcessError as err:
            returncode = err.returncode
        except OSError as err:
            returncode = err.errno
        finally:
            os._exit(returncode)


def make_tempdir(prefix: Optional[str] = None,
                 tmp_dir: Optional[Path] = None) -> Path:
    """Creates a temporary directory. The path is resolved and returned."""
    logger = logging.getLogger(__name__)
    tmp_path: Optional[str]
    if tmp_dir is not None:
        tmp_path = os.fspath(tmp_dir)
    else:
        tmp_path = None
    try:
        tmp_dirname = mkdtemp(prefix=prefix, dir=tmp_path)
    except OSError as err:
        logger.exception('Error while creating temporary directory in %s: %s',
                         tmp_path, str(err))
        raise

    try:
        temp = Path(tmp_dirname).resolve(True)
    except (FileNotFoundError, RuntimeError) as err:
        logger.exception('Error resolving %s to an absolute path: %s',
                         tmp_dirname, str(err))
        raise
    return temp


def delete_tempdir(tmp_dir: Path) -> None:
    """Recursively delete given directory."""
    logger = logging.getLogger(__name__)
    path = os.fspath(tmp_dir)
    logger.debug('deleting temporary directory %s', path)
    rmtree(path)


def build_image(archive: Path,
                tmp_dir: Path,
                tags: Sequence[str] = (),
                output: bool = False) -> None:
    """Build docker image from bootstrap image."""
    logger = logging.getLogger(__name__)

    archive = Path(archive)
    dockerfile_content = """
        FROM scratch
        ADD {} /
        # allow automated installation of new packages
        ENV DEBIAN_FRONTEND=noninteractive
        # skip initramfs post-install hooks
        ENV INITRD=no
        # fix locale
        ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
        ENTRYPOINT ["/sbin/root_pid.py"]
        CMD ["/bin/bash"]
        """.format(archive.name)
    stdout: Optional[int] = subprocess.DEVNULL
    if output is True:
        stdout = None
    build_dir = make_tempdir(TMP_PREFIX+'build-', tmp_dir)
    try:
        logger.debug('create context in %s', build_dir)
        copy2(os.fspath(archive), os.fspath(build_dir))
        dockerfile = Path(build_dir/'Dockerfile')
        with dockerfile.open('wt') as fhandle:
            fhandle.write(dockerfile_content)
        cmd: List[str] = ['docker', 'build']
        for tag in tags:
            cmd.append('-t')
            cmd.append(tag)
        cmd.append(os.fspath(build_dir))
        logger.info('Running docker build')
        logger.debug('running %s', ' '.join(cmd))
        try:
            subprocess.run(cmd, stdout=stdout, check=True)
        except subprocess.CalledProcessError as err:
            if err.returncode in (-2, -15):
                raise KeyboardInterrupt()
            else:
                logger.error('Error while running docker build: %s', str(err))
                raise
    finally:
        delete_tempdir(build_dir)


class Bootstrap(object):
    """Create a bootstrap image, tune it for use with docker and archive it."""

    default_packages: Sequence[str] = ('python3-minimal',)

    def __init__(self, suite: str, tmp_dir: Path,
                 output: bool = False, reduce_size: bool = False) -> None:
        self._suite = suite
        self.tmp_dir = tmp_dir
        self._target: Path
        self.output = output
        self.reduce_size = reduce_size

    def __enter__(self):
        logger = logging.getLogger(__name__)
        self._target = make_tempdir(TMP_PREFIX+'rootfs-', self.tmp_dir)
        logger.debug('bootstrapping into %s', self._target)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        delete_tempdir(self._target)

    def init(self,
             mirror: Optional[str] = None,
             packages: Iterable[str] = ()) -> None:
        """Running debootstrap."""
        logger = logging.getLogger(__name__)
        cmd: List[str] = ['debootstrap', '--variant=minbase',
                          '--force-check-gpg', '--merged-usr']
        include = list(self.default_packages)
        include.extend(packages)
        if include:
            cmd.append('--include='+','.join(include))
        cmd.append(self._suite)
        cmd.append(os.fspath(self._target))
        if mirror is not None:
            cmd.append(mirror)
        stdout = None if self.output is True else subprocess.DEVNULL
        logger.info('Running debootstrap')
        logger.debug('running %s', ' '.join(cmd))
        try:
            subprocess.run(cmd, stdout=stdout, check=True)
        except subprocess.CalledProcessError as err:
            if err.returncode in (-2, -15):
                raise KeyboardInterrupt()
            else:
                logger.error('debootstrap returned non-zero exit status %d.',
                             err.returncode)
                raise

    def _presetup_initctl(self) -> None:
        """Prevent upstart scripts from running during install/update and fix
        some issues with APT packages.

        https://github.com/saltstack/salt/issues/11118
        If your application uses upstart, this wont fit well in bare docker
        images, and even more if they divert /sbin/init or /sbin/initctl to
        something like /bin/true or /dev/null. You application may use service
        to start if this one has an old school systemV initscript and if the
        initctl command has not been diverted.
        In the case of salt-minion, on Ubuntu the packaging uses an upstart job
        and no classical init script so it is normal that it wont start in both
        cases.

        https://github.com/docker/docker/issues/1024
        Because Docker replaces the default /sbin/init with its own, there's no
        way to run the Upstart init inside a Docker container.
        """
        cmds = (
            ('dpkg-divert', '--local', '--rename', '/sbin/initctl'),
            ('ln', '-sf', '/bin/true', '/sbin/initctl'),
        )
        for cmd in cmds:
            exec_chroot(self._target, cmd, output=self.output)

    def _presetup_ichroot(self) -> None:
        """Replace the 'ischroot' tool to make it always return true.

        Prevent initscripts updates from breaking /dev/shm.
        https://journal.paul.querna.org/articles/2013/10/15/docker-ubuntu-on-rackspace/
        https://bugs.launchpad.net/launchpad/+bug/974584
        """
        cmds = (
            ('dpkg-divert', '--local', '--rename', '--add', '/usr/bin/ischroot'),
            ('ln', '-sf', '/bin/true', '/usr/bin/ischroot'),
        )
        for cmd in cmds:
            exec_chroot(self._target, cmd, output=self.output)

    def _presetup_policyrcd(self) -> None:
        """Prevent starting services by policy."""
        content = """\
        #!/bin/sh

        # For most Docker users, "apt-get install" only happens during
        # "docker build", where starting services doesn't work and often fails
        # in humorous ways. This prevents those failures by stopping the
        # services from attempting to start.

        exit 101
        """
        with (self._target/'usr'/'sbin'/'policy-rc.d').open('wt') as fhandle:
            fhandle.write(textwrap.dedent(content))

    def _presetup_dpkg_unsafeio(self) -> None:
        """Skip fsync on package installation.

        dpkg calls sync() after package extraction, but when building an image
        we don’t need to worry about individual fsyncs.
        """
        found = False
        with (self._target/'usr'/'bin'/'dpkg').open('rb') as fhandle:
            with mmap(fhandle.fileno(), 0, access=ACCESS_READ) as memmap:
                pos = memmap.find(b'unsafe-io')
                found = pos != -1
        if found is True:
            content = """\
            # For most Docker users, package installs happen during
            # "docker build", which doesn't survive power loss and gets
            # restarted clean afterwards anyhow, so this minor tweak gives
            # us a nice speedup (much nicer on spinning disks, obviously).
            force-unsafe-io
            """
            path = self._target/'etc'/'dpkg'/'dpkg.cfg.d'/'docker-dpkg-speedup'
            with path.open('wt') as fhandle:
                fhandle.write(textwrap.dedent(content))

    def _presetup_autoremove_suggests(self) -> None:
        """Configure APT to be aggressive about removing the packages it
        added.
        """
        content = """\
        # Since Docker users are looking for the smallest possible final
        # images, the following emerges as a very common pattern:
        #   RUN apt-get update \
        #       && apt-get install -y <packages> \
        #       && <do some compilation work> \
        #       && apt-get purge -y --auto-remove <packages>
        # By default, APT will actually _keep_ packages installed via
        # Recommends or Depends if another package Suggests them, even and
        # including if the package that originally caused them to be installed
        # is removed.  Setting this to "false" ensures that APT is
        # appropriately aggressive about removing the packages it added.
        # https://aptitude.alioth.debian.org/doc/en/ch02s05s05.html#configApt-AutoRemove-SuggestsImportant
        Apt::AutoRemove::SuggestsImportant "false";
        """
        path = \
            self._target/'etc'/'apt'/'apt.conf.d'/'docker-autoremove-suggests'
        with path.open('wt') as fhandle:
            fhandle.write(textwrap.dedent(content))

    def _presetup_no_languages(self) -> None:
        """Do not download translation files."""
        content = """\
        # In Docker, we don't often need the "Translations" files, so we're
        # just wasting time and space by downloading them, and this inhibits
        # that.  For users that do need them, it's a simple matter to delete
        # this file and "apt-get update". :)
        Acquire::Languages "none";
        """
        path = self._target/'etc'/'apt'/'apt.conf.d'/'docker-no-languages'
        with path.open('wt') as fhandle:
            fhandle.write(textwrap.dedent(content))

    def _presetup_gzip_indexes(self) -> None:
        """Request zipped version of indexes."""
        content = """\
        # Since Docker users using
        # "RUN apt-get update && apt-get install -y ..." in their Dockerfiles
        # don't go delete the lists files afterwards, we want them to be as
        # small as possible on-disk, so we explicitly request "gz" versions and
        # tell Apt to keep them gzipped on-disk. For comparison, an
        # "apt-get update" layer without this on a pristine "debian:wheezy"
        # base image was "29.88 MB", where with this it was only "8.273 MB".
        Acquire::GzipIndexes "true";
        Acquire::CompressionTypes::Order:: "gz";
        """
        path = self._target/'etc'/'apt'/'apt.conf.d'/'docker-gzip-indexes'
        with path.open('wt') as fhandle:
            fhandle.write(textwrap.dedent(content))

    def _presetup_dpkg_path_exclude(self) -> None:
        """Reducing the size of the image by excluding unnecessary files, like
        man pages, docs, translations and so on.
        """
        content = """\
        path-exclude */__pycache__/*
        path-exclude /usr/share/doc/*
        # we need to keep copyright files for legal reasons
        path-include /usr/share/doc/*/copyright
        path-exclude /usr/share/groff/*
        path-exclude /usr/share/info/*
        path-exclude /usr/share/lintian/*
        path-exclude /usr/share/linda/*
        path-exclude /usr/share/locale/*
        path-exclude /usr/share/man/*
        """
        path = self._target/'etc'/'dpkg'/'dpkg.cfg.d'/'path_exclude'
        with path.open('wt') as fhandle:
            fhandle.write(textwrap.dedent(content))

    def presetup(self) -> None:
        """Pre setup steps before copying resources and running upgrade."""
        logger = logging.getLogger(__name__)
        logger.info('Pre Setup')

        self._presetup_initctl()
        self._presetup_ichroot()
        self._presetup_policyrcd()
        self._presetup_dpkg_unsafeio()
        self._presetup_autoremove_suggests()
        self._presetup_no_languages()
        self._presetup_gzip_indexes()
        if self.reduce_size is True:
            self._presetup_dpkg_path_exclude()

        # TODO:
        #  commands = [
        #      # rename /sbin/init so we can use telinit to restart the thing.
        #      ['dpkg-divert', '--local', '--rename', '/sbin/init'],
        #
        #      ['dpkg-divert', '--local', '--divert', '/etc/syslog.conf.internal',
        #      '--rename', '/etc/syslog.conf'],
        #
        #      ['dpkg-divert', '--local', '--divert', '/sbin/sulogin.real',
        #      '--rename', '/sbin/sulogin'],
        #  ]
        #  for cmd in commands:
        #      exec_chroot(self._target, cmd, output=self.output)

    def copy_resources(self, sources: Iterable[Path]) -> None:
        """Recursively copy given resources to target preserving mode and time, but
        not symlinks.
        """
        logger = logging.getLogger(__name__)
        logger.info('Copying resources')
        dest = os.fspath(self._target)
        for source in sources:
            result = copy_tree(os.fspath(source), dest)
            for path in result:
                logger.debug('copied %s', path)

    def _postsetup_rootpid(self) -> None:
        """Install root_pid.py into bootstrap image."""
        src = Path('root_pid.py')
        dst = self._target/'sbin'
        copy(os.fspath(src), os.fspath(dst))

    def _postsetup_autoremove_kernels(self) -> None:
        """Allow apt to autoremove kernels."""
        # this file is one APT creates to make sure we don't "autoremove" our
        # currently in-use kernel, which doesn't really apply to
        # debootstraps/Docker images that don't even have kernels installed
        path = self._target/'etc'/'apt'/'apt.conf.d'/'01autoremove-kernels'
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def postsetup(self) -> None:
        """Post setup steps after copying resources and upgrade."""
        logger = logging.getLogger(__name__)
        logger.info('Post Setup')
        self._exec_aptget(['remove', '--purge', '--auto-remove', 'systemd'])
        self._postsetup_rootpid()
        self._postsetup_autoremove_kernels()

    def upgrade(self) -> None:
        """Running security and suite upgrade."""
        logger = logging.getLogger(__name__)
        logger.info('Upgrading suite')

        self._add_apt_securityupdate(self._suite)
        self._exec_aptget(['update'])
        self._exec_aptget(['dist-upgrade'])

    def _add_apt_securityupdate(self, suite: str) -> None:
        """Adds security updates to apt sources.list."""
        logger = logging.getLogger(__name__)

        if suite == 'sid' or suite == 'unstable':
            return

        apt_path = Path(self._target/'etc'/'apt')
        try:
            apt_path.mkdir(parents=True)
        except FileExistsError:
            pass
        sources = Path(apt_path/'sources.list')
        src_sec_line = 'deb http://security.debian.org {}/updates main'.format(
            suite)
        with sources.open('a+t') as source_fh:
            for line in source_fh:
                if line.rstrip('\r\n') == src_sec_line:
                    break
            else:
                logger.debug('adding "%s" to %s',
                             src_sec_line, sources.relative_to(self._target))
                source_fh.write(src_sec_line)

    def _iter_uncritical_paths(self) -> Iterator[Path]:
        target = self._target
        yield from (target/'usr'/'lib').glob('python*/**/__pycache__/')
        yield from (target/'usr'/'share').glob('python*/**/__pycache__/')
        yield from (target/'var'/'cache'/'apt').glob('*.bin')
        yield from (target/'var'/'cache'/'apt'/'archives').glob('**/*.deb')
        yield from (target/'var'/'cache'/'debconf').glob('**/*')
        yield target/'var'/'cache'/'man'
        yield from (target/'var'/'lib'/'apt'/'lists').glob('**/*')

    def _iter_aggressive_size_path(self) -> Iterator[Path]:
        target = self._target
        for path in (target/'usr'/'share'/'doc').glob('*/**/*'):
            if not path.match('*/copyright'):
                yield path
        yield target/'usr'/'share'/'groff'
        yield target/'usr'/'share'/'info'
        yield target/'usr'/'share'/'linda'
        yield target/'usr'/'share'/'lintian'
        yield from (target/'usr'/'share'/'locale').glob('*/')
        yield target/'usr'/'share'/'man'

    def cleanup(self) -> None:
        """Cleanup image in favor of size."""
        logger = logging.getLogger(__name__)
        logger.info('Cleanup bootstrap image')

        self._exec_aptget(['autoremove', '--purge'])
        self._exec_aptget(['autoclean'])
        self._exec_aptget(['clean'])

        logger.debug('clear apt cache')
        paths = self._iter_uncritical_paths()
        if self.reduce_size is True:
            paths = chain(paths, self._iter_aggressive_size_path())
        for path in paths:
            logger.debug('removing %s', os.fspath(path))
            if path.is_dir():
                if path.is_symlink():
                    link = path
                    path = path.resolve()
                    link.unlink()
                rmtree(os.fspath(path))
            else:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

        # Disable some init scripts that aren't relevant in Docker
        logger.debug('disabling init scripts')
        init_scripts = ('bootlogs', 'checkfs.sh', 'checkroot.sh',
                        'checkroot-bootclean.sh', 'hostname.sh', 'hwclock.sh',
                        'motd', 'mountall.sh', 'mountall-bootclean.sh',
                        'mountdevsubfs.sh', 'mountkernfs.sh', 'mountnfs.sh',
                        'mountnfs-bootclean.sh', 'procps', 'umountfs',
                        'umountnfs.sh', 'umountroot', 'urandom')
        cmd = ['update-rc.d', '-f', '', 'remove']
        for script in init_scripts:
            tmp_cmd = cmd[:]
            tmp_cmd[2] = script
            exec_chroot(self._target, tmp_cmd, output=self.output)

        # Let daemons start
        logger.debug('renaming policy-rc.d to let daemons start')
        policy_path = self._target/'usr'/'sbin'/'policy-rc.d'
        policy_path.rename(policy_path.with_suffix('.d.disabled'))

    def _exec_aptget(self,
                     args: Sequence[str]) -> subprocess.CompletedProcess:
        cmd = ['apt-get', '-y', '--no-install-recommends']
        cmd.extend(args)
        return exec_chroot(self._target, cmd, output=self.output)

    def archive(self, dest: Path) -> None:
        """Create archive from given directory."""
        logger = logging.getLogger(__name__)
        logger.info('Archiving bootstrap image')

        logger.debug('adding %s to %s',
                     os.fspath(self._target), os.fspath(dest))
        with tarfile.open(os.fspath(dest), 'w:gz') as tar:
            tar.add(os.fspath(self._target), '/')

    def create(self, dest: Path, resources: Iterable[Path] = (),
               packages: Iterable[Path] = (),
               mirror: Optional[str] = None,
               security_update: bool = True) -> None:
        """Does the whole bootstrapping in one call."""
        with self as bs_img:
            bs_img.init(mirror, packages)
            bs_img.presetup()
            bs_img.copy_resources(resources)
            if security_update is True:
                bs_img.upgrade()
            bs_img.postsetup()
            bs_img.cleanup()
            bs_img.archive(dest)


class ArchiveOperation(Enum):
    """Enumeration of possible archive operations."""
    SELECT = 1
    CREATE = 2
    UPDATE = 4


def is_tarfile(path: Path) -> bool:
    """Check if given path is readable and a valid tar archive."""
    try:
        return tarfile.is_tarfile(os.fspath(path))
    except FileNotFoundError:
        return False


def main() -> None:
    """The main function checks for permissions, creates a temporary directory,
    debootrap into it, may copy resources. After all the directory is archived
    and deleted.
    """
    args = parse_arguments()
    setup_logging(args.log_level, args.log_localtime)
    logger = logging.getLogger(__name__)
    logger.debug('parsed arguments: %s', args)

    if not is_root():
        logger.error('bootstrapping needs to be done as root')
        sys.exit(os.EX_NOPERM)

    arch_op: Optional[ArchiveOperation] = None
    if is_tarfile(args.archive):
        logger.debug('archive %s already exists', args.archive)
        if args.packages or args.reduce_size or args.suite is not None:
            logger.debug('recreating archive with packages %s',
                         sorted(args.packages))
            arch_op = ArchiveOperation.UPDATE
        else:
            arch_op = ArchiveOperation.SELECT
    elif args.archive.exists():
        logger.error('seems %s is not a archive', args.archive)
        sys.exit(2)
    else:
        logger.debug('no bootstrap archive found matching %s', args.archive)
        arch_op = ArchiveOperation.CREATE

    output = args.log_level < logging.INFO
    bs_img: Path = args.archive
    if arch_op in (ArchiveOperation.CREATE,
                   ArchiveOperation.UPDATE):
        rootfs = Bootstrap(args.suite or 'stable', args.tmpdir, output,
                           args.reduce_size)
        rootfs.create(args.archive, args.copy_dir, args.packages, args.mirror,
                      args.security_update)
    build_image(bs_img, args.tmpdir, args.tags, output=output)


if __name__ == '__main__':
    main()
