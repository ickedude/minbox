# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).


## [Unreleased]
### Changed
- moved biggest part of bootstrap cleanup into new img_build.py script

## [0.3.0] - 2018-06-27
### Added
- root_pid.py accepts graceful termination timeout argument
- added option --utc to log messages with UTC timestamp instead of local time
- added option --no-security-update for offline creation of images
- added option --reduce-size to create an reduced image without docs and so on

### Changed
- refactored root_pid.py to depend only on python3-minimal
- creating /{bin,sbin,lib}/ symlinks pointing to their counterparts in /usr/
- rebuild image if --suite option is given
- moved resources into bootstrap.py script

### Fixed
- aligned unsafe-io file name to corresponding resource file
- logging OS errors on executing command
- set environment variables in docker image equivalent to chroot
- fixed uninitialized var in exec_chroot for unhandled errors

## [0.2.0] - 2018-06-04
### Added
- bootstrap script to build debian docker images from scratch
- resource files to tweak the behavior of debian running in docker

## [0.1.0] - 2018-05-15
### Added
- minimalist init system spawning process from command line arguments and reaping all children
