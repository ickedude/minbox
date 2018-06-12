# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).


## [Unreleased]
### Fixed
- aligned unsafe-io file name to corresponding resource file
- refactored root_pid.py to depend only on python3-minimal

## [0.2.0] - 2018-06-04
### Added
- bootstrap script to build debian docker images from scratch
- resource files to tweak the behavior of debian running in docker

## [0.1.0] - 2018-05-15
### Added
- minimalist init system spawning process from command line arguments and reaping all children
