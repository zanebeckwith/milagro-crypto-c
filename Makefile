# MAKEFILE
#
# @author      Nicola Asuni <nicola.asuni@miracl.com>
# @link        https://github.com/miracl/milagro-crypto-c
#
# This file is intended to be executed in a Linux-compatible system.
#
# It also requires th astyle package to format the C code,
# the GO language and the python-autopep8 to format the python code
#
# ------------------------------------------------------------------------------

# List special make targets that are not associated with files
.PHONY: help all format analyze clean dbuild

# Use bash as shell (Note: Ubuntu now uses dash which doesn't support PIPESTATUS).
SHELL=/bin/bash

# Project owner
OWNER=miracl

# Project vendor
VENDOR=${OWNER}

# Project name
PROJECT=amcl

# Project version
VERSION=$(shell cat VERSION)

# Project release number (packaging build number)
RELEASE=$(shell cat RELEASE)

# --- MAKE TARGETS ---

# Display general help about this command
help:
	@echo ""
	@echo "$(PROJECT) Makefile."
	@echo "The following commands are available:"
	@echo ""
	@echo "    make format      : Format the source code"
	@echo "    make analyze     : Analyze the source code for security weaknesses"
	@echo "    make clean       : Remove any build artifact"
	@echo "    make dbuild      : build everything inside a Docker container"
	@echo ""

# Alias for help target
all: help

# Format the source code
format:
	astyle --style=allman --recursive 'src/*.c'
	astyle --style=allman --recursive 'test/*.c'
	find ./wrappers/go -type f -name "*.go" -exec gofmt -s -w {} \;
	find ./wrappers/go -type f -name "*.go.in" -exec gofmt -s -w {} \;
	autopep8 --in-place --aggressive ./wrappers/python/*.py

# Analyze the source code for security weaknesses (requires flawfinder)
analyze:
	flawfinder src/*.c

# Remove any build artifact
clean:
	rm -rf ./target
	go clean -i ./...

# build everything inside a Docker container
dbuild:
	@mkdir -p target
	./dockerbuild.sh
