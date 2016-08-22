# MAKEFILE
#
# @author      Nicola Asuni <nicola.asuni@miracl.com>
# @link        https://github.com/miracl/milagro-crypto-c
#
# This file is intended to be executed in a Linux-compatible system and requires
# the packages lised in resources/DockerDev/Dockerfile to execute the build in
# the current environment or Dcker to use the Docker build (dbuild).
#
# ------------------------------------------------------------------------------

# List special make targets that are not associated with files
.PHONY: help all format analyze clean dbuild qa build_coverage build_linux64wrappers build_linux64anonymous build_linux64 build_linux32 build_win64 build_win32

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
	@echo "    make format                 : Format the source code"
	@echo "    make analyze                : Analyze the source code for security weaknesses"
	@echo "    make clean                  : Remove any build artifact"
	@echo "    make dbuild                 : build everything inside a Docker container"
	@echo ""
	@echo "    make qa                     : execute all the following testing builds and generate reports"
	@echo ""
	@echo "    make build_coverage         : build and test with coverage for for linux 64bit"
	@echo "    make build_linux64wrappers  : build and test for linux 64bit with the wrappers"
	@echo "    make build_linux64anonymous : build and test for linux 64bit with the anonymous option on"
	@echo "    make build_linux64          : build and test for linux 64bit"
	@echo "    make build_linux32          : build and test for linux 32bit"
	@echo "    make build_win64            : build and test for windows 64bit (cross-build)"
	@echo "    make build_win32            : build and test for windows 32bit (cross-build)"
	@echo ""

# Alias for help target
all: help

# Format the source code
format:
	astyle --style=allman --recursive --suffix=none 'include/*.h'
	astyle --style=allman --recursive --suffix=none 'include/*.h.in'
	astyle --style=allman --recursive --suffix=none 'src/*.c'
	astyle --style=allman --recursive --suffix=none 'test/*.c'
	find ./wrappers/go -type f -name "*.go" -exec gofmt -s -w {} \;
	find ./wrappers/go -type f -name "*.go.in" -exec gofmt -s -w {} \;
	autopep8 --in-place --aggressive ./wrappers/python/*.py

# Analyze the source code for security weaknesses 
analyze:
	@echo -e "\n\n*** Run Address Sanitizer ***\n\n"
	mkdir -p target/build_asan
	rm -rf target/build_asan/*
	cd target/build_asan && \
	cmake  -D CMAKE_BUILD_TYPE=ASan -D WORD_LENGTH=64 -D BUILD_WCC=on ../.. | tee cmake.log && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log

# Remove any build artifact
clean:
	mkdir -p target/
	rm -rf ./target/*

# build everything inside a Docker container
dbuild:
	@mkdir -p target
	./dockerbuild.sh

# execute all builds and tests
qa: analyze build_coverage build_linux64wrappers build_linux64anonymous build_linux32 build_win64 build_win32

# BUILD FOR COVERAGE
build_coverage:
	@echo -e "\n\n*** BUILD FOR COVERAGE ***\n"
	mkdir -p target/build_test/coverage
	rm -rf target/build_test/*
	mkdir -p target/build_test/coverage
	cd target/build_test && \
	cmake -D CMAKE_BUILD_TYPE=Coverage -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 -D BUILD_WCC=on ../.. | tee cmake.log && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log && \
	lcov --zerocounters --directory . && \
	lcov --capture --initial --directory . --output-file coverage/amcl && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log && \
	lcov --no-checksum --directory . --capture --output-file coverage/amcl.info && \
	genhtml -o coverage -t "milagro-crypto-c Test Coverage" coverage/amcl.info && \
	make doc

# BUILD LINUX 64 WRAPPERS
build_linux64wrappers:
	@echo -e "\n\n*** BUILD LINUX 64 WRAPPERS ***\n\n"
	mkdir -p target/build_linux64_wrappers
	rm -rf target/build_linux64_wrappers/*
	cd target/build_linux64_wrappers && \
	cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 -D BUILD_PYTHON=on -D BUILD_GO=on -D GO_PATH=${GOPATH} -D BUILD_WCC=on ../.. | tee cmake.log && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log && \
	go get github.com/stretchr/testify/assert && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log

# BUILD LINUX 64 ANONYMOUS
build_linux64anonymous:
	@echo -e "\n\n*** BUILD LINUX 64 ANONYMOUS ***\n\n"
	mkdir -p target/build_linux64_anonymous
	rm -rf target/build_linux64_anonymous/*
	cd target/build_linux64_anonymous && \
	cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 -D USE_ANONYMOUS=on -D BUILD_WCC=on ../.. | tee cmake.log && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log

# BUILD LINUX 64
build_linux64:
	@echo -e "\n\n*** BUILD LINUX 64 ***\n\n"
	mkdir -p target/build_linux64
	rm -rf target/build_linux64/*
	cd target/build_linux64 && \
	cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 ../.. | tee cmake.log && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log

# BUILD LINUX 32
build_linux32:
	@echo -e "\n\n*** BUILD LINUX 32 ***\n\n"
	mkdir -p target/build_linux32
	rm -rf target/build_linux32/*
	cd target/build_linux32 && \
	cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=32 ../.. | tee cmake.log && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log

# BUILD WIN 64
build_win64:
	@echo -e "\n\n*** BUILD WIN 64 ***\n\n"
	mkdir -p target/build_win64
	rm -rf target/build_win64/*
	cd target/build_win64 && \
	cmake -D CMAKE_TOOLCHAIN_FILE=../../resources/cmake/mingw64-cross.cmake -D WORD_LENGTH=64 ../.. | tee cmake.log && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log

# BUILD WIN 32
build_win32:
	@echo -e "\n\n*** BUILD WIN 32 ***\n\n"
	mkdir -p target/build_win32
	rm -rf target/build_win32/*
	cd target/build_win32 && \
	cmake -D CMAKE_TOOLCHAIN_FILE=../../resources/cmake/mingw32-cross.cmake -D WORD_LENGTH=32 ../.. | tee cmake.log && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log
