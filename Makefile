# MAKEFILE
#
# @author      Nicola Asuni <nicola.asuni@miracl.com>
# @link        https://github.com/miracl/milagro-crypto-c
#
# This file is intended to be executed in a Linux-compatible system and requires
# the packages listed in resources/DockerDev/Dockerfile to execute the build in
# the current environment, or Docker to build everything inside a Docker 
# container via the command "make dbuild".
#
# ------------------------------------------------------------------------------

# List special make targets that are not associated with files
.PHONY: help all format clean qa build build_item buildx dbuild

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

# build options <NAME>:<COMMA-SEPARATED_LIST_OF_CMAKE_OPTIONS>
BUILDS=ASAN:-DCMAKE_BUILD_TYPE=ASan,-DAMCL_CHUNK=64,-DBUILD_WCC=on \
	COVERAGE:-DCMAKE_BUILD_TYPE=Coverage,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64 \
	WINDOWS_32BIT_BN254_CX:-DCMAKE_TOOLCHAIN_FILE=../../resources/cmake/mingw32-cross.cmake,-DAMCL_CHUNK=32 \
	WINDOWS_64BIT_BN254_CX:-DCMAKE_TOOLCHAIN_FILE=../../resources/cmake/mingw64-cross.cmake,-DAMCL_CHUNK=64 \
	LINUX_32BIT_BN254_CX:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=32 \
	LINUX_64BIT_BN254_CX:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64 \
	LINUX_64BIT_BN254_CX_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DBUILD_PYTHON=on,-DBUILD_GO=on,-DGO_PATH=${GOPATH} \
	LINUX_64BIT_BN254_CX_ANONYMOUS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DUSE_ANONYMOUS=on \
	LINUX_64BIT_NIST256_RSA1024:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DAMCL_CHOICE=NIST256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=4 \
	LINUX_64BIT_NIST256_RSA2048:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DAMCL_CHOICE=NIST256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=8 \
	LINUX_64BIT_NIST256_RSA4096:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DAMCL_CHOICE=NIST256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=16 \
	LINUX_64BIT_NIST384_RSA3072:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DAMCL_CHOICE=NIST384,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=8 \
	LINUX_64BIT_NIST521:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DAMCL_CHOICE=NIST521,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=4 \
	LINUX_64BIT_C25519_RSA2048_MONTGOMERY:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DAMCL_CHOICE=C25519,-DAMCL_CURVETYPE=MONTGOMERY,-DAMCL_FFLEN=8 \
	LINUX_64BIT_C25519_RSA2048_EDWARDS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DAMCL_CHOICE=C25519,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8 \
	LINUX_64BIT_GOLDILOCKS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=64,-DAMCL_CHOICE=GOLDILOCKS,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8

# variables used in text substitution
comma := ,
space :=
space +=

# --- MAKE TARGETS ---

# Display general help about this command
help:
	@echo ""
	@echo "$(PROJECT) Makefile."
	@echo "The following commands are available:"
	@echo ""
	@echo "    make format   : Format the source code"
	@echo "    make clean    : Remove any build artifact"
	@echo "    make qa       : build all versions and generate reports"
	@echo "    make dbuild   : build everything inside a Docker container"
	@echo ""
	@echo "    You can also build the following predefined types:"
	@echo ""
	@$(foreach PARAMS,$(BUILDS), \
		echo "    make build TYPE=$(word 1,$(subst :, ,${PARAMS}))" ; \
	)
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
	autopep8 --in-place --aggressive --aggressive ./wrappers/python/*.py

# Remove any build artifact
clean:
	mkdir -p target/
	rm -rf ./target/*

# execute all builds and tests
qa:
	@mkdir -p target/
	@echo 0 > target/make_qa.exit
	@echo '' > target/make_qa_errors.log
	@$(foreach ITEM,$(BUILDS), \
		make build_item ITEM=${ITEM} \
		|| (echo $$? > target/make_qa.exit && echo ${ITEM} >> target/make_qa_errors.log); \
	)
	@cat target/make_qa_errors.log
	@exit `cat target/make_qa.exit`

# build the project using one of the pre-defined targets (example: "make build TYPE=COVERAGE")
build:
	make build_item ITEM=$(filter ${TYPE}:%,$(BUILDS))

# build the specified item entry from the BUILDS list
build_item:
	make buildx BUILD_NAME=$(word 1,$(subst :, ,${ITEM})) BUILD_PARAMS=$(word 2,$(subst :, ,${ITEM}))

# Build with the specified parameters
buildx:
	@echo -e "\n\n*** BUILD ${BUILD_NAME} ***\n"
	rm -rf target/${BUILD_NAME}/*
	mkdir -p target/${BUILD_NAME}/coverage
	cd target/${BUILD_NAME} && \
	cmake $(subst $(comma),$(space),${BUILD_PARAMS}) ../.. | tee cmake.log ; test $${PIPESTATUS[0]} -eq 0 && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log ; test $${PIPESTATUS[0]} -eq 0
ifeq (${BUILD_NAME},COVERAGE)
	cd target/${BUILD_NAME} && \
	lcov --zerocounters --directory . && \
	lcov --capture --initial --directory . --output-file coverage/amcl && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log ; test $${PIPESTATUS[0]} -eq 0 && \
	lcov --no-checksum --directory . --capture --output-file coverage/amcl.info && \
	genhtml -o coverage -t "milagro-crypto-c Test Coverage" coverage/amcl.info && \
	make doc
else
	cd target/${BUILD_NAME} && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log ; test $${PIPESTATUS[0]} -eq 0
endif

# build everything inside a Docker container
dbuild:
	./dockerbuild.sh
	@exit `cat target/make_qa.exit`
