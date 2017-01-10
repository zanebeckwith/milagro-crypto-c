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
# Requires GNU parallel: https://www.gnu.org/software/parallel/
# ------------------------------------------------------------------------------

# List special make targets that are not associated with files
.PHONY: help all default format clean qa build_group build build_qa_item build_item buildx buildall dbuild pubdocs

# Use bash as shell (Note: Ubuntu now uses dash which doesn't support PIPESTATUS).
SHELL=/bin/bash

# Project root directory
PROJECTROOT=$(shell pwd)

# CVS path (path to the parent dir containing the project)
CVSPATH=github.com/miracl

# Project owner
OWNER=MIRACL

# Project vendor
VENDOR=miracl

# Project name
PROJECT=amcl

# Project version
VERSION=$(shell cat VERSION)

# Project release number (packaging build number)
RELEASE=$(shell cat RELEASE)

# Include default build configuration
include $(PROJECTROOT)/config.mk

# Common CMake options for building the language wrappers
WRAPPERS="-DBUILD_PYTHON=on,-DBUILD_GO=on,-DGO_PATH=${GOPATH}"

# Space-separated list of build options (grouped by type):
# <NAME>:<COMMA-SEPARATED_LIST_OF_CMAKE_OPTIONS>

BUILDS_QA=ASAN:-DCMAKE_BUILD_TYPE=ASan,-DBUILD_WCC=on \
	COVERAGE:-DCMAKE_BUILD_TYPE=Coverage,-DCMAKE_INSTALL_PREFIX=/opt/amcl \
	WINDOWS_32BIT_BN254_CX:-DCMAKE_TOOLCHAIN_FILE=../../resources/cmake/mingw32-cross.cmake,-DAMCL_CHUNK=32 \
	WINDOWS_64BIT_BN254_CX:-DCMAKE_TOOLCHAIN_FILE=../../resources/cmake/mingw64-cross.cmake \
	LINUX_32BIT_BN254_CX_ANONYMOUS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DUSE_ANONYMOUS=on,-DAMCL_CHUNK=32 \
	LINUX_64BIT_BN254_CX_ANONYMOUS_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DUSE_ANONYMOUS=on,${WRAPPERS} \
	LINUX_32BIT_BN254_CX:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHUNK=32 \
	LINUX_64BIT_BN254_CX:-DCMAKE_INSTALL_PREFIX=/opt/amcl \
	LINUX_64BIT_BN254_CX_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,${WRAPPERS}

BUILDS_64=LINUX_64BIT_BN454_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BN454,-DAMCL_FFLEN=4,${WRAPPERS} \
	LINUX_64BIT_BN254_T_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BN254_T,${WRAPPERS} \
	LINUX_64BIT_BN254_T2_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BN254_T2,${WRAPPERS} \
	LINUX_64BIT_BLS383_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BLS383,${WRAPPERS} \
	LINUX_64BIT_BLS455_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BLS455,${WRAPPERS} \
	LINUX_64BIT_BN646_WRAPPERS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BN646,-DAMCL_FFLEN=4,${WRAPPERS} \
	LINUX_64BIT_NIST256_RSA2048:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=NIST256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=8 \
	LINUX_64BIT_NIST256_RSA4096:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=NIST256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=16 \
	LINUX_64BIT_C25519_RSA2048_MONTGOMERY:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=C25519,-DAMCL_CURVETYPE=MONTGOMERY,-DAMCL_FFLEN=8 \
	LINUX_64BIT_C25519_RSA2048_EDWARDS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=C25519,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8 \
	LINUX_64BIT_BRAINPOOL:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BRAINPOOL,-DAMCL_CURVETYPE=WEIERSTRASS \
	LINUX_64BIT_ANSSI:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=ANSSI,-DAMCL_CURVETYPE=WEIERSTRASS \
	LINUX_64BIT_MF254_WEIERSTRASS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF254,-DAMCL_CURVETYPE=WEIERSTRASS \
	LINUX_64BIT_MF254_EDWARDS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF254,-DAMCL_CURVETYPE=EDWARDS \
	LINUX_64BIT_MF254_MONTGOMERY:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF254,-DAMCL_CURVETYPE=MONTGOMERY \
	LINUX_64BIT_MS255_WEIERSTRASS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS255,-DAMCL_CURVETYPE=WEIERSTRASS \
	LINUX_64BIT_MS255_EDWARDS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS255,-DAMCL_CURVETYPE=EDWARDS \
	LINUX_64BIT_MS255_MONTGOMERY:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS255,-DAMCL_CURVETYPE=MONTGOMERY \
	LINUX_64BIT_MF256_WEIERSTRASS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF256,-DAMCL_CURVETYPE=WEIERSTRASS \
	LINUX_64BIT_MF256_EDWARDS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF256,-DAMCL_CURVETYPE=EDWARDS \
	LINUX_64BIT_MF256_MONTGOMERY:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF256,-DAMCL_CURVETYPE=MONTGOMERY \
	LINUX_64BIT_MS256_WEIERSTRASS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS256,-DAMCL_CURVETYPE=WEIERSTRASS \
	LINUX_64BIT_MS256_EDWARDS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS256,-DAMCL_CURVETYPE=EDWARDS \
	LINUX_64BIT_MS256_MONTGOMERY:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS256,-DAMCL_CURVETYPE=MONTGOMERY \
	LINUX_64BIT_HIFIVE:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=HIFIVE,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8 \
	LINUX_64BIT_NIST384_RSA3072:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=NIST384,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=8 \
	LINUX_64BIT_C41417:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=C41417,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8 \
	LINUX_64BIT_NIST521:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=NIST521,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=4 \
	LINUX_64BIT_GOLDILOCKS:-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=GOLDILOCKS,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8

BUILDS_32=LINUX_32BIT_BN454:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BN454,-DAMCL_FFLEN=4,-DAMCL_CHUNK=32 \
	LINUX_32BIT_BN254_T:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BN254_T,-DAMCL_CHUNK=32 \
	LINUX_32BIT_BN254_T2:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BN254_T2,-DAMCL_CHUNK=32 \
	LINUX_32BIT_BN646:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BN646,-DAMCL_FFLEN=4,-DAMCL_CHUNK=32 \
	LINUX_32BIT_BLS383:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BLS383,-DAMCL_CHUNK=32 \
	LINUX_32BIT_BLS455:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BLS455,-DAMCL_CHUNK=32 \
	LINUX_32BIT_NIST256_RSA2048:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=NIST256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=8,-DAMCL_CHUNK=32 \
	LINUX_32BIT_NIST256_RSA4096:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=NIST256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=16,-DAMCL_CHUNK=32 \
	LINUX_32BIT_C25519_RSA2048_MONTGOMERY:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=C25519,-DAMCL_CURVETYPE=MONTGOMERY,-DAMCL_FFLEN=8,-DAMCL_CHUNK=32 \
	LINUX_32BIT_C25519_RSA2048_EDWARDS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=C25519,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8,-DAMCL_CHUNK=32 \
	LINUX_32BIT_BRAINPOOL:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=BRAINPOOL,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_ANSSI:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=ANSSI,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MF254_WEIERSTRASS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF254,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MF254_EDWARDS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF254,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MF254_MONTGOMERY:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF254,-DAMCL_CURVETYPE=MONTGOMERY,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MS255_WEIERSTRASS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS255,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MS255_EDWARDS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS255,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MS255_MONTGOMERY:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS255,-DAMCL_CURVETYPE=MONTGOMERY,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MF256_WEIERSTRASS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MF256_EDWARDS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF256,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MF256_MONTGOMERY:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MF256,-DAMCL_CURVETYPE=MONTGOMERY,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MS256_WEIERSTRASS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS256,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MS256_EDWARDS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS256,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_CHUNK=32 \
	LINUX_32BIT_MS256_MONTGOMERY:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=MS256,-DAMCL_CURVETYPE=MONTGOMERY,-DAMCL_CHUNK=32 \
	LINUX_32BIT_HIFIVE:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=HIFIVE,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8,-DAMCL_CHUNK=32 \
	LINUX_32BIT_NIST384_RSA3072:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=NIST384,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=8,-DAMCL_CHUNK=32 \
	LINUX_32BIT_C41417:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=C41417,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8,-DAMCL_CHUNK=32 \
	LINUX_32BIT_NIST521:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=NIST521,-DAMCL_CURVETYPE=WEIERSTRASS,-DAMCL_FFLEN=4,-DAMCL_CHUNK=32 \
	LINUX_32BIT_GOLDILOCKS:-DCMAKE_C_FLAGS=-m32,-DCMAKE_INSTALL_PREFIX=/opt/amcl,-DAMCL_CHOICE=GOLDILOCKS,-DAMCL_CURVETYPE=EDWARDS,-DAMCL_FFLEN=8,-DAMCL_CHUNK=32

# Merge all build types in a single list
BUILDS=${BUILDS_QA} ${BUILDS_64} ${BUILDS_32}


# Variables used in text substitution
comma := ,
space :=
space +=

# --- MAKE TARGETS ---

# Default build configured in config.mk
all: default

# Display general help about this command
help:
	@echo ""
	@echo "$(PROJECT) Makefile."
	@echo "The following commands are available:"
	@echo ""
	@echo "    make         :  Build library based on options in config.mk"
	@echo "    make format  :  Format the source code"
	@echo "    make clean   :  Remove any build artifact"
	@echo "    make qa      :  build all versions and generate reports"
	@echo "    make dbuild  :  build everything inside a Docker container"
	@echo ""
	@echo "    You can also build individual types or groups:"
	@echo ""
	@echo "    make build_group BUILD_GROUP=BUILDS_QA"
	@echo "    make build_group BUILD_GROUP=BUILDS_64"
	@echo "    make build_group BUILD_GROUP=BUILDS_32"
	@echo ""
	@$(foreach PARAMS,$(BUILDS_QA), \
		echo "    make build TYPE=$(word 1,$(subst :, ,${PARAMS}))" ; \
	)
	@echo ""
	@$(foreach PARAMS,$(BUILDS_64), \
		echo "    make build TYPE=$(word 1,$(subst :, ,${PARAMS}))" ; \
	)
	@echo ""
	@$(foreach PARAMS,$(BUILDS_32), \
		echo "    make build TYPE=$(word 1,$(subst :, ,${PARAMS}))" ; \
	)
	@echo ""

# Default build configured in config.mk
default: 
	@echo -e "\n\n*** BUILD default - see config.mk ***\n"
	rm -rf target/default/*
	mkdir -p target/default
	cd target/default && \
	cmake -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
	-DCMAKE_INSTALL_PREFIX=$(INSTALL_PATH) \
	-DBUILD_SHARED_LIBS=$(AMCL_BUILD_SHARED_LIBS) \
	-DBUILD_PYTHON=$(AMCL_BUILD_PYTHON) \
	-DBUILD_GO=$(AMCL_BUILD_GO) \
	-DGO_PATH=${GOPATH} \
	-DAMCL_CHUNK=$(AMCL_CHUNK) \
	-DAMCL_CHOICE=$(AMCL_CHOICE) \
	-DAMCL_CURVETYPE=$(AMCL_CURVETYPE) \
	-DAMCL_FFLEN=$(AMCL_FFLEN) \
	-DBUILD_MPIN=$(AMCL_BUILD_MPIN) \
	-DBUILD_WCC=$(AMCL_BUILD_WCC) \
	-DBUILD_DOXYGEN=$(AMCL_BUILD_DOXYGEN) \
	-DUSE_ANONYMOUS=$(AMCL_USE_ANONYMOUS) \
	-DAMCL_MAXPIN=$(AMCL_MAXPIN) \
	-DAMCL_PBLEN=$(AMCL_PBLEN) \
	../.. | tee cmake.log ; test $${PIPESTATUS[0]} -eq 0 && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log ; test $${PIPESTATUS[0]} -eq 0 && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log ; test $${PIPESTATUS[0]} -eq 0
ifeq ($(AMCL_BUILD_DOXYGEN),ON)
	cd target/default && \
	make doc | tee doc.log ; test $${PIPESTATUS[0]} -eq 0 
endif

# Format the source code
format:
	astyle --style=allman --recursive --suffix=none 'include/*.h'
	astyle --style=allman --recursive --suffix=none 'src/*.c'
	astyle --style=allman --recursive --suffix=none 'test/*.c'
	find ./wrappers/go -type f -name "*.go" -exec gofmt -s -w {} \;
	find ./wrappers/go -type f -name "*.go.in" -exec gofmt -s -w {} \;
	autopep8 --in-place --aggressive --aggressive ./wrappers/python/*.py

# Remove any build artifact
clean:
	mkdir -p target/
	rm -rf ./target/*

# Execute all builds and tests
qa:
	go get github.com/stretchr/testify/assert
	@mkdir -p target/
	@echo 0 > target/make.exit
	@echo '' > target/make_qa_errors.log
	make build_group BUILD_GROUP=BUILDS
	@cat target/make_qa_errors.log
	@exit `cat target/make.exit`

# Build the specified group of options
build_group:
	@parallel --no-notice --verbose make build_qa_item ITEM={} ::: ${${BUILD_GROUP}}

# Build the project using one of the pre-defined targets (example: "make build TYPE=COVERAGE")
build:
	make build_item ITEM=$(filter ${TYPE}:%,$(BUILDS))

# Same as build_item but stores the exit code and faling items
build_qa_item:
	make build_item ITEM=${ITEM} || (echo $$? > target/make.exit && echo ${ITEM} >> target/make_qa_errors.log);
 
# Build the specified item entry from the BUILDS list
build_item:
	make buildx BUILD_NAME=$(word 1,$(subst :, ,${ITEM})) BUILD_PARAMS=$(word 2,$(subst :, ,${ITEM}))

# Build with the specified parameters
buildx:
	@echo -e "\n\n*** BUILD ${BUILD_NAME} ***\n"
	rm -rf target/${BUILD_NAME}/*
	mkdir -p target/${BUILD_NAME}/coverage
ifneq ($(strip $(filter %COVERAGE,${BUILD_NAME})),)
	cd target/${BUILD_NAME} && \
	cmake $(subst $(comma),$(space),${BUILD_PARAMS}) ../.. | tee cmake.log ; test $${PIPESTATUS[0]} -eq 0 && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log ; test $${PIPESTATUS[0]} -eq 0 &&\
	lcov --zerocounters --directory . && \
	lcov --capture --initial --directory . --output-file coverage/amcl && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log ; test $${PIPESTATUS[0]} -eq 0 && \
	lcov --no-checksum --directory . --capture --output-file coverage/amcl.info && \
	lcov --remove coverage/amcl.info "/test_*" --output-file coverage/amcl.info && \
	genhtml -o coverage -t "milagro-crypto-c Test Coverage" coverage/amcl.info && \
	make doc | tee doc.log ; test $${PIPESTATUS[0]} -eq 0
else 
	cd target/${BUILD_NAME} && \
	cmake $(subst $(comma),$(space),${BUILD_PARAMS}) ../.. | tee cmake.log ; test $${PIPESTATUS[0]} -eq 0 && \
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
	make | tee make.log ; test $${PIPESTATUS[0]} -eq 0 && \
	make doc | tee doc.log ; test $${PIPESTATUS[0]} -eq 0 && \
	env CTEST_OUTPUT_ON_FAILURE=1 make test | tee test.log ; test $${PIPESTATUS[0]} -eq 0
endif

# Alias for building all inside the Docker container
buildall: default qa

# Build everything inside a Docker container
dbuild:
	@mkdir -p target
	@rm -rf target/*
	@echo 0 > target/make.exit
	CVSPATH=$(CVSPATH) VENDOR=$(VENDOR) PROJECT=$(PROJECT) MAKETARGET='$(MAKETARGET)' ./dockerbuild.sh
	@exit `cat target/make.exit`

# Publish Documentation in GitHub (requires writing permissions)
# Use this only after generating all build options with "make dbuild"
pubdocs:
	rm -rf ./target/DOCS
	rm -rf ./target/WIKI
	find ./target -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | xargs -i sh -c 'mkdir -p ./target/DOCS/{} && cp -rf ./target/{}/doc/html/* ./target/DOCS/{}/'
	#echo "# milagro-crypto-c Source Code Documentation" > ./target/DOCS/Home.md
	#find ./target/DOCS -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | xargs -i sh -c 'echo "* [{}](https://cdn.rawgit.com/wiki/miracl/milagro-crypto-c/{}/index.html)" >> ./target/DOCS/Home.md'
	cp ./doc/Home.md ./target/DOCS/
	git clone git@github.com:miracl/milagro-crypto-c.wiki.git ./target/WIKI
	mv -f ./target/WIKI/.git ./target/DOCS/
	cd ./target/DOCS/ && \
	git add . -A && \
	git commit -m 'Update documentation' && \
	git push origin master --force
	rm -rf ./target/DOCS
	rm -rf ./target/WIKI
