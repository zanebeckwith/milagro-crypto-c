#!/bin/sh
#
# dockerbuild.sh
#
# Build the software
#
# @author Nicola Asuni <nicola.asuni@miracl.com>
# ------------------------------------------------------------------------------

# NOTES:
#
# This script requires docker

# EXAMPLE USAGE:
# ./dockerbuild.sh

# build the environment
docker build --tag=miracl/cdev ./resources/DockerDev/

# go path
GOPATH=/root

# project root path
PRJPATH=/root/src/milagro-crypto-c

# generate a docker file on the fly
cat > Dockerfile <<- EOM
FROM miracl/cdev
MAINTAINER nicola.asuni@miracl.com
RUN mkdir -p /root/.ssh && \
    echo "Host github.com\n\tStrictHostKeyChecking no\n" >> /root/.ssh/config && \
    mkdir -p ${PRJPATH}
ADD ./ ${PRJPATH}
WORKDIR ${PRJPATH}

RUN echo -e "\n\n*** BUILD FOR COVERAGE ***\n" && \
    rm -rf ${PRJPATH}/target/build_test && \
    mkdir -p ${PRJPATH}/target/build_test/coverage && \
    cd ${PRJPATH}/target/build_test && \
    cmake -D CMAKE_BUILD_TYPE=Coverage -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 -D BUILD_WCC=on ../.. && \
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
    make && \
    lcov --zerocounters --directory . && \
    lcov --capture --initial --directory . --output-file coverage/amcl && \
    env CTEST_OUTPUT_ON_FAILURE=1 make test && \
    lcov --no-checksum --directory . --capture --output-file coverage/amcl.info && \
    genhtml -o coverage -t "milagro-crypto-c Test Coverage" coverage/amcl.info && \
    make doc

RUN echo -e "\n\n*** BUILD LINUX 64 WRAPPERS ***\n\n" && \
    rm -rf ${PRJPATH}/target/build_linux64_wrappers && \
    mkdir -p ${PRJPATH}/target/build_linux64_wrappers && \
    cd ${PRJPATH}/target/build_linux64_wrappers && \
    cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 -D BUILD_PYTHON=on -D BUILD_GO=on -D GO_PATH=${GOPATH} -D BUILD_WCC=on ../.. && \
    make && \
    go get ./... && \
    go get github.com/stretchr/testify/assert && \
    env CTEST_OUTPUT_ON_FAILURE=1 LD_LIBRARY_PATH=${PRJPATH}/target/build_linux64_wrappers/wrappers/go make test && \
    make package

RUN echo -e "\n\n*** BUILD LINUX 64 WRAPPERS ***\n\n" && \
    rm -rf ${PRJPATH}/target/build_linux64_wrappers && \
    mkdir -p ${PRJPATH}/target/build_linux64_wrappers && \
    cd ${PRJPATH}/target/build_linux64_wrappers && \
    cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 -D BUILD_PYTHON=on -D BUILD_GO=on -D GO_PATH=${GOPATH} -D BUILD_WCC=on ../.. && \
    make && \
    env CTEST_OUTPUT_ON_FAILURE=1 make test && \
    make package

RUN echo -e "\n\n*** BUILD LINUX 64 ANONYMOUS ***\n\n" && \
    rm -rf ${PRJPATH}/target/build_linux64_anon && \
    mkdir -p ${PRJPATH}/target/build_linux64_anon && \
    cd ${PRJPATH}/target/build_linux64_anon && \
    cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 -D USE_ANONYMOUS=on -D BUILD_WCC=on ../.. && \
    make && \
    env CTEST_OUTPUT_ON_FAILURE=1 make test && \
    make package

RUN echo -e "\n\n*** BUILD LINUX 64 ***\n\n" && \
    rm -rf ${PRJPATH}/target/build_linux64 && \
    mkdir -p ${PRJPATH}/target/build_linux64 && \
    cd ${PRJPATH}/target/build_linux64 && \
    cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 ../.. && \
    make && \
    env CTEST_OUTPUT_ON_FAILURE=1 make test && \
    make package

RUN echo -e "\n\n*** BUILD LINUX 32 ***\n\n" && \
    rm -rf ${PRJPATH}/target/build_linux32 && \
    mkdir -p ${PRJPATH}/target/build_linux32 && \
    cd ${PRJPATH}/target/build_linux32 && \
    cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=32 ../.. && \
    make && \
    env CTEST_OUTPUT_ON_FAILURE=1 make test && \
    make package

RUN echo -e "\n\n*** BUILD WIN 64 ***\n\n" && \
    rm -rf ${PRJPATH}/target/build_win64 && \
    mkdir -p ${PRJPATH}/target/build_win64 && \
    cd ${PRJPATH}/target/build_win64 && \
    cmake -D CMAKE_TOOLCHAIN_FILE=../../resources/cmake/mingw64-cross.cmake -D WORD_LENGTH=64 ../.. && \
    make && \
    env CTEST_OUTPUT_ON_FAILURE=1 make test

RUN echo -e "\n\n*** BUILD WIN 32 ***\n\n" && \
    rm -rf ${PRJPATH}/target/build_win32 && \
    mkdir -p ${PRJPATH}/target/build_win32 && \
    cd ${PRJPATH}/target/build_win32 && \
    cmake -D CMAKE_TOOLCHAIN_FILE=../../resources/cmake/mingw32-cross.cmake -D WORD_LENGTH=32 ../.. && \
    make && \
    env CTEST_OUTPUT_ON_FAILURE=1 make test
EOM

# docker image name
DOCKER_IMAGE_NAME="local/build"

# build the docker container and build the project
docker build --no-cache --tag=${DOCKER_IMAGE_NAME} .

# start a container using the newly created docker image
CONTAINER_ID=$(docker run -d ${DOCKER_IMAGE_NAME})

# copy the artifact back to the host
docker cp ${CONTAINER_ID}:"${PRJPATH}/target" ./

# remove the container and image
docker rm -f ${CONTAINER_ID} || true
docker rmi -f ${DOCKER_IMAGE_NAME} || true
