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
docker build -t miracl/cdev ./resources/DockerDev/

# generate a docker file on the fly
cat > Dockerfile <<- EOM
FROM miracl/cdev
MAINTAINER nicola.asuni@miracl.com
RUN mkdir -p /root/.ssh
RUN echo "Host github.com\n\tStrictHostKeyChecking no\n" >> /root/.ssh/config
RUN mkdir -p /root/C/milagro-crypto-c
ADD ./ /root/C/milagro-crypto-c
RUN rm -rf /root/C/milagro-crypto-c/target/build
WORKDIR /root/C/milagro-crypto-c
RUN mkdir -p /root/C/milagro-crypto-c/target/build && \
    cd target/build && \
    cmake -D BUILD_COVERAGE=on -D CMAKE_INSTALL_PREFIX=/opt/amcl -D WORD_LENGTH=64 -D BUILD_WCC=on ../.. && \
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./ && \
    make && \
    lcov --zerocounters --directory . && \
    lcov --capture --initial --directory . --output-file amcl && \
    make test && \
    lcov --no-checksum --directory . --capture --output-file amcl.info && \
    genhtml amcl.info && \
    make doc && \
    cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D USE_ANONYMOUS=on -D WORD_LENGTH=64 -D BUILD_WCC=on ../.. && \
    make && \
    make test && \
    make package
EOM

# docker image name
DOCKER_IMAGE_NAME="local/build"

# build the docker container and build the project
docker build --no-cache -t ${DOCKER_IMAGE_NAME} .

# start a container using the newly created docker image
CONTAINER_ID=$(docker run -d ${DOCKER_IMAGE_NAME})

# copy the artifact back to the host
docker cp ${CONTAINER_ID}:"/root/C/milagro-crypto-c/target" ./

# remove the container and image
docker rm -f ${CONTAINER_ID} || true
docker rmi -f ${DOCKER_IMAGE_NAME} || true
