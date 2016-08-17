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
RUN make qa
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
