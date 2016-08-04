# Dockerfile
#
# Ubuntu 16.04 (Xenial) with development packages for c
#
# @author      Nicola Asuni <nicola.asuni@miracl.com>
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# NOTES:
#
# This script requires Docker (https://www.docker.com/)
#
#     sudo apt-get install docker docker.io
#
# Add your user to the "docker" group:
#     sudo groupadd docker
#     sudo gpasswd -a <YOURUSER> docker
#     sudo service docker restart
#
# To create the container execute:
#     docker build --tag="miracl/cdev:milagro-crypto-c" .
#
# To log into the newly created container:
#     docker run -t -i miracl/cdev /bin/bash
#
# To get the container ID:
#     CONTAINER_ID=`docker ps -a | grep miracl/cdev | cut -c1-12`
#
# To delete the newly created docker container:
#     docker rm -f $CONTAINER_ID
#
# To delete the docker image:
#     docker rmi -f miracl/cdev
#
# To delete all containers
#     docker rm $(docker ps -a -q)
#
# To delete all images
#     docker rmi $(docker images -q)
# ------------------------------------------------------------------------------

FROM ubuntu:xenial
MAINTAINER nicola.asuni@miracl.com

ENV DEBIAN_FRONTEND noninteractive
ENV TERM linux
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
ENV HOME /root
ENV DISPLAY :0
ENV GOPATH=/root/GO
ENV PATH=$GOPATH/bin:$PATH

# add i386 architecture
RUN dpkg --add-architecture i386

# add repositories and update
RUN apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y apt-utils software-properties-common python-software-properties && \
    apt-add-repository universe && \
    apt-add-repository multiverse && \
    apt-get update

# install development packages and debugging tools
RUN apt-get install -y wget nano vim curl rsync git screen build-essential python python-dev python-pip libffi-dev autotools-dev autoconf make cmake gcc g++ golang golang-golang-x-tools alien rpm dh-make dh-golang debhelper devscripts pbuilder strace lsof gdb valgrind pkg-config doxygen doxygen-latex lcov libc6 libc6-dev astyle pylint pyflakes

# add mingw for cross compiling the Windows version in Linux
RUN apt-get install -y dos2unix mingw-w64 binutils-mingw-w64 mingw-w64-tools mingw-w64-i686-dev mingw-w64-x86-64-dev wine winetricks libwine-development ubuntu-restricted-extras ubuntu-restricted-addons wine64-development-tools binfmt-support

RUN pip install --upgrade pip && pip install cffi

# configure GO
RUN mkdir -p /root/GO/bin && \
    mkdir -p /root/GO/pkg && \
    mkdir -p /root/GO/src && \
    echo 'export GOPATH=/root/GO' >> /root/.profile && \
    echo 'export PATH=$GOPATH/bin:$PATH' >> /root/.profile
