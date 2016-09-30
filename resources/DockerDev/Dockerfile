# Dockerfile
#
# Development environment for milagro-crypto-c
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
#     docker build --tag="miracl/amcldev" .
#
# To log into the newly created container:
#     docker run -t -i miracl/amcldev /bin/bash
#
# To get the container ID:
#     CONTAINER_ID=`docker ps -a | grep miracl/amcldev | cut -c1-12`
#
# To delete the newly created docker container:
#     docker rm -f $CONTAINER_ID
#
# To delete the docker image:
#     docker rmi -f miracl/amcldev
#
# To delete all containers
#     docker rm $(docker ps -a -q)
#
# To delete all images
#     docker rmi $(docker images -q)
# ------------------------------------------------------------------------------

FROM phusion/baseimage
MAINTAINER nicola.asuni@miracl.com

ENV DEBIAN_FRONTEND noninteractive
ENV TERM linux
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
ENV HOME /root
ENV DISPLAY :0
ENV GOPATH=/root
ENV PATH=/usr/local/go/bin:$GOPATH/bin:$PATH

# add i386 architecture
RUN dpkg --add-architecture i386

# add repositories and update
RUN apt-get update && apt-get -y dist-upgrade && \
apt-get install -y apt-utils software-properties-common python-software-properties && \
apt-add-repository universe && \
apt-add-repository multiverse && \
apt-get update

# install development packages and debugging tools
RUN apt-get install -y \
alien \
astyle \
autoconf \
autotools-dev \
binfmt-support \
binutils-mingw-w64 \
build-essential \
cmake \
curl \
debhelper \
devscripts \
dh-golang \
dh-make \
dos2unix \
doxygen \
doxygen-latex \
flawfinder \
g++ \
gcc \
gdb \
git \
g++-multilib \
golang \
golang-golang-x-tools \
lcov \
libc6 \
libc6-dev \
libc6-dev-i386 \
libffi-dev \
libwine-development \
lsof \
make \
mingw-w64 \
mingw-w64-i686-dev \
mingw-w64-tools \
mingw-w64-x86-64-dev \
nano \
openssh-client \
openssh-server \
openssl \
parallel \
pbuilder \
pkg-config \
pyflakes \
pylint \
python \
python-dev \
python-pip \
rpm \
rsync \
screen \
strace \
ubuntu-restricted-addons \
ubuntu-restricted-extras \
valgrind \
vim \
wget \
wine \
wine64-development-tools \
winetricks

# Configure SSH
RUN mkdir -p /root/.ssh && echo "Host github.com\n\tStrictHostKeyChecking no\n" >> /root/.ssh/config

# Install extra python dependencies
RUN pip install --upgrade pip && \
pip install cffi && \
pip install --upgrade autopep8

# Install and configure GO
RUN wget https://storage.googleapis.com/golang/go1.7.1.linux-amd64.tar.gz && \
tar xvf go1.7.1.linux-amd64.tar.gz && \
mv go /usr/local && \
mkdir -p /root/bin && \
mkdir -p /root/pkg && \
mkdir -p /root/src && \
echo 'export GOPATH=/root' >> /root/.profile && \
echo 'export PATH=/usr/local/go/bin:$GOPATH/bin:$PATH' >> /root/.profile && \
go version
