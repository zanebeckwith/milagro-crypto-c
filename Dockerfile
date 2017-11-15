FROM ubuntu:latest AS downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates

ENV GOVERSION 1.9.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    && wget -nv https://storage.googleapis.com/golang/go$GOVERSION.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go$GOVERSION.linux-amd64.tar.gz


FROM ubuntu:latest

# Install and configure GO
ENV GOPATH /go
ENV PATH $PATH:/usr/local/go/bin:$GOPATH/bin
COPY --from=downloader /usr/local/go /usr/local/

RUN dpkg --add-architecture i386 \
    && apt-get update && apt-get install -y --no-install-recommends \
    astyle \
    ca-certificates \
    cmake \
    doxygen \
    doxygen-latex \
    g++ \
    g++-multilib \
    gcc \
    git \
    lcov \
    make \
    mingw-w64 \
    parallel \
    python-pip \
    python-setuptools\
    wine \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && pip install --upgrade pip \
    && pip install \
    autopep8 \
    cffi \
    wheel

CMD ["/bin/bash"]
