FROM ubuntu:18.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install --no-install-recommends -y \
    software-properties-common \
    build-essential \
    libtool \
    zlib1g \
    zlib1g-dev \
    libxml2 \
    git \
    wget \
    zip \
    autoconf \
    automake \
    lsb-release \
    software-properties-common \
    gnupg \
    clang-5.0 \
    llvm-5.0 \
    lld-5.0 \
    libncurses5 \
    libssl-dev \
    curl \
    cmake \
    ssh \
    && rm -rf /var/lib/apt/lists/*

# install python 3.9 from source
RUN wget https://www.python.org/ftp/python/3.9.16/Python-3.9.16.tgz && \
        tar -xf Python-3.9.16.tgz && \
        cd Python-3.9.16 && \
        ./configure --enable-optimizations && \
        make -j6 && \
        make altinstall

RUN ln -s /usr/bin/clang-5.0 /usr/bin/clang \
        && ln -s /usr/bin/clang++-5.0 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-5.0 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-5.0 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-5.0 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-5.0 /usr/bin/lld \
        && ln -s /usr/bin/ld.lld-5.0 /usr/bin/ld.lld

# RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
#         python3.9 get-pip.py

RUN python3.9 -m ensurepip --upgrade

RUN ln -s /usr/bin/python3.9 /usr/local/sbin/python3 \
        && ln -s /usr/bin/python3.9 /usr/local/sbin/python

RUN python3.9 -m pip install Jinja2 jsonschema setuptools

# Install go (necessary for boringssl)
RUN wget -q -O - https://go.dev/dl/go1.20.2.linux-amd64.tar.gz | tar -v -C /usr/local -xz
ENV PATH $PATH:/usr/local/go/bin

# WORKDIR /install
ADD ./microsurf /install
RUN python3.9 -m pip install /install/


WORKDIR /build
ADD ./ /build
