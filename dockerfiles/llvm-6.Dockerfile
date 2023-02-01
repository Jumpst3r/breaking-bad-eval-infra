FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install --no-install-recommends -y \
    build-essential \
    libtool \
    zlib1g \
    zlib1g-dev \
    libxml2 \
    git \
    wget \
    python3.9 \
    python3.9-distutils \
    zip \
    autoconf \
    automake \
    lsb-release \
    software-properties-common \
    gnupg \
    clang-6.0 \
    lld-6.0 \
    libncurses5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/bin/clang-6.0 /usr/bin/clang \
        && ln -s /usr/bin/clang++-6.0 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-6.0 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-6.0 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-6.0 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-6.0 /usr/bin/lld \
        && ln -s /usr/bin/ld.lld-6.0 /usr/bin/ld.lld

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
        python3.9 get-pip.py

RUN ln -s /usr/bin/python3.9 /usr/local/sbin/python3 \
        && ln -s /usr/bin/python3.9 /usr/local/sbin/python

RUN pip install Jinja2 jsonschema setuptools


# WORKDIR /install
ADD ./microsurf /install
RUN pip install /install/

WORKDIR /build
ADD ./ /build
