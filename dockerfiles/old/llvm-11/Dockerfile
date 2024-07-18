FROM ubuntu:22.04
RUN apt update && apt install --no-install-recommends -y \
    build-essential \
    libtool \
    zlib1g \
    zlib1g-dev \
    libxml2 \
    git \
    wget \
    python3 \
    python-is-python3 \
    python3-pip \
    zip \
    autoconf \
    automake \
    lsb-release \
    software-properties-common \
    gnupg
RUN pip3 install Jinja2
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-20.10.tar.xz && tar xf clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-20.10.tar.xz && cd clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-20.10 && cp -R * /usr/local/
#RUN wget https://registrationcenter-download.intel.com/akdlm/irc_nas/18673/l_BaseKit_p_2022.2.0.262.sh && sh ./l_BaseKit_p_2022.2.0.262.sh -a --components intel.oneapi.lin.dpcpp-cpp-compiler -s --eula accept 
# WORKDIR /build
# ADD ../../ /build
# CMD ["python3", "./setup.py", "x86-i686"]