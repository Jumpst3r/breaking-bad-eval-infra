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
RUN pip3 install Jinja2 jsonschema
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 15
RUN ln -s /usr/bin/clang-15 /usr/bin/clang
RUN ln -s /usr/bin/clang++-15 /usr/bin/clang++
RUN ln -s /usr/bin/llvm-ar-15 /usr/bin/llvm-ar
RUN ln -s /usr/bin/llvm-ranlib-15 /usr/bin/llvm-ranlib
#RUN wget https://registrationcenter-download.intel.com/akdlm/irc_nas/18673/l_BaseKit_p_2022.2.0.262.sh && sh ./l_BaseKit_p_2022.2.0.262.sh -a --components intel.oneapi.lin.dpcpp-cpp-compiler -s --eula accept 
# WORKDIR /build
# ADD ../../ /build
# CMD ["python3", "./setup.py", "x86-i686"]

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    #
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# ********************************************************
# * Anything else you want to do like clean up goes here *
# ********************************************************

# [Optional] Set the default user. Omit if you want to keep the default as root.
USER $USERNAME