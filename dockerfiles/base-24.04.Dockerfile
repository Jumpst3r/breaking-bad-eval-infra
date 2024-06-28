FROM ubuntu:24.04
# RUN apt update && apt install -y --no-install-recommends software-properties-common
# RUN add-apt-repository ppa:deadsnakes/ppa -y
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
    gnupg \
    cmake \
    ssh \
    libncurses6 \
    python3-jinja2 \
    earlyoom \
    python3-jsonschema
# RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 15
# RUN ln -s /usr/bin/clang-15 /usr/bin/clang
# RUN ln -s /usr/bin/clang++-15 /usr/bin/clang++
# RUN ln -s /usr/bin/llvm-ar-15 /usr/bin/llvm-ar
# RUN ln -s /usr/bin/llvm-ranlib-15 /usr/bin/llvm-ranlib
#RUN wget https://registrationcenter-download.intel.com/akdlm/irc_nas/18673/l_BaseKit_p_2022.2.0.262.sh && sh ./l_BaseKit_p_2022.2.0.262.sh -a --components intel.oneapi.lin.dpcpp-cpp-compiler -s --eula accept 

# Install go (necessary for boringssl)
RUN wget -q -O - https://go.dev/dl/go1.20.2.linux-amd64.tar.gz | tar -v -C /usr/local -xz
ENV PATH $PATH:/usr/local/go/bin

# WORKDIR /install
ADD ./microsurf /install
RUN pip install /install/ --break-system-packages



# WORKDIR /build
# ADD ./ /build

# RUN pip install -e ./microsurf/


# CMD ["python", "./run.py", "-a", "riscv64", "-t", "llvm", "--toolchain-version", "15", "-f", "botan", "-c", "master", '-o="-O2 -flto"', "hmac-sha2"]