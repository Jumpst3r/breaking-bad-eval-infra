FROM moschn/microsurf-eval:base

RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.1/clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
        && tar -xf clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
        && cd clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04 \
        && cp -R * /usr/local/

WORKDIR /build
ADD ./ /build