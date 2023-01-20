FROM moschn/microsurf-eval:base

RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-20.10.tar.xz \
        && tar xf clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-20.10.tar.xz \
        && cd clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-20.10 \
        && cp -R * /usr/local/

WORKDIR /build
ADD ./ /build
