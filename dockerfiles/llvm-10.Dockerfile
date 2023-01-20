FROM moschn/microsurf-eval:base

RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/clang+llvm-10.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
        && tar xf clang+llvm-10.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
        && cd clang+llvm-10.0.1-x86_64-linux-gnu-ubuntu-16.04 \
        && cp -R * /usr/local/

WORKDIR /build
ADD ./ /build
