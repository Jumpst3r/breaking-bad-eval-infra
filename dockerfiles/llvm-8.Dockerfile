FROM moschn/microsurf-eval:base

# Had to use an uimage hosted by github since it is not available on the LLVM mirror
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-8.0.1/clang+llvm-8.0.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz \
        && tar xf clang+llvm-8.0.1-x86_64-linux-gnu-ubuntu-14.04.tar.xz \
        && cd clang+llvm-8.0.1-x86_64-linux-gnu-ubuntu-14.04 \
        && cp -R * /usr/local/ \
        && cd .. \
        && rm -rf clang+llvm-8.0.1-x86_64-linux-gnu-ubuntu-14.04*

WORKDIR /build
ADD ./ /build
