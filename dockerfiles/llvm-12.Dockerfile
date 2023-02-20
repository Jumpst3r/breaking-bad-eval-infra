FROM moschn/microsurf-eval:base

# We need to download llvm release 12.0.0 instead of 12.0.1 because the latter 
# was compiled without zlib support. Using 12.0.1 breaks compiles for x86-i686
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.0/clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz \
        && tar xf clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz \
        && cd clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-20.04 \
        && cp -R * /usr/local/ \
        && cd .. \
        && rm -rf clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-20.04*

WORKDIR /build
ADD ./ /build
