FROM moschn/microsurf-eval:base

# We need to download llvm release 9.0.0 instead of 9.0.1 because the latter 
# was compiled without zlib support. Using 9.0.1 breaks compiles for x86-i686
RUN wget https://releases.llvm.org/9.0.0/clang%2bllvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
        && tar xf clang+llvm-9.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
        && cd clang+llvm-9.0.1-x86_64-linux-gnu-ubuntu-16.04 \
        && cp -R * /usr/local/ \
        && cd .. \
        && rm -rf clang+llvm-9.0.1-x86_64-linux-gnu-ubuntu-16.04*

WORKDIR /build
ADD ./ /build
