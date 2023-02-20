FROM moschn/microsurf-eval:base

RUN wget https://releases.llvm.org/7.1.0/clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz \
        && tar -xf clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz \
        && cd clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04 \
        && cp -R * /usr/local/ \
        && cd .. \
        && rm -rf clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04*

WORKDIR /build
ADD ./ /build
