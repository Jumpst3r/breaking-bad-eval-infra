FROM moschn/microsurf-eval:base

RUN wget https://releases.llvm.org/6.0.1/clang+llvm-6.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
        && tar -xf clang+llvm-6.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
        && cd clang+llvm-6.0.1-x86_64-linux-gnu-ubuntu-16.04 \
        && cp -R * /usr/local/ \
        && cd .. \
        && rm -rf clang+llvm-6.0.1-x86_64-linux-gnu-ubuntu-16.04*

WORKDIR /build
ADD ./ /build
