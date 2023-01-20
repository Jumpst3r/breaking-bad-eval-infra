FROM moschn/microsurf-eval:base

RUN wget https://releases.llvm.org/5.0.2/clang+llvm-5.0.2-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
        && tar -xf clang+llvm-5.0.2-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
        && cd clang+llvm-5.0.2-x86_64-linux-gnu-ubuntu-16.04 \
        && cp -R * /usr/local/

WORKDIR /build
ADD ./ /build
