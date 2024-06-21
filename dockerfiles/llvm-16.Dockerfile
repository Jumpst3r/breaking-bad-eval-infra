FROM moschn/microsurf-eval:base-24.04

RUN apt update && apt install --no-install-recommends -y \
        clang-16 \
        llvm-16 \
        lld-16

RUN ln -s /usr/bin/clang-16 /usr/bin/clang \
        && ln -s /usr/bin/clang++-16 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-16 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-16 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-16 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-16 /usr/bin/lld

WORKDIR /build
ADD ./ /build