FROM moschn/microsurf-eval:base-24.04

RUN apt update && apt install --no-install-recommends -y \
        clang-18 \
        llvm-18 \
        lld-18

RUN ln -s /usr/bin/clang-18 /usr/bin/clang \
        && ln -s /usr/bin/clang++-18 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-18 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-18 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-18 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-18 /usr/bin/lld

WORKDIR /build
ADD ./ /build