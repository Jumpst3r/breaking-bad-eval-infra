FROM moschn/microsurf-eval:base-24.04

RUN apt update && apt install --no-install-recommends -y \
        clang-17 \
        llvm-17 \
        lld-17

RUN ln -s /usr/bin/clang-17 /usr/bin/clang \
        && ln -s /usr/bin/clang++-17 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-17 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-17 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-17 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-17 /usr/bin/lld

WORKDIR /build
ADD ./ /build