FROM moschn/microsurf-eval:base

RUN apt update && apt install --no-install-recommends -y \
        clang-15 \
        llvm-15 \
        lld-15

RUN ln -s /usr/bin/clang-15 /usr/bin/clang \
        && ln -s /usr/bin/clang++-15 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-15 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-15 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-15 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-15 /usr/bin/lld

WORKDIR /build
ADD ./ /build