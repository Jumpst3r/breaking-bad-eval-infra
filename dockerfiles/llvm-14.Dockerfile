FROM moschn/microsurf-eval:base

RUN apt update && apt install --no-install-recommends -y \
        clang-14 \
        llvm-14 \
        lld-14

RUN ln -s /usr/bin/clang-14 /usr/bin/clang \
        && ln -s /usr/bin/clang++-14 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-14 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-14 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-14 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-14 /usr/bin/lld

WORKDIR /build
ADD ./ /build