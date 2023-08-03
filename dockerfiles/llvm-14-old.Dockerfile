FROM moschn/microsurf-eval:base

# use the llvm.sh script to install 
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 14 \
        && ln -s /usr/bin/clang-14 /usr/bin/clang \
        && ln -s /usr/bin/clang++-14 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-14 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-14 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-14 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-14 /usr/bin/lld

WORKDIR /build
ADD ./ /build