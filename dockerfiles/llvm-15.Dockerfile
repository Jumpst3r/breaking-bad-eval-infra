FROM moschn/microsurf-eval:base

# use the llvm.sh script to install 
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 15 \
        && ln -s /usr/bin/clang-15 /usr/bin/clang \
        && ln -s /usr/bin/clang++-15 /usr/bin/clang++ \
        && ln -s /usr/bin/llvm-ar-15 /usr/bin/llvm-ar \
        && ln -s /usr/bin/llvm-as-15 /usr/bin/llvm-as \
        && ln -s /usr/bin/llvm-ranlib-15 /usr/bin/llvm-ranlib \
        && ln -s /usr/bin/lld-15 /usr/bin/lld

WORKDIR /build
ADD ./ /build