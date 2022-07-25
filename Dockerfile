FROM jumpst3r/microsurf:latest
#FROM docker.io/library/microsurf2
RUN apt update && apt install --no-install-recommends -y build-essential libtool zlib1g zlib1g-dev libxml2 git wget python3 python-is-python3 zip autoconf automake
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.0/clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && tar -xf clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && cd clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04 && cp -R * /usr/local/
#RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz && tar -xf clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz && cd clang+llvm-7.1.0-x86_64-linux-gnu-ubuntu-14.04 && cp -R * /usr/local/
RUN pip3 install Jinja2
RUN wget https://registrationcenter-download.intel.com/akdlm/irc_nas/18673/l_BaseKit_p_2022.2.0.262.sh && sh ./l_BaseKit_p_2022.2.0.262.sh -a --components intel.oneapi.lin.dpcpp-cpp-compiler -s --eula accept 
WORKDIR /build
ADD . /build
CMD ["python3", "./builder.py"]