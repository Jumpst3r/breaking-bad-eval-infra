FROM jumpst3r/microsurf:eval
RUN apt update && apt install --no-install-recommends -y build-essential libtool git wget python3 python-is-python3 zip
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.0/clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && tar -xf clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && cd clang+llvm-14.0.0-x86_64-linux-gnu-ubuntu-18.04 && cp -R * /usr/local/
RUN pip3 install Jinja2
# RUN wget https://registrationcenter-download.intel.com/akdlm/irc_nas/18673/l_BaseKit_p_2022.2.0.262.sh && sh ./l_BaseKit_p_2022.2.0262.sh -a -s --eula accept 
WORKDIR /build
ADD . /build
CMD ["python3", "./builder.py"]