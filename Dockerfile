FROM jumpst3r/microsurf:latest
RUN apt update && apt install -y build-essential libtool git wget python3 python-is-python3 zip
RUN pip3 install Jinja2
# RUN wget https://registrationcenter-download.intel.com/akdlm/irc_nas/18673/l_BaseKit_p_2022.2.0.262.sh && sh ./l_BaseKit_p_2022.2.0262.sh -a -s --eula accept 
WORKDIR /build
ADD . /build
CMD ["python3", "./builder.py"]