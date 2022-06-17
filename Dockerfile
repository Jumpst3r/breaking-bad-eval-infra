FROM jumpst3r/microsurf:latest
RUN apt update && apt install -y build-essential libtool git wget python3 python-is-python3 zip
RUN pip3 install Jinja2
WORKDIR /build
ADD . /build
CMD ["python3", "./builder.py"]