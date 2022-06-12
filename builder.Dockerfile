FROM microsurf
RUN command apt update && apt install -y build-essential git wget python3 zip
WORKDIR /build
ADD . /build
CMD ["python3", "./builder.py"]