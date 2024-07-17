# Breaking Bad: How Compilers Break Constant-Time Implementations

This repository contains the environment and the scripts used in the paper "Breaking Bad: How Compilers Break Constant-Time Implementations". For the large sclae evaluateion, we used a kubernetes cluster setup running [argo workflows](https://argoproj.github.io/argo-workflows/). For further details, check the large scale analysis section below.

## Quickstart

```bash
git submodule update --init --recursive

# install microsurf in a virtualenv
python -m virtualenv venv
source venv/bin/activate
pip install -e microsurf

# run the analysis
mkdir test
cd test
../run.py -a riscv64 -t gcc --toolchain-version 11.3.0 -f haclstar -c f283af14715cc66ec7481a3ae0ed019cbff4c790 -o="-O2" --fw-dir ../src/frameworks -p ../config.json hmac-sha2
```

## Synopsis

```
usage: run.py [-h] [-a {riscv64,x86-64,x86-i686,aarch64,armv7,mips32el}] [-t {gcc,llvm}] --toolchain-version TOOLCHAIN_VERSION -f
              {haclstar,openssl,mbedtls,wolfssl,botan,bearssl,libsodium,boringssl} -c COMMIT [-o OPT] [-p PATH] [--result-dir RESULT_DIR] [--fw-dir FW_DIR]
              [--save-binaries | --no-save-binaries] [--asm | --no-asm]
              target [target ...]

positional arguments:
  target                Target algorithm(s) to be analyzed

options:
  -h, --help            show this help message and exit
  -a {riscv64,x86-64,x86-i686,aarch64,armv7,mips32el}, --arch {riscv64,x86-64,x86-i686,aarch64,armv7,mips32el}
                        Architecture
  -t {gcc,llvm}, --toolchain {gcc,llvm}
                        Toolchain
  --toolchain-version TOOLCHAIN_VERSION
                        Toolchain Version
  -f {haclstar,openssl,mbedtls,wolfssl,botan,bearssl,libsodium,boringssl}, --framework {haclstar,openssl,mbedtls,wolfssl,botan,bearssl,libsodium,boringssl}
                        Framework
  -c COMMIT, --commit COMMIT
                        Commit of the framework
  -o OPT, --opt OPT, --optimization OPT
                        Optimization (default: -O2)
  -p PATH, --path PATH  path to config
  --result-dir RESULT_DIR
                        Result directory
  --fw-dir FW_DIR       Directory to frameworks directory
  --save-binaries, --no-save-binaries
  --asm, --no-asm       Extract assembly during analysis. Will incur a memory and performance overhead if enabled.

example usage:

    python run.py -a riscv64 -t gcc --toolchain-version 11.3.0 -f haclstar -c main -o="-O3" hmac-sha2
    python run.py -a x86-64 -t llvm --toolchain-version 15 -f haclstar -c main -o="-O0" hmac-sha2

Running in a different directory:
    python ../run.py -a riscv64 -t gcc --toolchain-version 11.3.0 -f libsodium -c stable -o="-O2" --fw-dir ../src/frameworks -p ../config.json hmac-sha2
```

## Docker Images

Docker images exist for extra convenience. We provide docker images for LLVM versions 5-15. GCC toolchains are downloaded at runtime. Follow the steps below to build a single image.

```bash
git submodule update --init
docker build -t microsurf-eval:base -f dockerfiles/base.Dockerfile .

# edit dockerfiles/llvmXX.Dockerfile with the tag chosen above
# First line of dockerfiles/llvmXX.Dockerfile should be: 
# FROM microsurf-eval:base

docker build -t 'microsurf-eval:llvmXX' -f dockerfiles/llvm-XX.Dockerfile .
```

We also provide a script to build all docker images and upload them to a dockerhub account in [docker_build.sh](docker_build.sh).

## Running in Docker

Executing an individual analysis on a target library and cryptographic algorithm is simple within a docker image. Run the following steps to run an individual analysis

```bash
docker run --rm -it microsurf-eval:llvmXX bash
python run.py --help
python run.py -a x86-64 -t llvm --toolchain-version XX -f haclstar -c main -o="-O0" hmac-sha2
```

## Large Scale Analysis

The large scale setup is a bit more involved. It requires the following prerequisites:

- A working kubernetes cluster
- Installation of argo workflow on your cluster
- All Docker images uploaded to to dockerhub (see [docker_build.sh](docker_build.sh)) 
- A shared network drive that is accessible to all argo containers, e.g., an ntfs drive that is mounted to `/data/`.

The configuration of the run is specified in [workflow/workflow.yaml](workflow/workflow.yaml). An example configuration:

```yaml
  arguments:
    parameters:
    - name: architectures
      value: |
        ["riscv64", "x86-64", "x86-i686", "aarch64", "mips32el", "armv7"]
    - name: compilers
      value: |
        {
          "gcc": [
            "5.4.0", "6.4.0", "7.3.0", "8.4.0", "9.3.0", "10.3.0", "11.3.0"
          ],
          "llvm": [
            "15", "14", "13", "12", "11", "10", "9", "8", "7", "6", "5"
          ]
        }
    - name: frameworks
      value: |
        ["haclstar"]
    - name: target-algorithms
      value: |
        "hmac-sha1 hmac-sha2 hmac-blake2 chacha-poly1305 curve25519 ecdh-p256 ecdsa rsa"
    - name: optimizations
      value: |
        ["-O0", "-O1", "-O2", "-O3", "-Os", "-Ofast", "-Oz"]
    - name: commit
      value: "f283af14715cc66ec7481a3ae0ed019cbff4c790" # hacl-star
```

The run can then be launched with the following command:

```
argo submit -n microsurf --name haclstar workflow/workflow.yaml
```

## Known Issues

- Old dockerfiles might not build. Need realignment with ubuntu.
- For specific settings, a lot of memory is required (>64gb). This is mostly relevant for `-O0` builds.
