from ..util import *
import os
from src.process import run_subprocess, run_subprocess_env
from src.config import Settings, Config
import logging

logging.getLogger().setLevel(logging.DEBUG)

compile_options = {"buildcmd-gcc": ["./Configure linux-aarch64 --cross-compile-prefix={cwd}/../toolchain/bin/aarch64-linux- $CFLAGS", "make -j4"],
                   "buildcmd-clang": ["./Configure linux-aarch64 $CFLAGS", "sed -i \"/^CC=/c\\CC=clang\" Makefile && sed -i \"/^AR=/c\\AR=llvm-ar\" Makefile && sed -i \"/^CXX=/c\\CXX=clang++\" Makefile", "make -j4"],
                   "cflags-clang": "--target=aarch64-elf-linux -gdwarf-4 -march=armv8-a --gcc-toolchain={cwd}/../toolchain/ -I{cwd}/../toolchain/aarch64-buildroot-linux-gnu/include/c++/7.3.0/ -I{cwd}/../toolchain/aarch64-buildroot-linux-gnu/include/c++/7.3.0/aarch64-buildroot-linux-gnu/ -I{cwd}/../toolchain/aarch64-buildroot-linux-gnu/include/ --sysroot={cwd}/../toolchain/aarch64-buildroot-linux-gnu/sysroot -L{cwd}/../toolchain/lib/gcc/aarch64-buildroot-linux-gnu/7.3.0/ -B {cwd}/../toolchain/lib/gcc/aarch64-buildroot-linux-gnu/7.3.0/ -fuse-ld=lld -Wno-error",
                                   "cflags-gcc": "-march=armv8-a -gdwarf-4"}

arch_str_gcc = {
    'x86-64': 'linux-x86_64',
    'aarch64': 'linux-aarch64',
    'armv4': 'linux-armv4',
    'armv7': 'linux-armv4',
    'riscv64': 'linux64-riscv64',
    'mips32el': 'linux-mips32',
    'x86-i686': 'linux-x86'
}

arch_str_llvm = {
    'x86-64': 'linux-x86_64-clang',
    'aarch64': 'linux-aarch64',
    'armv4': 'linux-armv4',
    'armv7': 'linux-armv4',
    'riscv64': 'linux64-riscv64',
    'mips32el': 'linux-mips32',
    'x86-i686': 'linux-x86-clang'
}

# Example configure call using LLVM and aarch64
# ./Configure linux-aarch64 \
# --target=aarch64-elf-linux -gdwarf-4 -march=armv8-a \
# --gcc-toolchain={cwd}/../toolchain/ \
# -I{cwd}/../toolchain/aarch64-buildroot-linux-musl/include/c++/11.3.0/ \
# -I{cwd}/../toolchain/aarch64-buildroot-linux-musl/include/c++/11.3.0/aarch64-buildroot-linux-musl/ \
# -I{cwd}/../toolchain/aarch64-buildroot-linux-musl/include/ \
# --sysroot={cwd}/../toolchain/aarch64-buildroot-linux-musl/sysroot \
# -L{cwd}/../toolchain/lib/gcc/aarch64-buildroot-linux-musl/11.3.0/ \
# -B {cwd}/../toolchain/lib/gcc/aarch64-buildroot-linux-musl/11.3.0/ \
# -fuse-ld=lld -Wno-error


class Openssl(Framework):
    def __init__(self, settings: Settings, config: Config, rootfs: str, fwDir: str):
        self.name = 'openssl'
        self.url = 'git://git.openssl.org/openssl.git'
        super().__init__(settings, config, rootfs, fwDir)

    def download(self):
        if not os.path.isdir(self.name):
            git_clone(self.url, self.settings.commit, self.name)
        else:
            git_reset(self.settings.commit, self.name)

    def build_lib(self):
        os.chdir(self.name)

        cwd = os.getcwd()

        logging.info(
            f'Configuring openssl for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        cflags += f" {self.settings.optflag}"

        if self.settings.arch == 'x86-i686':
            cflags += " -m32 -march=i386"
        if self.settings.arch == 'aarch64':
            cflags += " -march=armv8-a"
        if self.settings.arch == 'armv7':
            cflags += " -march=armv7"
            cflags += " no-asm" # openssl somehow includes armv8 insturctions in this build
        if self.settings.compiler == 'llvm':
            cflags += self.llvm_ldflags(f'{cwd}/../toolchain')

        logging.info(f'Setting CFLAGS to {cflags}')

        if self.settings.compiler == 'gcc':
            configure = [
                './Configure',
                f'{arch_str_gcc[self.settings.arch]}',
                f'--cross-compile-prefix={cwd}/../toolchain/{self.prefix}',
                'no-async',  # Some older versions of openssl do not support async with MUSL
                cflags
            ]
            run_subprocess(configure)
        elif self.settings.compiler == 'llvm':
            configure = [
                './Configure',
                f'{arch_str_llvm[self.settings.arch]}',
                cflags
            ]
            run_subprocess_env(configure, 'clang', 'llvm-ar', 'clang++')
        else:
            logging.error('Unknown compiler for Openssl')
            raise Exception('Unknown compiler for Openssl')

        logging.info('Building OpenSSL (make)')
        if self.settings.compiler == 'gcc':
            run_subprocess(['make', '-j6'])
        if self.settings.compiler == 'llvm':
            run_subprocess_env(['make', '-j6'], 'clang', 'llvm-ar', 'clang++')

        os.chdir('../')

    def copy_lib_rootfs(self):
        logging.info(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

        logging.info(f"pwd = {os.getcwd()}")
        logging.info(f"find ./ -name '{self.name}*.so'")
        run_subprocess(
            f'cp $(find ./{self.name} -name "*.so") {os.getcwd()}/{self.rootfs}/{self.libdir}')
        run_subprocess(
            f'cp $(find ./{self.name} -name "*.so.*") {os.getcwd()}/{self.rootfs}/{self.libdir}')

        # emulation for ppc requires libs in a different dir
        if 'powerpc' in self.settings.arch:
            run_subprocess(
                f'mkdir -p {os.getcwd()}/../{self.rootfs}/{self.libdir}/tls/i686')
            run_subprocess(
                f'cp {os.getcwd()}/../{self.rootfs}/{self.libdir}/* {os.getcwd()}/../toolchain/{self.rootfs}/{self.libdir}/tls/i686/')

    def build(self):
        self.build_lib()
        self.copy_lib_rootfs()

        logging.info(f'- Building driver.c')

        cwd = os.getcwd()

        includestr = f'-I{self.name}/include'
        librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lcrypto'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_ldflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {librarystr} {cflags} {self.fwDir}/{self.name}/driver.c -lm -o {self.rootfs}/driver.bin')

    def supported_ciphers(self) -> list[Algo]:
        return [
            Algo.AES_CBC,
            Algo.AES_CTR,
            Algo.AES_GCM,
            Algo.CAMELLIA_CBC,
            Algo.ARIA_CBC,
            Algo.DES_CBC,
            Algo.CHACHA_POLY1305,
            Algo.HMAC_SHA1,
            Algo.HMAC_SHA2,
            Algo.HMAC_BLAKE2,
            Algo.ECDH_P256,
            Algo.CURVE25519,
            Algo.ECDSA
        ]

    def gen_args(self, algo: Algo) -> list[str]:
        if algo not in self.supported_ciphers():
            raise "Unsupported algorithm"

        algo_str = {
            Algo.AES_CBC: 'aes-cbc',
            Algo.AES_CTR: 'aes-ctr',
            Algo.AES_GCM: 'aes-gcm',
            Algo.CAMELLIA_CBC: 'camellia-cbc',
            Algo.ARIA_CBC: 'aria-cbc',
            Algo.DES_CBC: 'des-cbc',
            Algo.CHACHA_POLY1305: 'chacha_poly1305',
            Algo.HMAC_SHA1: 'hmac-sha1',
            Algo.HMAC_SHA2: 'hmac-sha256',
            Algo.HMAC_BLAKE2: 'hmac-blake2',
            Algo.ECDH_P256: 'ecdh-p256',
            Algo.CURVE25519: 'x25519',
            Algo.ECDSA: 'ecdsa'
        }

        return f'@ {algo_str[algo]}'.split()

    def shared_objects(self) -> list[str]:
        return ['libcrypto']

    def clean_report(self, scd):
        # mask = scd.DF['Symbol Name'].str.contains('hextobin')
        # scd.DF = scd.DF[~mask]
        # # recreate reports:
        # scd._generateReport()
        return scd
