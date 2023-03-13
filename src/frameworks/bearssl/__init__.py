from ..util import *
import os
from src.process import run_subprocess, run_subprocess_env
from src.config import Settings, Config
import logging

logging.getLogger().setLevel(logging.DEBUG)

arch_str_gcc = {
    'x86-64': 'linux-x86_64',
    'aarch64': 'linux-aarch64',
    'armv4': 'linux-armv4',
    'armv7': 'linux-armv7',
    'riscv64': 'linux64-riscv64',
    'mips32el': 'linux-mips32',
    'x86-i686': 'linux-x86'
}

arch_str_llvm = {
    'x86-64': 'linux-x86_64-clang',
    'aarch64': 'linux-aarch64',
    'armv4': 'linux-armv4',
    'armv7': 'linux-armv7',
    'riscv64': 'linux64-riscv64',
    'mips32el': 'linux-mips32',
    'x86-i686': 'linux-x86-clang'
}


class Bearssl(Framework):
    def __init__(self, settings: Settings, config: Config, rootfs: str, fwDir: str):
        self.name = 'BearSSL'
        self.url = 'https://www.bearssl.org/git/BearSSL'
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
            f'Configuring {self.name} for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        cflags += f" {self.settings.optflag}"
        if self.settings.compiler == 'gcc':
            if self.settings.arch == 'x86-i686':
                cflags += " -m32 -march=i386"
            if self.settings.arch == 'aarch64':
                cflags += " -march=armv8-a"
            if self.settings.arch == 'armv4':
                cflags += " -march=armv4"
        if self.settings.compiler == 'llvm':
            cflags += self.llvm_cflags(f'{cwd}/../toolchain')

        logging.info(f'Setting CFLAGS to {cflags}')

        with open(f'conf/{self.confFile}', 'w') as f:
            f.write('include conf/Unix.mk\n')
            f.write('BUILD = crossbuild\n')
            f.write(f'CFLAGS = {cflags} -fPIC\n')
            if self.settings.compiler == 'gcc':
                f.write(f'CC = {cwd}/../toolchain/{self.prefix}gcc\n')
                f.write(f'LD = {cwd}/../toolchain/{self.prefix}gcc\n')
                f.write(f'LDDLL = {cwd}/../toolchain/{self.prefix}gcc\n')
                f.write(f'AR = {cwd}/../toolchain/{self.prefix}ar\n')
            else:
                f.write('CC = clang\n')
                f.write('LD = clang\n')
                f.write('LDDLL = clang\n')
                f.write('AR = llvm-ar\n')

                f.write(
                    f'LDDLLFLAGS = -shared {self.llvm_ldflags(f"{cwd}/../toolchain")}\n')
                f.write(
                    f'LDFLAGS = {self.llvm_ldflags(f"{cwd}/../toolchain")}\n')

        logging.info(f'Building {self.name} (make)')
        run_subprocess(f'make CONF=cross -j6')

        os.chdir('../')

    def copy_lib_rootfs(self):
        logging.info(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

        logging.info(f"pwd = {os.getcwd()}")
        run_subprocess(
            f'cp BearSSL/crossbuild/libbearssl.so {os.getcwd()}/{self.rootfs}/{self.libdir}')

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

        includestr = f'-I{self.name}/inc'
        librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lbearssl'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_ldflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {librarystr} {cflags} {self.fwDir}/bearssl/driver.c -lm -o {self.rootfs}/driver.bin')

    def supported_ciphers(self) -> list[Algo]:
        return [
            Algo.AES_CBC,
            Algo.AES_CTR,
            Algo.AES_GCM,
            Algo.CHACHA_POLY1305,
            Algo.HMAC_SHA1,
            Algo.HMAC_SHA2,
            Algo.ECDSA,
            Algo.ECDH_P256,
            Algo.CURVE25519,
            Algo.RSA
        ]

    def gen_args(self, algo: Algo) -> list[str]:
        if algo not in self.supported_ciphers():
            raise "Unsupported algorithm"

        algo_str = {
            Algo.AES_CBC: 'aes-cbc',
            Algo.AES_CTR: 'aes-ctr',
            Algo.AES_GCM: 'aes-gcm',
            Algo.CHACHA_POLY1305: 'chacha-poly1305',
            Algo.HMAC_SHA1: 'hmac-sha1',
            Algo.HMAC_SHA2: 'hmac-sha2',
            Algo.ECDSA: 'ecdsa-p256',
            Algo.ECDH_P256: 'ecdh-p256',
            Algo.CURVE25519: 'ecdh-25519',
            Algo.RSA: 'rsa'
        }

        return f'@ {algo_str[algo]}'.split()

    def shared_objects(self) -> list[str]:
        return ['libbearssl']

    def clean_report(self, scd):
        # mask = scd.DF['Symbol Name'].str.contains('hextobin')
        # scd.DF = scd.DF[~mask]
        # # recreate reports:
        # scd._generateReport()
        return scd
