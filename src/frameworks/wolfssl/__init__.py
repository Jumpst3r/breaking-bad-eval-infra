from ..util import *
import os
from src.process import run_subprocess, run_subprocess_env
from src.config import Settings, Config
import logging

logging.getLogger().setLevel(logging.DEBUG)

host_str = {
    'riscv64': 'riscv64',
    'x86-64': 'x86_64',
    'x86-i686': 'x86',
    'armv4': 'arm',
    'armv7': 'arm',
    'aarch64': 'arm',
    'mips32el': 'mips'
}


class Wolfssl(Framework):
    def __init__(self, settings: Settings, config: Config, rootfs: str, fwDir: str):
        self.name = 'wolfssl'
        self.url = 'https://github.com/wolfSSL/wolfssl.git'
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

        if self.settings.arch == 'x86-i686':
            cflags += " -m32 -march=i386"
        if self.settings.arch == 'aarch64':
            cflags += " -march=armv8-a"
        if self.settings.arch == 'armv4':
            cflags += " -march=armv4"
        if self.settings.arch == 'armv7':
            cflags += ' -march=armv7 -mthumb'
        if self.settings.compiler == 'llvm':
            cflags += self.llvm_ldflags(f'{cwd}/../toolchain')

        logging.info(f'Setting CFLAGS to {cflags}')

        logging.info(f'Configuring {self.name} (autogen)')
        run_subprocess('./autogen.sh')

        logging.info(f'Configuring {self.name} (configure)')
        common = f'--enable-all-crypto --disable-shared --enable-opensslall --enable-static --disable-optflags --host={host_str[self.settings.arch]}'

        prefix = f'{cwd}/../toolchain/bin/{self.config.get_toolchain_name(self.settings)}'
        if self.settings.compiler == 'gcc':
            cc = f'{prefix}-gcc'
            ld = f'{prefix}-ld'
            ar = f'{prefix}-ar'
            ranlib = f'{prefix}-ranlib'
        else:
            cc = 'clang'
            ld = 'lld'
            ar = 'llvm-ar'
            ranlib = 'llvm-ranlib'

        run_subprocess_env(f'./configure {common}', cc=cc,
                           ld=ld, ar=ar, cflags=cflags, ranlib=ranlib)

        logging.info(f'Building {self.name} (make)')
        run_subprocess_env('make')

        os.chdir('../')

    def copy_lib_rootfs(self):
        logging.info(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

    def build(self):
        self.build_lib()
        self.copy_lib_rootfs()

        logging.info(f'- Building driver.c')

        cwd = os.getcwd()

        includestr = f'-I{self.name}/'
        includestr += f' -I{self.name}/wolfssl'
        includestr += f' -I{self.name}/wolfssl/openssl'
        includestr += f' -I{self.name}/wolfssl/wolfcrypt'
        includestr += f'-I{self.fwDir}/{self.name}/'
        librarystr = f'{self.name}/src/.libs/libwolfssl.a'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_ldflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {cflags} -lm -lpthread {self.fwDir}/{self.name}/driver.c {librarystr} -o {self.rootfs}/driver.bin')

    def supported_ciphers(self) -> list[Algo]:
        return [
            Algo.AES_CBC,
            Algo.AES_CTR,
            Algo.AES_GCM,
            Algo.CAMELLIA_CBC,
            Algo.DES_CBC,
            Algo.HMAC_SHA1,
            Algo.HMAC_SHA2,
            Algo.CHACHA_POLY1305,
            Algo.CURVE25519
        ]

    def gen_args(self, algo: Algo) -> list[str]:
        if algo not in self.supported_ciphers():
            raise "Unsupported algorithm"

        algo_str = {
            Algo.AES_CBC: 'aes-cbc',
            Algo.AES_CTR: 'aes-ctr',
            Algo.AES_GCM: 'aes-gcm',
            Algo.CAMELLIA_CBC: 'camellia-cbc',
            Algo.DES_CBC: 'des-cbc',
            Algo.HMAC_SHA1: 'hmac-sha1',
            Algo.HMAC_SHA2: 'hmac-sha256',
            Algo.CHACHA_POLY1305: 'chachapoly1305',
            Algo.CURVE25519: 'curve25519'
        }

        return f'@ {algo_str[algo]}'.split()

    def shared_objects(self) -> list[str]:
        # wolfssl is not compiled to a shared library but a static one
        # therefore, we cannot just trace the shared library
        # by returning an empty list, the entire binary is traced
        return []

    def clean_report(self, scd):
        # mask = scd.DF['Symbol Name'].str.contains('hextobin')
        # scd.DF = scd.DF[~mask]
        # # recreate reports:
        # scd._generateReport()
        # # if len(scd.DF.index) != 0:

        return scd
