from ..util import *
import os
from src.process import run_subprocess, run_subprocess_env
from src.config import Settings, Config
import logging


logging.getLogger().setLevel(logging.DEBUG)


class Libsodium(Framework):
    def __init__(self, settings: Settings, config: Config, rootfs: str, fwDir: str):
        self.name = 'libsodium'
        self.url = 'https://github.com/jedisct1/libsodium.git'
        super().__init__(settings, config, rootfs, fwDir)

    def download(self):
        if not os.path.isdir(self.name):
            git_clone(self.url, self.settings.commit, self.name)
        else:
            git_reset(self.settings.commit, self.name)

    def custom_llvm_ldflags(self, toolchain_dir):
        ldflags = f'-XCClinker --target={arch_str_target[self.settings.arch]}'
        ldflags += f' -XCClinker -B{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        ldflags += f' -fuse-ld=lld'
        ldflags += f' -L{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        
        return ldflags

    def build_lib(self):
        cwd = os.getcwd()

        os.chdir(f"{self.name}/")

        logging.info(
            f'Configuring {self.name} for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        cflags += f" {self.settings.optflag}"
        ldflags = ""
        if self.settings.compiler == 'gcc':
            if self.settings.arch == 'x86-i686':
                cflags += " -m32 -march=i386"
            if self.settings.arch == 'aarch64':
                cflags += " --specs=nosys.specs"
                cflags += " -march=armv8-a"
            if self.settings.arch == 'armv7':
                cflags += " --specs=nosys.specs"
                cflags += " -march=armv7"
                cflags += ' -mfloat-abi=softfp'
        if self.settings.compiler == 'llvm':
            ldflags += self.custom_llvm_ldflags(f'{cwd}/toolchain')
            cflags += self.llvm_cflags(f'{cwd}/toolchain')

        logging.info(f'Setting CFLAGS to {cflags}')
        logging.info(f'Setting LDFLAGS to {ldflags}')

        logging.info(f'Calling ./configure')
        if self.settings.compiler == 'gcc':
            run_subprocess_env(f'./configure --host {self.config.get_toolchain_name(self.settings)}',
                               cflags=cflags, ldflags=ldflags, path=f'{cwd}/toolchain/bin')
        elif self.settings.compiler == 'llvm':
            run_subprocess_env(f'./configure --host {self.config.get_toolchain_name(self.settings)}',
                               cc='clang', cflags=cflags, ldflags=ldflags, path=f'{cwd}/toolchain/bin')

        logging.info(f'Building {self.name} (make)')
        run_subprocess_env('make -j6', path=f'{cwd}/toolchain/bin')

        os.chdir(cwd)

    def copy_lib_rootfs(self):
        logging.info(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

        logging.info(f"pwd = {os.getcwd()}")
        run_subprocess(
            f'cp {cwd}/{self.name}/src/libsodium/.libs/libsodium.so* {os.getcwd()}/{self.rootfs}/{self.libdir}')

    def build(self):
        self.build_lib()
        self.copy_lib_rootfs()

        logging.info(f'- Building driver.c')

        cwd = os.getcwd()

        includestr = f'-I{self.name}/src/libsodium/include/'
        librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lsodium'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_ldflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {librarystr} {cflags} {self.fwDir}/{self.name}/driver.c -lm -o {self.rootfs}/driver.bin')

    def supported_ciphers(self) -> list[Algo]:
        return [
            Algo.CHACHA_POLY1305,
            Algo.HMAC_SHA2,
            Algo.HMAC_BLAKE2,
            Algo.SECRET_BOX,
            Algo.SECRET_STREAM,
            Algo.CRYPTO_BOX,
            Algo.CRYPTO_SIGN,
            Algo.CRYPTO_SEAL,
            Algo.CURVE25519
        ]

    def gen_args(self, algo: Algo) -> list[str]:
        if algo not in self.supported_ciphers():
            raise "Unsupported algorithm"

        algo_str = {
            Algo.CHACHA_POLY1305: 'secretbox',
            Algo.HMAC_BLAKE2: 'generichash',
            Algo.HMAC_SHA2: 'hmac-sha2',
            Algo.SECRET_BOX: 'secretbox',
            Algo.SECRET_STREAM: 'secretstream',
            Algo.CRYPTO_BOX: 'crypto_box',
            Algo.CRYPTO_SIGN: 'crypto_sign',
            Algo.CRYPTO_SEAL: 'crypto_seal',
            Algo.CURVE25519: 'crypto_kx'
        }

        return f'@ {algo_str[algo]}'.split()

    def shared_objects(self) -> list[str]:
        return ['libsodium']

    def clean_report(self, scd):
        # mask = scd.DF['Symbol Name'].str.contains('hextobin')
        # scd.DF = scd.DF[~mask]
        # # recreate reports:
        # scd._generateReport()
        return scd
