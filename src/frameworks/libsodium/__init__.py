from ..util import *
import os
from src.process import run_subprocess, run_subprocess_env
from src.config import Settings, Config
# import logging


# logging.getLogger().setLevel(logger.DEBUG)


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

    def custom_llvm_ldflags_configure(self, toolchain_dir):
        ldflags = f' -fuse-ld=lld'
        ldflags += f' -L{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'

        if self.settings.arch == 'mips32el':
            ldflags += ' -Wl,-z,notext'
        
        return ldflags
    
    def custom_llvm_ldflags_make(self, toolchain_dir):
        ldflags = f'-XCClinker --target={arch_str_target[self.settings.arch]}'
        ldflags += f' -XCClinker -B{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        ldflags += f' -fuse-ld=lld'
        ldflags += f' -L{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'

        if self.settings.arch == 'mips32el':
            ldflags += ' -Wl,-z,notext'
        
        return ldflags

    def build_lib(self):
        cwd = os.getcwd()

        os.chdir(f"{self.name}/")

        logger.info(
            f'Configuring {self.name} for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        cflags += f" {self.settings.optflag}"
        ldflags = ""
        if self.settings.arch == 'x86-i686':
            cflags += " -m32 -march=i386"
        if self.settings.arch == 'aarch64':
            # cflags += " --specs=nosys.specs"
            cflags += " -march=armv8-a"
        if self.settings.arch == 'armv7':
            # cflags += " --specs=nosys.specs"
            cflags += " -march=armv7"
            # cflags += ' -mfloat-abi=softfp'
            cflags += ' -mfloat-abi=hard'
        if self.settings.compiler == 'llvm':
            ldflags += self.custom_llvm_ldflags_configure(f'{cwd}/toolchain')
            cflags += self.llvm_cflags(f'{cwd}/toolchain')

        logger.info(f'Setting CFLAGS to {cflags}')
        logger.info(f'Setting LDFLAGS to {ldflags}')

        logger.info(f'Calling ./configure')
        if self.settings.compiler == 'gcc':
            # run_subprocess_env(f'./configure --host {self.config.get_toolchain_name(self.settings)}',
            #                    cflags=cflags, ldflags=ldflags, path=f'{cwd}/toolchain/bin')
            prefix = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}'
            cc = f'{prefix}-gcc'
            ld = f'{prefix}-ld'
            ar = f'{prefix}-ar'
            ranlib = f'{prefix}-ranlib'
            run_subprocess_env(f'./configure --host {self.config.get_toolchain_name(self.settings)}',
                               cflags=cflags, ldflags=ldflags, cc=cc, ld=ld, ar=ar, ranlib=ranlib)
        elif self.settings.compiler == 'llvm':
            # run_subprocess_env(f'./configure --host {self.config.get_toolchain_name(self.settings)}',
            #                    cc='clang', cflags=cflags, ldflags=ldflags, path=f'{cwd}/toolchain/bin')
            run_subprocess_env(f'./configure --host {self.config.get_toolchain_name(self.settings)}',
                               cflags=cflags, ldflags=ldflags, cc="clang", ar="llvm-ar", ranlib="llvm-ranlib")

        logger.info(f'Building {self.name} (make)')
        if self.settings.compiler == 'llvm':
            ldflags = self.custom_llvm_ldflags_make(f'{cwd}/toolchain')
            run_subprocess_env(f'make -j6 LDFLAGS="{ldflags}"', path=f'{cwd}/toolchain/bin')
        else:
            run_subprocess_env('make -j6', path=f'{cwd}/toolchain/bin')

        os.chdir(cwd)

    def copy_lib_rootfs(self):
        logger.info(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

        logger.info(f"pwd = {os.getcwd()}")
        run_subprocess(
            f'cp {cwd}/{self.name}/src/libsodium/.libs/libsodium.so* {os.getcwd()}/{self.rootfs}/{self.libdir}')

    def build(self):
        self.build_lib()
        self.copy_lib_rootfs()

        logger.info(f'- Building driver.c')

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
