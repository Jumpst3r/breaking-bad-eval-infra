from ..util import *
import os
from src.process import run_subprocess, run_subprocess_env
from src.config import Settings, Config
import logging

logging.getLogger().setLevel(logging.DEBUG)

class Mbedtls(Framework):
    def __init__(self, settings: Settings, config: Config, rootfs: str, fwDir):
        self.name = 'mbedtls'
        self.url = 'https://github.com/Mbed-TLS/mbedtls.git'
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
            f'Configuring MBEDTLS for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        cflags += f" {self.settings.optflag}"
        ldflags = ""
        if self.settings.arch == 'x86-i686':
            cflags += " -m32 -march=i386"
        if self.settings.arch == 'aarch64':
            cflags += " -march=armv8-a"
        if self.settings.arch == 'armv4':
            cflags += " -march=armv4"
        if self.settings.arch == 'armv7':
            cflags += ' -march=armv7 -mthumb'
        if self.settings.compiler == 'llvm':
            cflags += self.llvm_cflags(f'{cwd}/../toolchain')
            ldflags = self.llvm_ldflags(f'{cwd}/../toolchain')

        logging.info(f'Setting CFLAGS to {cflags}')

        logging.info('Building mbedtls (make)')
        if self.settings.compiler == 'gcc':
            prefix = f'{cwd}/../toolchain/bin/{self.config.get_toolchain_name(self.settings)}'
            cc = f'{prefix}-gcc'
            ld = f'{prefix}-ld'
            ar = f'{prefix}-ar'
            run_subprocess_env(['SHARED=1 make lib'], cc=cc,
                               ld=ld, ar=ar, cflags=cflags)
        if self.settings.compiler == 'llvm':
            run_subprocess_env(['SHARED=1 make lib'], cc='clang', ar='llvm-ar',
                               cxx='clang++', ld='clang', cflags=cflags, ldflags=ldflags)

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
        includestr += f' -I{self.name}/include/mbedtls'
        includestr += f' -I{self.name}/include/psa'
        librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lmbedcrypto'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_ldflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {librarystr} {cflags} {self.fwDir}/{self.name}/driver.c {self.fwDir}/{self.name}/crypt_and_hash.c {self.fwDir}/{self.name}/ecdsa.c {self.fwDir}/{self.name}/ecdh.c -lm -o {self.rootfs}/driver.bin')

    def supported_ciphers(self) -> list[Algo]:
        return [
            Algo.AES_CBC,
            Algo.AES_CTR,
            Algo.AES_GCM,
            Algo.CAMELLIA_CBC,
            Algo.ARIA_CBC,
            Algo.DES_CBC,
            Algo.CHACHA_POLY1305,
            Algo.HMAC_SHA2,
            Algo.ECDH_P256,
            Algo.ECDSA,
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
            Algo.ARIA_CBC: 'aria-cbc',
            Algo.DES_CBC: 'des-cbc',
            Algo.CHACHA_POLY1305: 'chacha-poly1305',
            Algo.HMAC_SHA2: 'hmac-sha256',
            Algo.ECDH_P256: 'ecdh-p256',
            Algo.ECDSA: 'ecdsa-p256',
            Algo.CURVE25519: 'ecdh-25519'
        }

        # ECDH and ECDSA require different inputs
        if algo in [Algo.ECDH_P256, Algo.ECDSA, Algo.CURVE25519]:
            return f'{algo_str[algo]} @'.split()

        # create input and output files
        with open(f'{self.rootfs}/input', 'w') as file:
            file.write('AAAAAAAAAAAAAAA')

        # empty output file
        open(f'{self.rootfs}/output', 'w').close()

        return f'0 input output {algo_str[algo]} SHA1 @'.split()

    def shared_objects(self) -> list[str]:
        return ['libmbedcrypto']

    def clean_report(self, scd):
        # mask = scd.DF['Symbol Name'].str.contains('hextobin')
        # scd.DF = scd.DF[~mask]
        # # recreate reports:
        # scd._generateReport()
        return scd
