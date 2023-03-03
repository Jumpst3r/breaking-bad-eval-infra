import logging
import os
from enum import Enum

from src.process import run_subprocess
from src.config import Settings, Config

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import hex_key_generator, SecretGenerator


class Algo(Enum):
    AES_CBC = 1
    AES_CTR = 2
    AES_GCM = 3
    CAMELLIA_CBC = 4
    ARIA_CBC = 5
    DES_CBC = 6
    CHACHA_POLY1305 = 7
    HMAC_SHA1 = 10
    HMAC_SHA2 = 11
    HMAC_BLAKE2 = 13
    CURVE25519 = 20
    ECDH_P256 = 21
    ECDSA = 22
    RSA = 23
    SECRET_BOX = 50
    SECRET_STREAM = 51
    CRYPTO_BOX = 52     # Public key crypto
    CRYPTO_SIGN = 53
    CRYPTO_SEAL = 54

    def __str__(self):
        mapping = {
            Algo.AES_CBC: 'aes-cbc',
            Algo.AES_CTR: 'aes-ctr',
            Algo.AES_GCM: 'aes-gcm',
            Algo.CAMELLIA_CBC: 'camellia-cbc',
            Algo.ARIA_CBC: 'aria-cbc',
            Algo.DES_CBC: 'des-cbc',
            Algo.CHACHA_POLY1305: 'chacha-poly1305',
            Algo.HMAC_SHA1: 'hmac-sha1',
            Algo.HMAC_SHA2: 'hmac-sha2',
            Algo.HMAC_BLAKE2: 'hmac-blake2',
            Algo.CURVE25519: 'curve25519',
            Algo.ECDH_P256: 'ecdh-p256',
            Algo.ECDSA: 'ecdsa',
            Algo.RSA: 'rsa',
            Algo.SECRET_BOX: 'secretbox',
            Algo.SECRET_STREAM: 'secretstream',
            Algo.CRYPTO_BOX: 'crypto_box',
            Algo.CRYPTO_SIGN: 'crypto_sign',
            Algo.CRYPTO_SEAL: 'crypto_seal'
        }
        return mapping[self]


def algo_from_str(s: str) -> Algo:
    mapping = {
        'aes-cbc': Algo.AES_CBC,
        'aes-ctr': Algo.AES_CTR,
        'aes-gcm': Algo.AES_GCM,
        'camellia-cbc': Algo.CAMELLIA_CBC,
        'aria-cbc': Algo.ARIA_CBC,
        'des-cbc': Algo.DES_CBC,
        'chacha-poly1305': Algo.CHACHA_POLY1305,
        'hmac-sha1': Algo.HMAC_SHA1,
        'hmac-sha2': Algo.HMAC_SHA2,
        'hmac-blake2': Algo.HMAC_BLAKE2,
        'curve25519': Algo.CURVE25519,
        'ecdh-p256': Algo.ECDH_P256,
        'ecdsa': Algo.ECDSA,
        'rsa': Algo.RSA,
        'secretbox': Algo.SECRET_BOX,
        'secretstream': Algo.SECRET_STREAM,
        'crypto_box': Algo.CRYPTO_BOX,
        'crypto_sign': Algo.CRYPTO_SIGN,
        'crypto_seal': Algo.CRYPTO_SEAL
    }
    if s not in mapping:
        raise "Algorithm not supported"
    return mapping[s]


arch_str_target = {
    'x86-64': 'x86_64-unknown-linux-musl',
    'aarch64': 'aarch64-unknown-linux-musl',
    'armv4': 'arm-unknown-linux-musl',
    'armv7': 'arm-unknown-linux-musl',
    'riscv64': 'riscv64-unknown-linux-musl',
    'mips32el': 'mipsel-unknown-linux-musl',
    'x86-i686': 'i386-unknown-linux-musl'
}


class Framework:
    def __init__(self, settings: Settings, config: Config, rootfs: str, fwDir: str):
        self.settings = settings
        self.prefix = config.get_prefix(settings)
        self.rootfs = rootfs
        self.libdir = '/lib' if 'armv7' in settings.arch or 'mips32el' in settings.arch or 'x86-i686' in settings.arch else '/lib64'
        self.config = config
        self.fwDir = fwDir
        self.confFile = 'cross.mk'

        if not os.path.isdir(self.rootfs):
            os.mkdir(self.rootfs)
        # if not os.path.isdir(f'{self.rootfs}{self.libdir}'):
        #     os.mkdir(f'{self.rootfs}{self.libdir}')

    def download(self):
        pass

    def build(self):
        pass

    def supported_ciphers(self) -> list[Algo]:
        pass

    def gen_args(self, algo: Algo) -> list[str]:
        pass

    def shared_objects(self) -> list[str]:
        pass

    def clean_report(self, scd):
        pass

    def llvm_cflags(self, toolchain_dir):
        cflags = f' --target={arch_str_target[self.settings.arch]}'
        cflags += f' --gcc-toolchain={toolchain_dir}/'
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/c++/{self.settings.gcc_ver}/'
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/c++/{self.settings.gcc_ver}/{self.config.get_toolchain_name(self.settings)}/'
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/'
        cflags += f' --sysroot={toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/sysroot/'
        cflags += f' -B{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += f' -Wno-error'

        if self.settings.arch == 'riscv64':
            # For older llvm versions use -mno-relax in riscv64
            if self.settings.llvm_ver not in ['14', '15', '16']:
                cflags += f' -mno-relax'
            # Older LLVM needs a workaround for lto
            # One needs to tell opt which floating point ABI to use
            if self.settings.llvm_ver not in ['15', '16'] and '-flto' in self.settings.optflag:
                cflags += f' -Wl,-plugin-opt=-target-abi=lp64d'

        if self.settings.arch == 'aarch64':
            cflags += " -march=armv8-a"
        if self.settings.arch == 'armv7':
            cflags += " -march=armv7"
            cflags += ' -mfloat-abi=softfp'
        return cflags

    def llvm_ldflags(self, toolchain_dir):
        ldflags = self.llvm_cflags(toolchain_dir)
        ldflags += f' -fuse-ld=lld'
        ldflags += f' -L{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'

        if self.settings.arch == 'mips32el':
            ldflags += ' -Wl,-z,notext'

        return ldflags

    def run(self, algo: Algo, resultDir='results'):
        rootfs = os.getcwd() + '/rootfs'
        binpath = rootfs + '/driver.bin'

        sharedObjects = self.shared_objects()

        # keylen hardcoded to 256
        fct = hex_key_generator(256)

        args = self.gen_args(algo)

        logging.info("Creating BinaryLoader")
        binLoader = BinaryLoader(
            path=binpath,
            args=args,
            rootfs=rootfs,
            rndGen=fct,
            sharedObjects=sharedObjects,
            name=str(algo),
            resultDir=resultDir
        )
        logging.info("Configuring BinaryLoader")
        errno = binLoader.configure()
        if errno:
            logging.error("failed to configure BinaryLoader")
            raise "failed to configure BinaryLoader"

        lmodues = [DataLeakDetector(binaryLoader=binLoader, granularity=1), CFLeakDetector(
            binaryLoader=binLoader, flagVariableHitCount=True)]
        scd = SCDetector(modules=lmodues, getAssembly=True)
        scd.initTraceCount = 5
        scd.exec()

        scd = self.clean_report(scd)
        return scd


def git_clone(url: str, commit: str, name: str):
    logging.info(f'Cloning {name}')
    run_subprocess(['git', 'clone', url, name])

    os.chdir(name)
    logging.info(f'Selecting commit {commit}')
    run_subprocess(['git', 'checkout', commit])
    os.chdir('../')


def git_reset(commit: str, name: str):
    os.chdir(name)
    run_subprocess(f'git reset --hard {commit}')
    run_subprocess(f'git clean -f -x .')
    os.chdir('../')
