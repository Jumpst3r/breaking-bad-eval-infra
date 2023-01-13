import logging
import os
from enum import Enum

from process import run_subprocess
from config import Settings, Config

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
    HMAC_SHA3 = 12
    HMAC_BLAKE2 = 13
    ECDH_CURVE25519 = 20
    ECDH_P256 = 21
    ECDSA = 22


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
        'hmac-sha3': Algo.HMAC_SHA3,
        'hmac-blake2': Algo.HMAC_BLAKE2,
        'ecdh-curve25519': Algo.ECDH_CURVE25519,
        'ecdh-p256': Algo.ECDH_P256,
        'ecdsa': Algo.ECDSA
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
    def __init__(self, settings: Settings, config: Config, rootfs: str):
        pass

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

    def run(self, algo: Algo):
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
            sharedObjects=sharedObjects
        )
        logging.info("Configuring BinaryLoader")
        errno = binLoader.configure()
        if errno:
            logging.error("failed to configure BinaryLoader")
            raise "failed to configure BinaryLoader"

        lmodues = [DataLeakDetector(binaryLoader=binLoader, granularity=1), CFLeakDetector(
            binaryLoader=binLoader, flagVariableHitCount=True)]
        scd = SCDetector(modules=lmodues, getAssembly=True)
        scd.initTraceCount = 10
        scd.exec()

        scd = self.clean_report(scd)


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
