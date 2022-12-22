import logging
import os
from enum import Enum

from process import run_subprocess
from config import Settings, Config


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


class Framework:
    def __init__(self, settings: Settings, config: Config, rootfs: str):
        pass

    def download(self):
        pass

    def build(self):
        pass

    def supported_ciphers(self) -> list[Algo]:
        pass


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
