import random
import os
import sys
import json
import subprocess
import base64
import uuid
import logging
from typing import Dict

from config import *
from process import run_subprocess


resultjson = []
initPath = ""


def download_gcc(url: str, sha256: str):
    """download gcc

    Args:
        url (str): URL to be downloaded
        sha256 (str): Checksum url
    """
    print('- Downloading GCC')
    run_subprocess(['wget', '-O', 'toolchain.tar.bz2', url])
    # checkretcode(result)

    run_subprocess(['wget', '-O', 'toolchain.tar.bz2.sha256', sha256])
    # checkretcode(result)

    with open('toolchain.tar.bz2.sha256', 'r+') as f:
        l = f.readline()
        hash, name = l.split('  ')
        f.seek(0)
        f.writelines([f'{hash} toolchain.tar.bz2'])
        f.truncate()

    print('- Checking checksum')
    run_subprocess(['sha256sum', '-c', 'toolchain.tar.bz2.sha256'])

    print('- Extracting')
    run_subprocess(['mkdir', '-p', 'toolchain'])

    run_subprocess(['tar', '-xf', 'toolchain.tar.bz2', '-C',
                    'toolchain', '--strip-components', '1'])


def check_llvm(version: str):
    """Check that the installed LLVM version is correct

    Args:
        version (str): Major version of LLVM that is expected to be installed, 
                       e.g., '15' 
    """
    print('- Checking LLVM')
    result = run_subprocess(
        ['clang', '--version'])
    # print(result.stdout)

    if f"{version}." not in result.stdout.decode():
        logging.error(
            f'Unexpected LLVM version.\nExpected: {version}\nFound: {result.stdout}')
        exit(-1)


def toolchain(config: Config, settings: Settings, DOWNLOAD=True):
    """Download and setup the specified toolchain

    Args:
        arch (str): Architecture for the toolchain. Must be listed in 
                    `config.json` to be supported.
        compiler (str): currently only 'gcc' and 'llvm' supported.
        version (str): Version string of the compiler.
        DOWNLOAD (bool, optional): Download the toolchain. Defaults to True.
    """
    toolchain_data = config.get_toolchain_data(settings)

    download_gcc(toolchain_data['gcc']['versions'][settings.gcc_ver]['url'],
                 toolchain_data['gcc']['versions'][settings.gcc_ver]['sha256'])

    check_llvm(settings.llvm_ver)
    set_toolchain_params(config, settings, toolchain_data)


def set_toolchain_params(config: Config, settings: Settings, toolchain_data: Dict = None):
    if toolchain_data == None:
        toolchain_data = config.get_toolchain_data(settings)

    os.environ["TOOLCHAIN_ROOT"] = os.getcwd() + '/toolchain'
    print(f'- Set TOOLCHAIN_ROOT to {os.environ.get("TOOLCHAIN_ROOT")}')

    os.environ["ROOTFS"] = os.getcwd() + '/toolchain/' + \
        toolchain_data['gcc']['rootfs']
    print(f'- Set ROOTFS to {os.environ.get("ROOTFS")}')

