import json
from json import tool
from typing import Dict
import logging

from dataclasses import dataclass
from xmlrpc.client import Boolean


@dataclass
class Settings:
    gcc_ver: str
    llvm_ver: str
    compiler: str
    arch: str
    framework: str
    optflag: str
    commit: str

    def __init__(self, arch: str, compiler: str = "gcc", version: str = "11.3.0", framework: str = "openssl", optflag: str = "-O2", commit: str = None):
        # We always need a gcc toolchain for the sysroot and the includes
        # we use version 11.3.0
        self.gcc_ver = version if compiler == 'gcc' else '11.3.0'
        self.llvm_ver = version if compiler == 'llvm' else '15'
        self.arch = arch
        self.compiler = compiler
        self.framework = framework
        self.optflag = optflag
        self.commit = commit


def replace_placholders(toolchain_name: str, gcc_ver: str, llvm_ver: str, obj: Dict) -> Dict:
    """Replace placeholders in config.json. Currently there are three distinct
    placeholders to replace: '${TOOLCHAIN}', '${GCC_VER}', and '${LLVM_VER}'.

    Args:
        toolchain_name (str): String to replace '${TOOLCHAIN}'
        gcc_ver (str): String to replace '${GCC_VER}'
        llvm_ver (str): String to replace '${LLVM_VER}'
        obj (Dict): Object to parse

    Returns:
        The dict where all values with the type str are parsed and the keywords
        above are replaced with `toolchain_name`, `gcc_ver`, and `llvm_ver`
        respectively.
    """
    if isinstance(obj, dict):
        for key in obj:
            if isinstance(obj[key], str):
                obj[key] = obj[key].replace('${TOOLCHAIN}', toolchain_name)
                obj[key] = obj[key].replace('${GCC_VER}', gcc_ver)
                obj[key] = obj[key].replace('${LLVM_VER}', llvm_ver)
            if isinstance(obj[key], dict):
                obj[key] = replace_placholders(
                    toolchain_name, gcc_ver, llvm_ver, obj[key])
            if isinstance(obj[key], list):
                obj[key] = [replace_placholders(
                    toolchain_name, gcc_ver, llvm_ver, elem) for elem in obj[key]]
    if isinstance(obj, str):
        obj = obj.replace('${TOOLCHAIN}', toolchain_name)
        obj = obj.replace('${GCC_VER}', gcc_ver)
        obj = obj.replace('${LLVM_VER}', llvm_ver)
    return obj


class Config:
    def __init__(self, settings: Settings, path='config.json'):
        with open(path, 'r') as f:
            self.config = json.load(f)
        if not self.validate_settings(settings):
            raise Exception("Config failed to validate")

    def get_toolchain_data(self, settings: Settings) -> Dict:
        """Get toolchain data

        Args:
            settings (Settings): 


        Returns:
            Dict: Toolchain data
        """
        data = {}
        data['gcc'] = self.config['gcc'][settings.arch]
        data['llvm'] = self.config['llvm']
        toolchain_name = data['gcc']['toolchain']
        return replace_placholders(toolchain_name, settings.gcc_ver, settings.llvm_ver, data)

    def get_framework_data(self, settings: Settings) -> Dict:
        """Get framework data

        Args:
            settings (Settings): 

        Returns:
            Dict: framework data
        """

        data = self.config['frameworks'][settings.framework]
        return data

    def get_framework_config(self, settings: Settings) -> Dict:
        """Get framework config

        Args:
            settings (Settings): 

        Returns:
            Dict: Framework config
        """
        toolchain_name = self.config[settings.compiler][settings.arch]["toolchain"]
        data = self.config['architectures'][settings.arch][settings.framework]
        return replace_placholders(toolchain_name, settings.gcc_ver, settings.llvm_ver, data)

    def get_prefix(self, settings: Settings) -> str:
        return self.get_toolchain_data(settings)['gcc']['prefix']

    def get_toolchain_name(self, settings: Settings) -> str:
        return self.get_toolchain_data(settings)['gcc']['toolchain']

    def validate_settings(self, settings: Settings) -> Boolean:
        # Validate compiler
        if settings.compiler not in ['gcc', 'llvm']:
            raise Exception('Invalid compiler.')

        # validate that we have a gcc toolchain with the correct architecture
        if settings.arch not in self.config['gcc']:
            raise Exception('Invalid architecture.')

        # validate that the compiler version exists
        if settings.gcc_ver not in self.config['gcc'][settings.arch]['versions']:
            raise Exception('Invalid version.')

        if settings.llvm_ver not in self.config['llvm']['versions']:
            raise Exception('Invalid version.')

        # validate that the framework compiler settings exist
        # if settings.arch not in config['architectures']:
        #     logging.error('Invalid architecture.')
        #     return False
        # if settings.framework not in config['architectures'][settings.arch]:
        #     logging.error('Framework missing')
        #     return False

        # validate the framework entries exist
        if settings.framework not in self.config['frameworks']:
            raise Exception('Framework missing')

        return True
