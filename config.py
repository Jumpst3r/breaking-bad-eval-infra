import json
from json import tool
from typing import Dict
import logging

from dataclasses import dataclass
from xmlrpc.client import Boolean

try:
    with open('../config_new.json', 'r') as f:
        config = json.load(f)
except:
    with open('./config_new.json', 'r') as f:
        config = json.load(f)
# except:
#     exit(0)

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


# def load_config() -> Dict:
#     with open('../config_new.json', 'r') as f:
#         config = json.load(f)
#     return config


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


def get_toolchain_data(settings: Settings) -> Dict:
    """Get toolchain data

    Args:
        settings (Settings): 


    Returns:
        Dict: Toolchain data
    """
    data = {}
    data['gcc'] = config['gcc'][settings.arch]
    data['llvm'] = config['llvm']
    toolchain_name = data['gcc']['toolchain']
    return replace_placholders(toolchain_name, settings.gcc_ver, settings.llvm_ver, data)


def get_framework_data(settings: Settings) -> Dict:
    """Get framework data

    Args:
        settings (Settings): 

    Returns:
        Dict: framework data
    """

    data = config['frameworks'][settings.framework]
    return data


def get_framework_config(settings: Settings) -> Dict:
    """Get framework config

    Args:
        settings (Settings): 

    Returns:
        Dict: Framework config
    """
    toolchain_name = config[settings.compiler][settings.arch]["toolchain"]
    data = config['architectures'][settings.arch][settings.framework]
    return replace_placholders(toolchain_name, settings.gcc_ver, settings.llvm_ver, data)

def get_prefix(settings: Settings) -> str:
    return get_toolchain_data(settings)['gcc']['prefix']

def get_toolchain_name(settings: Settings) -> str:
    return get_toolchain_data(settings)['gcc']['toolchain']

def validate_settings(settings: Settings) -> Boolean:
    # Validate compiler
    if settings.compiler not in ['gcc', 'llvm']:
        logging.error('Invalid compiler.')
        return False

    # validate that we have a gcc toolchain with the correct architecture
    if settings.arch not in config['gcc']:
        logging.error('Invalid architecture.')
        return False

    # validate that the compiler version exists
    if settings.gcc_ver not in config['gcc'][settings.arch]['versions']:
        logging.error('Invalid version.')
        return False

    if settings.llvm_ver not in config['llvm']['versions']:
        logging.error('Invalid version.')
        return False

    # validate that the framework compiler settings exist
    # if settings.arch not in config['architectures']:
    #     logging.error('Invalid architecture.')
    #     return False
    # if settings.framework not in config['architectures'][settings.arch]:
    #     logging.error('Framework missing')
    #     return False

    # validate the framework entries exist
    if settings.framework not in config['frameworks']:
        logging.error('Framework missing')
        return False

    return True
