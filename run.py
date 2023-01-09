import logging
import argparse
from config import *
from frameworks import *
from frameworks.util import *
from setup import *

example_usage = """example usage:

    python run.py -a riscv64 -t gcc -v 11.3.0 -f haclstar -c main -o="-O3"
    python run.py -a x86-64 -t llvm -v 15.0 -f haclstar -c main -o="-O0"
"""

parser = argparse.ArgumentParser(
    epilog=example_usage, formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument('-a', '--arch', type=str, help='Architecture', required=True,
                    choices=['riscv64', 'x86-64', 'x86-i686', 'aarch64', 'armv7', 'mips32el'])
parser.add_argument('-t', '--toolchain', type=str, required=True,
                    help='Compiler', choices=['gcc', 'llvm'])
parser.add_argument('-v', '--version', type=str,
                    help='Compiler Version', required=True)
parser.add_argument('-f', '--framework', type=str, help='Framework', required=True,
                    choices=['haclstar', 'openssl', 'mbedtls', 'wolfssl', 'botan'])
parser.add_argument('-c', '--commit', type=str,
                    help='Commit of the framework', default='main', required=True)

parser.add_argument('-o', '--opt', '--optimization', type=str,
                    help='Optimization (default: -O2)', default='-O2')
parser.add_argument('-p', '--path', type=str,
                    help='config file', default='../config_new.json')

args = parser.parse_args()


def build_framework(config: Config, settings: Settings, rootfs='rootfs'):
    # logger = logging.getLogger()
    # logger.setLevel(logging.INFO)
    logging.root.setLevel(logging.INFO)

    if settings.framework == "openssl":
        f = Openssl(settings, config, rootfs)

    if settings.framework == 'mbedtls':
        f = Mbedtls(settings, config, rootfs)

    if settings.framework == 'wolfssl':
        f = Wolfssl(settings, config, rootfs)

    if settings.framework == 'botan':
        f = Botan(settings, config, rootfs)

    if settings.framework == 'haclstar':
        f = Haclstar(settings, config, rootfs)

    f.download()
    f.build()
    scd = f.run(Algo.AES_GCM)


logging.basicConfig(level=logging.DEBUG)
settings = Settings(
    arch=args.arch, compiler=args.toolchain, version=args.version,
    framework=args.framework, commit=args.commit, optflag=args.opt
)
config = Config(settings, args.path)
toolchain(config, settings)
build_framework(config, settings)
