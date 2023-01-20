import logging
import argparse
import sqlite3
import contextlib
from src.config import *
from src.frameworks import *
from src.frameworks.util import *
from src.toolchain import *

example_usage = """example usage:

    python run.py -a riscv64 -t gcc --toolchain-version 11.3.0 -f haclstar -c main -o="-O3" hmac-sha2
    python run.py -a x86-64 -t llvm --toolchain-version 15 -f haclstar -c main -o="-O0" hmac-sha2
"""

parser = argparse.ArgumentParser(
    epilog=example_usage, formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument('-a', '--arch', type=str, help='Architecture', default='x86-64',
                    choices=['riscv64', 'x86-64', 'x86-i686', 'aarch64', 'armv7', 'mips32el'])
parser.add_argument('-t', '--toolchain', type=str, default='gcc',
                    help='Toolchain', choices=['gcc', 'llvm'])
parser.add_argument('--toolchain-version', type=str,
                    help='Toolchain Version', required=True)
parser.add_argument('-f', '--framework', type=str, help='Framework', required=True,
                    choices=['haclstar', 'openssl', 'mbedtls', 'wolfssl', 'botan'])
parser.add_argument('-c', '--commit', type=str,
                    help='Commit of the framework', default='main', required=True)
parser.add_argument('target', type=str, help='Target algorithm to be analyzed',
                    default='aes-cbc', choices=[
                        'aes-cbc', 'aes-ctr', 'aes-gcm', 'camellia-cbc', 'aria-cbc',
                        'des-cbc', 'chacha-poly1305', 'hmac-sha1', 'hmac-sha2', 'hmac-sha3',
                        'hmac-blake2', 'ecdh-curve25519', 'ecdh-p256', 'ecdsa'
                    ])

parser.add_argument('-o', '--opt', '--optimization', type=str,
                    help='Optimization (default: -O2)', default='-O2')
parser.add_argument('-p', '--path', type=str,
                    help='path to config', default='../config.json')

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
    return f


logging.basicConfig(level=logging.DEBUG)
settings = Settings(
    arch=args.arch, compiler=args.toolchain, version=args.toolchain_version,
    framework=args.framework, commit=args.commit, optflag=args.opt
)
print(settings)
config = Config(settings, args.path)
toolchain(config, settings)
f = build_framework(config, settings)
scd = f.run(algo_from_str(args.target))

results = {
    'arch': settings.arch,
    'toolchain': settings.compiler,
    'toolchain-version': args.toolchain_version,
    'framework': args.framework,
    'commit': args.commit,
    'optflag': args.opt,
    'foldername': scd.loader.resultDir.split('/')[1],
    'tracecount': scd.initTraceCount
}

if 'DF' in dir(scd):
    # Leaks were found
    results['leaks'] = len(scd.DF)
    results['details'] = scd.DF.to_dict('records')

else:
    results['leaks'] = 0
    results['details'] = []

# dump the content into a json file
with open(f'results/{results["foldername"]}/data.json', 'w') as f:
    f.write(json.dumps(results))


with contextlib.closing(sqlite3.connect('results/database.db')) as con:
    cur = con.cursor()

    cur.execute("""CREATE TABLE IF NOT EXISTS data (
        ID INTEGER PRIMARY KEY AUTOINCREMENT, 
        arch VARCHAR(20), 
        toolchain VARCHAR(20), 
        toolchain_version VARCHAR(20), 
        framework VARCHAR(256), 
        fw_commit VARCHAR(256), 
        optflag VARCHAR(256), 
        foldername VARCHAR(256), 
        tracecount INTEGER, 
        leaks INTEGER
    );""")

    cur.execute("INSERT INTO data (arch, toolchain, toolchain_version, framework, fw_commit, optflag, foldername, tracecount, leaks) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", (
        results['arch'],
        results['toolchain'],
        results['toolchain-version'],
        results['framework'],
        results['commit'],
        results['optflag'],
        results['foldername'],
        results['tracecount'],
        results['leaks']
    ))

    con.commit()