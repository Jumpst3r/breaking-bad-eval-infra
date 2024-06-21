#!/usr/bin/env python

import logging
import argparse
import sqlite3
import contextlib
from src.config import *
from src.frameworks import *
from src.frameworks.util import *
from src.toolchain import *
from src.process import *

example_usage = """example usage:

    python run.py -a riscv64 -t gcc --toolchain-version 11.3.0 -f haclstar -c main -o="-O3" hmac-sha2
    python run.py -a x86-64 -t llvm --toolchain-version 15 -f haclstar -c main -o="-O0" hmac-sha2

Running in a different directory:
    python ../run.py -a riscv64 -t gcc --toolchain-version 11.3.0 -f libsodium -c stable -o="-O2" --fw-dir ../src/frameworks -p ../config.json hmac-sha2
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
                    choices=['haclstar', 'openssl', 'mbedtls', 'wolfssl', 'botan', 'bearssl', 'libsodium', 'boringssl'])
parser.add_argument('-c', '--commit', type=str,
                    help='Commit of the framework', default='main', required=True)
parser.add_argument('target', nargs='+', type=str, help='Target algorithm(s) to be analyzed',
                    default='aes-cbc')

parser.add_argument('-o', '--opt', '--optimization', type=str,
                    help='Optimization (default: -O2)', default='-O2')
parser.add_argument('-p', '--path', type=str,
                    help='path to config', default='../config.json')
parser.add_argument('--result-dir', type=str,
                    help='Result directory', default='./results')
parser.add_argument('--fw-dir', type=str,
                    help="Directory to frameworks directory", default='src/frameworks')
parser.add_argument('--save-binaries', action=argparse.BooleanOptionalAction, default=True)

args = parser.parse_args()


def build_framework(config: Config, settings: Settings, rootfs='rootfs', fwDir='src/frameworks'):
    # logger = logging.getLogger()
    # logger.setLevel(logging.INFO)
    logging.root.setLevel(logging.INFO)

    if settings.framework == "openssl":
        f = Openssl(settings, config, rootfs, fwDir)

    if settings.framework == 'mbedtls':
        f = Mbedtls(settings, config, rootfs, fwDir)

    if settings.framework == 'wolfssl':
        f = Wolfssl(settings, config, rootfs, fwDir)

    if settings.framework == 'botan':
        f = Botan(settings, config, rootfs, fwDir)

    if settings.framework == 'haclstar':
        f = Haclstar(settings, config, rootfs, fwDir)

    if settings.framework == 'bearssl':
        f = Bearssl(settings, config, rootfs, fwDir)

    if settings.framework == 'libsodium':
        f = Libsodium(settings, config, rootfs, fwDir)

    if settings.framework == 'boringssl':
        f = Boringssl(settings, config, rootfs, fwDir)

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
f = build_framework(config, settings, fwDir=args.fw_dir)

target = args.target if len(args.target) > 1 else args.target[0].split(' ')

if len(target) == 0:
    exit()
results = []

resultDir = args.result_dir
resultDir += f'/{settings.framework}-{settings.arch}-{settings.compiler}'
if settings.compiler == 'gcc':
    resultDir += f'-{settings.gcc_ver}'
else:
    resultDir += f'-{settings.llvm_ver}'

quote = '"'
resultDir += f'-{settings.optflag.replace(" ", "_").replace(quote, "")}'

for t in target:
    try:
        scd = f.run(algo_from_str(t), resultDir=resultDir)

        res = {
            'arch': settings.arch,
            'toolchain': settings.compiler,
            'toolchain-version': args.toolchain_version,
            'framework': args.framework,
            'commit': args.commit,
            'optflag': args.opt,
            'foldername': resultDir,
            'tracecount': scd.initTraceCount,
            'algo': t
        }

        if 'DF' in dir(scd):
            # Leaks were found
            res['leaks'] = len(scd.DF)
            res['details'] = scd.DF.to_dict('records')

        else:
            res['leaks'] = 0
            res['details'] = []

        results.append(res)
    except Exception as e:
        print(str(e))

# dump the content into a json file
with open(f'{resultDir}/data.json', 'w') as f:
    f.write(json.dumps(results))

if args.save_binaries:
    run_subprocess(f'zip -r {resultDir}/rootfs.zip rootfs')

try:
    with contextlib.closing(sqlite3.connect(f'{args.result_dir}/database.db')) as con:
        cur = con.cursor()

        cur.execute("""CREATE TABLE IF NOT EXISTS data (
            ID INTEGER PRIMARY KEY AUTOINCREMENT, 
            arch VARCHAR(20), 
            toolchain VARCHAR(20), 
            toolchain_version VARCHAR(20), 
            framework VARCHAR(256), 
            algo VARCHAR(256),
            fw_commit VARCHAR(256), 
            optflag VARCHAR(256), 
            foldername VARCHAR(256), 
            tracecount INTEGER, 
            leaks INTEGER
        );""")
        for r in results:
            cur.execute("INSERT INTO data (arch, toolchain, toolchain_version, framework, algo, fw_commit, optflag, foldername, tracecount, leaks) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                r['arch'],
                r['toolchain'],
                r['toolchain-version'],
                r['framework'],
                r['algo'],
                r['commit'],
                r['optflag'],
                r['foldername'],
                r['tracecount'],
                r['leaks']
            ))

            con.commit()

except Exception as e:
        print(str(e))