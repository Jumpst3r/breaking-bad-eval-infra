"""
file @builder.py

@author nicolas

builder.py <toolchain> <framework> <commit> <optlvl> <alg> <keylen>

"""


import multiprocessing
import os
import sys
import json
import subprocess
from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import hex_key_generator


def checkretcode(result):
    err = result.stderr
    if result.returncode != 0:
        print(f"failed: {err}")
        exit(1)

def analyze(lib):
    rootfs = os.getcwd()
    algname = sys.argv[5]
    keylen = int(sys.argv[6])
    binpath = rootfs + '/driver.bin'
    args = f'@ {algname}'.split()
    sharedObjects = [lib]
    binLoader = BinaryLoader(
        path=binpath,
        args=args,
        rootfs=rootfs,
        rndGen=hex_key_generator(keylen),
        sharedObjects=sharedObjects,
    )
    scd = SCDetector(modules=[
        # Secret dependent memory read detection
        DataLeakDetector(binaryLoader=binLoader),
        # Secret dependent control flow detection
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True)
    ])
    scd.exec()

def build():
    cwd = os.getcwd()
    toolchain_id = sys.argv[1]
    framework_id = sys.argv[2]
    framework_commit = sys.argv[3]
    optflag = sys.argv[4]

    with open('config.json', 'r') as f:
        config = json.load(f)

    framework_valid = False
    for framework in config['frameworks']:
        if framework_id in framework['name']:
            framework_valid = True 
            framework_url = framework['git']
            libname = framework['libname']
            includes = framework['includeDirs']
            compiler = framework['compiler']
    
    if not framework_valid:
        print("Invalid framework name")
        exit(1)

    toolchain_valid = False
    # validate if toolchain is valid:
    framework_config_cmd = None
    for tc in config['toolchains']:
        if toolchain_id in tc.keys():
            toolchain_valid = True
            toolchain_url = tc[toolchain_id]['url']
            libdir = tc[toolchain_id]['libdir']
            prefix = tc[toolchain_id]['prefix']

            rootfs =  tc[toolchain_id]['rootfs']
            for options in tc[toolchain_id]['compileOptions']:
                if options['name'] == framework_id:
                    framework_config_cmd = options['buildcmd']
                    cflags = options['cflags'] + f" {optflag}"

    
    if not toolchain_valid or not framework_config_cmd:
        print("Invalid toolchain name")
        exit(1)

    # Download toolchain:
    print("- Downloading toolchain")
    
    result = subprocess.run(['wget', '-O', 'toolchain.tar.bz2', toolchain_url], stderr=subprocess.PIPE)
    checkretcode(result)

    print('- Extracting')
    
    result = subprocess.run(['mkdir', '-p', 'toolchain'], stderr=subprocess.PIPE)
    checkretcode(result)
    
    result = subprocess.run(['tar', '-xf', 'toolchain.tar.bz2', '-C', 'toolchain', '--strip-components', '1'], stderr=subprocess.PIPE)
    checkretcode(result)
    
    os.environ["TOOLCHAIN_ROOT"] = os.getcwd() + '/toolchain'
    print(f'- Set TOOLCHAIN_ROOT to {os.environ.get("TOOLCHAIN_ROOT")}')

    os.environ["ROOTFS"] = os.getcwd() + '/toolchain/' + rootfs
    print(f'- Set ROOTFS to {os.environ.get("ROOTFS")}')

    print(f'- Cloning {framework_id}')
    result = subprocess.run(['git', 'clone', framework_url], stderr=subprocess.PIPE)
    checkretcode(result)

    os.environ["FRAMEWORK"] = os.getcwd() + '/' +framework_id
    print(f'- Set FRAMEWORK to {os.environ.get("FRAMEWORK")}')

    os.chdir(os.environ.get("FRAMEWORK"))

    print(f'- Checking out {framework_commit}')
    result = subprocess.run(['git', 'checkout', framework_commit], stderr=subprocess.PIPE)
    checkretcode(result)

    os.environ["CFLAGS"] = cflags
    print(f'- Configuring {framework_id} with {framework_config_cmd.split()}')
    result = subprocess.run(framework_config_cmd, stderr=subprocess.PIPE, shell=True)
    checkretcode(result)

    nbcores = multiprocessing.cpu_count()

    print(f'- Compiling')
    result = subprocess.run(['make', f'-j{nbcores}'], stderr=subprocess.PIPE)
    checkretcode(result)

    print(f'- Copying files to {rootfs}/{libdir}')
    result = subprocess.run(f'cp {libname}* {os.getcwd()}/../toolchain/{rootfs}/{libdir}', stderr=subprocess.PIPE, shell=True)
    checkretcode(result)

    os.chdir(cwd)

    print(f'- Copying driver to {rootfs}')
    result = subprocess.run(f'cp {framework_id}-builder/driver.c {os.getcwd()}/toolchain/{rootfs}/driver.c', stderr=subprocess.PIPE, shell=True)
    checkretcode(result)

    os.chdir(cwd + '/toolchain')

    print(f'- Compiling driver')
    print(f'- Updating LD_LIBRARY_PATH to {os.getcwd() + "/" + "lib"}')
    os.environ["LD_LIBRARY_PATH"] = os.getcwd() + '/' + 'lib'
    includestr = ' '.join([f"-I{os.getcwd()}/../{framework_id}/{d}" for d in includes])
    canonicalLibName = libname[3:].split('.')[0]
    result = subprocess.run(f'{os.getcwd()}/{prefix}{compiler} {includestr} -l{canonicalLibName} {os.getcwd()}/{rootfs}/driver.c -o {os.getcwd()}/{rootfs}/driver.bin', stderr=subprocess.PIPE, shell=True)
    print(f'CWD={os.getcwd()}')
    print(f'{os.getcwd()}/{prefix}{compiler} {includestr} -l{canonicalLibName} {os.getcwd()}/{rootfs}/driver.c {cflags} -o {os.getcwd()}/{rootfs}/driver.bin')
    checkretcode(result)
    os.chdir(cwd + f'/toolchain/{rootfs}')
    analyze(libname.split('.')[0])

    

def main():
    build()
    print("- Zipping results " + os.getcwd())
    result = subprocess.run(f'zip -r results.zip results', stderr=subprocess.PIPE, shell=True)
    checkretcode(result)
    result = subprocess.run(f'mv results.zip /build/results.zip', stderr=subprocess.PIPE, shell=True)
    checkretcode(result)

if __name__ == "__main__":
    main()