import random
import os
import sys
import json
import subprocess
from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import hex_key_generator, mbedTLS_hex_key_generator, SecretGenerator
import base64
import uuid

from config import get_toolchain_data, load_config
from run import run_subprocess

class bit_generator(SecretGenerator):
    # we pass asFile=True because our secrets are directly included as command line arguments (hex strings)
    def __init__(self, keylen):
        super().__init__(keylen, asFile=False)

    def __call__(self, *args, **kwargs) -> str:
        a = random.randint(0,10)
        self.str = '0' if a < 5 else '1'
        return self.str

    def getSecret(self) -> int:
        return int(self.str, 10)

'''
called for every element in algomap.json
'''
def analyze(lib, algname, keylen, extensions):
    global resultjson
    global initPath
    # clear previous results
    result = subprocess.run('rm -rf results', stderr=subprocess.PIPE, shell=True)
    checkretcode(result)
    result = subprocess.run('rm results.zip', stderr=subprocess.PIPE, shell=True)
    # checkretcode(result)
    try:
        os.mkdir('results', )
    except Exception as e:
        pass
    result = subprocess.run('zip -r results.zip results', stderr=subprocess.PIPE, shell=True)
    subprocess.run(f'mv results.zip {initPath}/results.zip', stderr=subprocess.PIPE, shell=True)

    fct = hex_key_generator(keylen)
    args = f'@ {algname}'.split()
    # for mbedtls the driver is more complex so go custom:
    if 'mbed' in lib:
        print(f'- Creating tmp files')
        result = subprocess.run('echo "AAAAAAAAAAAAAAA" > input', stderr=subprocess.PIPE, shell=True)
        checkretcode(result)
        fct = mbedTLS_hex_key_generator(keylen)
        result = subprocess.run('touch output', stderr=subprocess.PIPE, shell=True)
        checkretcode(result)
        args = f"0 input output {algname} SHA1 @".split()
    if 'compare' in lib:
        fct = bit_generator(1)

    rootfs = os.getcwd()
    
    binpath = rootfs + '/driver.bin'
    # can't get wolfssl to create shared objects on some archs, so hard code a fix here (track static object)
    if 'wolfssl' in lib or 'compare' in lib or 'hacl' in lib or 'util':
        sharedObjects = ['driver.bin']
    else:
        sharedObjects = [lib]
    print("Creating BinaryLoader")
    binLoader = BinaryLoader(
        path=binpath,
        args=args,
        rootfs=rootfs,
        rndGen=fct,
        sharedObjects=sharedObjects,
        x8664Extensions=extensions
    )
    print("Configuring BinaryLoader")

    errno = binLoader.configure()
    if errno:
        print("failed to configure BinaryLoader")
        resultjson.append({"algorithm":algname,"CF Leak Count":-1,"Memory Leak Count":-1})
        return 0
    
    lmodues = [DataLeakDetector(binaryLoader=binLoader, granularity=1), CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True)]
    if 'compare' in lib or 'hacl' in lib:
        lmodues = [CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True)]
    scd = SCDetector(modules=lmodues, getAssembly=True)
    scd.initTraceCount = 500
    scd.exec()
    # remove driver induced leaks
    try:
        if 'wolfssl' in lib or 'hacl' in lib or 'util' in lib:
            mask = scd.DF['Symbol Name'].str.contains('hextobin')
            scd.DF = scd.DF[~mask]
            # recreate reports:
            scd._generateReport()
    except Exception as e:
        print("no leaks")
    result = subprocess.run('find ./results/ -name "*.md" -type f -delete', stderr=subprocess.PIPE, shell=True)
    result = subprocess.run('find ./results/ -name "*.json" -type f -delete', stderr=subprocess.PIPE, shell=True)
    result = subprocess.run('find ./results/ -name "*.png" -type f -delete', stderr=subprocess.PIPE, shell=True)
    result = subprocess.run('zip -9 -r results.zip results', stderr=subprocess.PIPE, shell=True)
    result = subprocess.run('find ./results/ -name "*.html" -type f -delete', stderr=subprocess.PIPE, shell=True)
    subprocess.run(f'cp results.zip /build/results.zip', stderr=subprocess.PIPE, shell=True)
    
    with open("results.zip", "rb") as f:
        b64 = base64.b64encode(f.read())

    with open('/tmp/summary.json', 'r') as f:
        d = json.load(f)
    d['result'] = str(b64, encoding='utf8')
    d['algorithm'] = algname
    d['extensions'] = extensions[0]

    resultjson.append(d)

global ID

def build():
    global ID
    DOWNLOAD = True 
    finalres = {}
    toolchain_id = sys.argv[1]
    framework_id = sys.argv[2]
    framework_commit = sys.argv[3]
    optflag = sys.argv[4]
    u_compiler = sys.argv[5]
    finalres['toolchain'] = toolchain_id
    finalres['framework'] = framework_id
    finalres['commit'] = framework_commit
    finalres['optlvl'] = optflag
    finalres['compiler'] = u_compiler
    finalres['results'] = [{"CF Leak Count":-2, "Memory Leak Count":-2}]
    ID = f'{toolchain_id}*{framework_id}*{framework_commit}*{optflag}*{u_compiler}*{uuid.uuid4()}'
    # check if k8s shared volume is mounted
    if os.path.isdir('/mnt/vol'):
        with open(f'/mnt/vol/{ID}.json', 'w') as f:
            json.dump(finalres, f)
        print("saved data in case of failure")
    else:
        print("No mounted volume")
    # write to output file
    with open('/tmp/summary.json', 'w') as f:
        f.writelines(finalres)
    try:
        os.mkdir('results', )
    except Exception as e:
        pass
    result = subprocess.run('zip -r results.zip results', stderr=subprocess.PIPE, shell=True)
    subprocess.run('mv results.zip /build/results.zip', stderr=subprocess.PIPE, shell=True)

    cwd = os.getcwd()

    if u_compiler not in ['gcc', 'clang', 'icx']:
        print("Invalid compiler.")
        exit(0)

    with open('config.json', 'r') as f:
        config = json.load(f)

    framework_valid = False
    for framework in config['frameworks']:
        if framework_id in framework['name']:
            framework_valid = True 
            framework_url = framework['git']
            libname = framework['libname']
            includes = framework['includeDirs']
            ciphers = framework['available-ciphers']
            compiler = u_compiler
    
    if not framework_valid:
        print("Invalid framework name")
        exit(0)

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
                    try: 
                        extensions = options['x8664-extensions']
                    except KeyError:
                        extensions = ["DEFAULT"]
                    if u_compiler == 'gcc':
                        framework_config_cmd = options['buildcmd-gcc']
                        cflags = options['cflags-gcc'] + " " + optflag.strip('"')
                    elif u_compiler == 'clang':
                        framework_config_cmd = options['buildcmd-clang']
                        cflags = options['cflags-clang'] + " " + optflag.strip('"')
                    elif u_compiler == 'icx':
                        framework_config_cmd = options['buildcmd-icx']
                        cflags = options['cflags-clang'] + " " + optflag.strip('"')

    ICX_LIB_DIR = '/opt/intel/oneapi/compiler/2022.1.0/linux/compiler/lib/intel64_lin/'

    if not toolchain_valid or not framework_config_cmd:
        print("Invalid toolchain name")
        exit(0)

    # Download toolchain:
    print("- Downloading toolchain")
    if DOWNLOAD:
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

    if framework_id not in ['compare', 'haclutil', 'opensslutils']:
        if DOWNLOAD:
            print(f'- Cloning {framework_id}')
            result = subprocess.run(['git', 'clone', framework_url], stderr=subprocess.PIPE)
            checkretcode(result)

        os.environ["FRAMEWORK"] = os.getcwd() + '/' +framework_id
        print(f'- Set FRAMEWORK to {os.environ.get("FRAMEWORK")}')

        os.chdir(os.environ.get("FRAMEWORK"))

        print(f'- Checking out {framework_commit}')
        if DOWNLOAD:
            result = subprocess.run(['git', 'checkout', framework_commit], stderr=subprocess.PIPE)
            checkretcode(result)
    else:
        os.environ["FRAMEWORK"] = os.getcwd() + '/' + f'{framework_id}-builder'
        print(f'- Set FRAMEWORK to {os.environ.get("FRAMEWORK")}')
        os.chdir(os.environ.get("FRAMEWORK"))
    
    cflags = cflags.replace('$(pwd)', os.getcwd())
    os.environ["CFLAGS"] = cflags
    os.environ["SHARED"] = '1'
    if DOWNLOAD:
        if 'powerpc' in toolchain_id or framework_id in ['compare', 'haclutil', 'opensslutils']:
            print(f"- Updating LD_LIBRARY_PATH to {os.getcwd() + '/../toolchain/' + 'lib/'}")
            os.environ["LD_LIBRARY_PATH"] = os.getcwd() + '/../toolchain/' + 'lib/'
        subprocess.run('make clean', stderr=subprocess.PIPE, shell=True)
        for cmd in framework_config_cmd:
            print(f'- Configuring/Compiling {framework_id} with {cmd.split()}')
            result = subprocess.run(f'{". /opt/intel/oneapi/setvars.sh intel64 && " if compiler=="icx" else ""} {cmd}', stderr=subprocess.PIPE, shell=True)
            checkretcode(result)

    print(f'- Copying files to {rootfs}/{libdir}')

    if compiler == 'icx':
        result = subprocess.run(f'cp {ICX_LIB_DIR}* {os.getcwd()}/../toolchain/{rootfs}/{libdir}', stderr=subprocess.PIPE, shell=True)


    if 'wolf' in libname:
        result = subprocess.run(f'cp --backup=numbered $(find ./ -name "{libname}*.a") {os.getcwd()}/../toolchain/{rootfs}/{libdir}', stderr=subprocess.PIPE, shell=True)
        checkretcode(result)
    else:
        print(f"pwd = {os.getcwd()}")
        print(f"find ./ -name '{libname}*.so'")
        result = subprocess.run(f'cp $(find ./ -name "{libname}*.so") {os.getcwd()}/../toolchain/{rootfs}/{libdir}', stderr=subprocess.PIPE, shell=True)
        result = subprocess.run(f'cp $(find ./ -name "{libname}*.so.*") {os.getcwd()}/../toolchain/{rootfs}/{libdir}', stderr=subprocess.PIPE, shell=True)
    
    # emulation for ppc requires libs in a different dir
    if 'powerpc' in toolchain_id:
        result = subprocess.run(f'mkdir -p {os.getcwd()}/../toolchain/{rootfs}/{libdir}/tls/i686', stderr=subprocess.PIPE, shell=True)
        result = subprocess.run(f'cp {os.getcwd()}/../toolchain/{rootfs}/{libdir}/* {os.getcwd()}/../toolchain/{rootfs}/{libdir}/tls/i686/', stderr=subprocess.PIPE, shell=True)

    os.chdir(cwd)

    print(f'- Copying driver to {rootfs} (framework_id={framework_id})')
    if framework_id not in ['compare', 'haclutil', 'opensslutils']:
        result = subprocess.run(f'cp {framework_id}-builder/driver.c {os.getcwd()}/toolchain/{rootfs}/driver.c', stderr=subprocess.PIPE, shell=True)
        checkretcode(result)
    else:
        print(f"compare framework {os.getcwd()}")
        print(f'cp {framework_id}-builder/driver.bin {os.getcwd()}/toolchain/{rootfs}/driver.bin')
        result = subprocess.run(f'cp {framework_id}-builder/driver.bin {os.getcwd()}/toolchain/{rootfs}/driver.bin', stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
        checkretcode(result)

    os.chdir(cwd + '/toolchain')

    if framework_id not in ['compare', 'haclutil', 'opensslutils']:
        print(f'- Compiling driver')
        print(f'- Updating LD_LIBRARY_PATH to {os.getcwd() + "/" + "lib"}')
        os.environ["LD_LIBRARY_PATH"] = os.getcwd() + '/' + 'lib'
        includestr = ' '.join([f"-I{os.getcwd()}/../{framework_id}/{d}" for d in includes])
        canonicalLibName = libname[3:].split('.')[0]
        # check if we got a static .a object, for wolfssl shared object don't seem to get created on non x86 so we need to create them. Ugly hack
        flist = ""
        if 'wolf' in libname:
            import glob
            flist = glob.glob(f'{os.getcwd()}/{rootfs}/{libdir}/{libname.split(".")[0]}.a')
        if flist:
            static = True
            statObj = flist[0]
        else:
            static = False
            statObj = ""
        flist = " ".join(flist)
        print(f'CWD={os.getcwd()}')

        if compiler == 'gcc':
            if framework_id == 'botan':
                result = subprocess.run(f'{os.getcwd()}/{prefix}g++ {includestr} -l{canonicalLibName} {os.getcwd()}/{rootfs}/driver.c {flist} -lm -o {os.getcwd()}/{rootfs}/driver.bin', stderr=subprocess.PIPE, shell=True)
            else:
                result = subprocess.run(f'{os.getcwd()}/{prefix}gcc {includestr} -l{canonicalLibName} {os.getcwd()}/{rootfs}/driver.c {flist} -lm -o {os.getcwd()}/{rootfs}/driver.bin', stderr=subprocess.PIPE, shell=True)
        elif compiler == 'clang':
            if framework_id == 'botan':
                compiler = 'clang++'
            result = subprocess.run(f'{compiler} {includestr} -l{canonicalLibName} {os.getcwd()}/{rootfs}/driver.c {flist} {cflags} -o {os.getcwd()}/{rootfs}/driver.bin -fuse-ld=lld', stderr=subprocess.PIPE, shell=True)
        elif compiler == 'icx':
            result = subprocess.run(f'. /opt/intel/oneapi/setvars.sh intel64 && {compiler} {includestr} -l{canonicalLibName} {os.getcwd()}/{rootfs}/driver.c {flist} {cflags} -o {os.getcwd()}/{rootfs}/driver.bin -fuse-ld=lld', stderr=subprocess.PIPE, shell=True)

        print(f'CWD={os.getcwd()}')
        print(f'{compiler} {includestr} -l{canonicalLibName} {os.getcwd()}/{rootfs}/driver.c {flist} {cflags} -o {os.getcwd()}/{rootfs}/driver.bin')
        checkretcode(result)

    # parse algomap file
    with open('../algomap.json', 'r') as f:
        algomap = json.load(f)

    os.chdir(cwd + f'/toolchain/{rootfs}')

    for el in algomap:
        if el['algo'] in ciphers:
            if 'aes' in el['algo']:
                for e in extensions:
                    analyze(libname.split('.')[0], el['algo'], int(el['keylen']), [e])
            else:
                analyze(libname.split('.')[0], el['algo'], int(el['keylen']), ['DEFAULT'])

    global resultjson
    finalres = {}
    finalres['toolchain'] = toolchain_id
    finalres['framework'] = framework_id
    finalres['commit'] = framework_commit
    finalres['optlvl'] = optflag
    finalres['compiler'] = compiler
    finalres['results'] = resultjson

    print(finalres)

    # check if k8s shared volume is mounted
    if os.path.isdir('/mnt/vol'):
        with open(f'/mnt/vol/{ID}.json', 'w') as f:
            json.dump(finalres, f)
        print("saved data")
    else:
        print("No mounted volume")

def main():
    global initPath
    initPath = os.getcwd()
    build()
    print("- Zipping results " + os.getcwd())
    result = subprocess.run(f'zip -r results.zip results', stderr=subprocess.PIPE, shell=True)
    checkretcode(result)
    result = subprocess.run(f'mv results.zip {initPath}/results.zip', stderr=subprocess.PIPE, shell=True)
    checkretcode(result)

if __name__ == "__main__":
    main()
