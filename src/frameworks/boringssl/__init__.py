from ..util import *
import os
from src.process import run_subprocess, run_subprocess_env
from src.config import Settings, Config
# from cryptography.hazmat.primitives.asymmetric import ec
import logging
from .keygen import SECP256PrivateKeyGeneratorBoringSSL, ECDHP256PrivateKeyGeneratorBoringSSL

logging.getLogger().setLevel(logging.DEBUG)

arch_str = {
    'riscv64': 'riscv64',
    'x86-64': 'x86_64',
    'x86-i686': 'i686',
    'aarch64': 'aarch64',
    'armv7': 'arm',
    'mips32el': 'mips'
}


class Boringssl(Framework):
    def __init__(self, settings: Settings, config: Config, rootfs: str, fwDir: str):
        self.name = 'boringssl'
        self.url = 'https://boringssl.googlesource.com/boringssl'
        super().__init__(settings, config, rootfs, fwDir)

    def download(self):
        if not os.path.isdir(self.name):
            git_clone(self.url, self.settings.commit, self.name)
        else:
            git_reset(self.settings.commit, self.name)

    def gcc_toolchain_cmake(self, toolchain_dir, extra_cflags):
        prefix = f'{toolchain_dir}/bin/{self.config.get_toolchain_name(self.settings)}'
        cc = f'{prefix}-gcc'
        cxx = f'{prefix}-g++'
        ld = f'{prefix}-ld'
        ar = f'{prefix}-ar'
        extra_cflags_format = extra_cflags.replace(" ", "\"\n\t\"")
        return f"""
set(CMAKE_SYSTEM_PROCESSOR "{arch_str[self.settings.arch]}")

# the name of the target operating system
set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# which compilers to use for C and C++
set(CMAKE_C_COMPILER   {cc})
set(CMAKE_CXX_COMPILER {cxx})
set(CMAKE_AR {ar})
set(CMAKE_LINKER {ld})

# set OPTFLAG
set(CMAKE_CXX_FLAGS "{self.settings.optflag}")
set(CMAKE_C_FLAGS "{self.settings.optflag}")
set(CMAKE_ASM_FLAGS "{self.settings.optflag}")

add_compile_options("{extra_cflags_format}")
"""

    def llvm_toolchain_cmake(self, toolchain_dir, extra_cflags, extra_ldflags):
        triple = self.config.get_toolchain_name(self.settings)
        cc = f'clang'
        cxx = f'clang++'
        ld = f'ld.lld'
        ar = f'llvm-ar'

        extra_cflags_format = extra_cflags.replace(" ", "\"\n\t\"")
        extra_ldflags_format = extra_ldflags.replace(" ", "\"\n\t\"")

        return f"""
# the name of the target operating system
set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_SYSTEM_PROCESSOR "{arch_str[self.settings.arch]}")

# which compilers to use for C and C++
set(CMAKE_C_COMPILER   {cc})
set(CMAKE_CXX_COMPILER {cxx})
set(CMAKE_AR {ar})
set(CMAKE_LINKER {ld})

# llvm specific settings
set(toolchain {toolchain_dir})
set(triple {triple})
set(gcc_ver {self.settings.gcc_ver})
set(CMAKE_SYSROOT ${{toolchain}}/${{triple}}/sysroot)
set(CLANG_TARGET_TRIPLE ${{triple}})
set(CMAKE_C_COMPILER_TARGET ${{CLANG_TARGET_TRIPLE}})
set(CMAKE_CXX_COMPILER_TARGET ${{CLANG_TARGET_TRIPLE}})
set(CMAKE_ASM_COMPILER_TARGET ${{CLANG_TARGET_TRIPLE}})

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH  ${{CMAKE_SYSROOT}})

# add custom flags
add_compile_options(
    "-B${{toolchain}}/lib/gcc/${{triple}}/${{gcc_ver}}"
    "-I${{toolchain}}/${{triple}}/include/"
    "-I${{toolchain}}/${{triple}}/include/c++/${{gcc_ver}}/"
    "-I${{toolchain}}/${{triple}}/include/c++/${{gcc_ver}}/${{triple}}"
    "{extra_cflags_format}"
)
add_link_options(
    "-L${{toolchain}}/lib/gcc/${{triple}}/${{gcc_ver}}"
    "-B${{toolchain}}/lib/gcc/${{triple}}/${{gcc_ver}}"
    "-fuse-ld=lld"
    "{extra_ldflags_format}"
)

# set OPTFLAG
set(CMAKE_CXX_FLAGS "{self.settings.optflag}")
set(CMAKE_C_FLAGS "{self.settings.optflag}")
set(CMAKE_ASM_FLAGS "{self.settings.optflag}")
"""

    def build_lib(self):
        cwd = os.getcwd()

        os.chdir(f"{self.name}/")

        os.mkdir("build")
        os.chdir("build")

        logging.info(
            f'Generating toolchain.cmake for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4 -Wno-error"
        ldflags = ""
        if self.settings.arch == 'x86-i686':
            cflags += " -m32 -march=i386"
        if self.settings.arch == 'aarch64':
            # cflags += " --specs=nosys.specs"
            cflags += " -march=armv8-a"
        if self.settings.arch == 'armv7':
            # cflags += " --specs=nosys.specs"
            cflags += " -march=armv7-a"
            cflags += ' -mfloat-abi=hard'
        if self.settings.arch == 'mips32el':
            ldflags += '-Wl,-z,notext'
        if self.settings.arch == 'riscv64' and self.settings.llvm_ver not in ['14', '15', '16']:
            cflags += f' -mno-relax'
        # if self.settings.compiler == 'llvm':
            # cflags += self.llvm_cflags(f'{cwd}/toolchain')

        with open('toolchain.cmake', 'w') as file:
            if self.settings.compiler == 'gcc':
                file.write(self.gcc_toolchain_cmake(
                    f'{cwd}/toolchain', cflags))
            elif self.settings.compiler == 'llvm':
                file.write(self.llvm_toolchain_cmake(
                    f'{cwd}/toolchain', cflags, ldflags))

        logging.info('Created custom toolchain config for cmake')

        logging.info(
            'Forcing fvisbility=default in CMakeLists.txt of boringSSL')
        with open("../CMakeLists.txt", "r") as fin:
            data = fin.read()
        data = data.replace('-fvisibility=hidden', '-fvisibility=default')
        with open("../CMakeLists.txt", "w") as fout:
            fout.write(data)

        run_subprocess(
            'cmake -DCMAKE_TOOLCHAIN_FILE=toolchain.cmake -DBORINGSSL_UNSAFE_DETERMINISTIC_MODE=1 -DBUILD_SHARED_LIBS=1 -DCMAKE_BUILD_TYPE=None ..')

        logging.info(f'Building {self.name} (make)')
        run_subprocess_env('make -j6')

        os.chdir(cwd)

    def copy_lib_rootfs(self):
        logging.info(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

        logging.info(f"pwd = {os.getcwd()}")
        run_subprocess(
            f'cp {cwd}/{self.name}/build/crypto/libcrypto.so* {os.getcwd()}/{self.rootfs}/{self.libdir}')

    def build(self):
        self.build_lib()
        self.copy_lib_rootfs()

        logging.info(f'- Building driver.c')

        cwd = os.getcwd()

        includestr = f'-I{self.name}/include'
        includestr += f' -I{self.name}/crypto'
        librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lcrypto'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_ldflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {librarystr} {cflags} {self.fwDir}/{self.name}/driver.c -lm -o {self.rootfs}/driver.bin')

    def supported_ciphers(self) -> list[Algo]:
        return [
            Algo.AES_CBC,
            Algo.AES_CTR,
            Algo.AES_GCM,
            Algo.CHACHA_POLY1305,
            Algo.HMAC_SHA1,
            Algo.HMAC_SHA2,
            Algo.HMAC_BLAKE2,
            Algo.ECDH_P256,
            Algo.CURVE25519,
            Algo.ECDSA
        ]

    def secretgen(self, algo: Algo) -> SecretGenerator:
        if algo == Algo.ECDSA:
            return SECP256PrivateKeyGeneratorBoringSSL(0)
        elif algo == Algo.ECDH_P256:
            return ECDHP256PrivateKeyGeneratorBoringSSL(0, 'p256')
        elif algo == Algo.CURVE25519:
            return ECDHP256PrivateKeyGeneratorBoringSSL(0, 'x25519')
        else:
            return hex_key_generator_fixed(256, seed=1)

    def gen_args(self, algo: Algo) -> list[str]:
        if algo not in self.supported_ciphers():
            raise "Unsupported algorithm"

        algo_str = {
            Algo.AES_CBC: 'aes-cbc',
            Algo.AES_CTR: 'aes-ctr',
            Algo.AES_GCM: 'aes-gcm',
            Algo.CHACHA_POLY1305: 'chacha_poly1305',
            Algo.HMAC_SHA1: 'hmac-sha1',
            Algo.HMAC_SHA2: 'hmac-sha256',
            Algo.HMAC_BLAKE2: 'hmac-blake2',
            Algo.ECDH_P256: 'ecdh-p256',
            Algo.CURVE25519: 'x25519',
            Algo.ECDSA: 'ecdsa'
        }

        return f'@ {algo_str[algo]}'.split()

    def shared_objects(self) -> list[str]:
        return ['libcrypto']

    def clean_report(self, scd):
        # mask = scd.DF['Symbol Name'].str.contains('hextobin')
        # scd.DF = scd.DF[~mask]
        # # recreate reports:
        # scd._generateReport()
        return scd
