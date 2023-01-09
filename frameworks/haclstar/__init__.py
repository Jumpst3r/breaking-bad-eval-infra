from ..util import git_clone, git_reset, Algo, Framework
import os
from process import run_subprocess, run_subprocess_env
from config import Settings, Config
import logging


logging.getLogger().setLevel(logging.DEBUG)

arch_str_target = {
    'x86-64': 'x86_64-unknown-linux-elf',
    'aarch64': 'aarch64-unknown-linux-elf',
    'armv4': 'arm-unknown-linux-elf',
    'armv7': 'arm-unknown-linux-elf',
    'riscv64': 'riscv64-unknown-linux-elf',
    'mips32el': 'mipsel-unknown-linux-elf',
    'x86-i686': 'i386-unknown-linux-elf'
}

march = {
    'x86-64': '',
    'x86-i686': 'ia32',
    'aarch64': 'aarch64',
    'armv4': 'arm',  # not sure
    'armv7': 'arm',  # not sure
    'riscv64': 'riscv64',
    'mips32el': 'mipsel',  # not sure
}


class Haclstar(Framework):
    def __init__(self, settings: Settings, config: Config, rootfs: str):
        self.name = 'hacl-star'
        self.url = 'https://github.com/hacl-star/hacl-star.git'
        self.settings = settings
        self.prefix = config.get_prefix(settings)
        self.rootfs = rootfs
        self.libdir = '/lib' if 'armv7' in settings.arch or 'mips32el' in settings.arch else '/lib64'
        self.config = config

        if not os.path.isdir(self.rootfs):
            os.mkdir(self.rootfs)
        # if not os.path.isdir(f'{self.rootfs}{self.libdir}'):
        #     os.mkdir(f'{self.rootfs}{self.libdir}')

    def download(self):
        if not os.path.isdir(self.name):
            git_clone(self.url, self.settings.commit, self.name)
        else:
            git_reset(self.settings.commit, self.name)

    def llvm_cflags(self, toolchain_dir):
        cflags = f' --target={arch_str_target[self.settings.arch]}'
        cflags += f' --gcc-toolchain={toolchain_dir}/'
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/c++/{self.settings.gcc_ver}/'
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/c++/{self.settings.gcc_ver}/{self.config.get_toolchain_name(self.settings)}/'
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/'
        cflags += f' --sysroot={toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/sysroot/'
        cflags += f' -B{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += f' -Wno-error'
        return cflags

    def llvm_ldflags(self, toolchain_dir):
        ldflags = " -fuse-ld=lld"
        ldflags += f' -L{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        return ldflags

    def gen_config(self):
        # Disable BZERO, disable all 128/256bit vector operations
        # TODO: Enable 128/256 for architectures that support it
        return """#define Lib_IntVector_Intrinsics_vec128 void *
#define Lib_IntVector_Intrinsics_vec256 void *
#define HACL_CAN_COMPILE_UINT128 1
#define LINUX_NO_EXPLICIT_BZERO
"""

    def gen_makefile_config(self, cflags, ldflags, toolchain_dir):
        result = ""
        result += f"CFLAGS += {cflags}\n"
        result += f"LDFLAGS += {ldflags}\n"
        result += f"UNAME = Linux\n"
        result += f"MARCH = {march[self.settings.arch]}\n"
        result += f"BLACKLIST += Hacl_Curve25519_64.c Hacl_HPKE_Curve64_CP128_SHA256.c Hacl_HPKE_Curve64_CP128_SHA512.c Hacl_HPKE_Curve64_CP256_SHA256.c Hacl_HPKE_Curve64_CP256_SHA512.c Hacl_HPKE_Curve64_CP32_SHA256.c Hacl_HPKE_Curve64_CP32_SHA512.c\n"
        result += f"BLACKLIST += evercrypt_vale_stubs.c\n"
        result += f"BLACKLIST += Hacl_Chacha20Poly1305_128.c Hacl_Chacha20_Vec128.c Hacl_HKDF_Blake2s_128.c Hacl_HMAC_Blake2s_128.c Hacl_HPKE_Curve51_CP128_SHA256.c Hacl_HPKE_Curve51_CP128_SHA512.c Hacl_HPKE_Curve64_CP128_SHA256.c Hacl_HPKE_Curve64_CP128_SHA512.c Hacl_HPKE_P256_CP128_SHA256.c Hacl_Hash_Blake2s_128.c Hacl_Poly1305_128.c Hacl_SHA2_Vec128.c Hacl_Streaming_Blake2s_128.c Hacl_Streaming_Poly1305_128.c\n"
        result += f"BLACKLIST += Hacl_Chacha20Poly1305_256.c Hacl_Chacha20_Vec256.c Hacl_HKDF_Blake2b_256.c Hacl_HMAC_Blake2b_256.c Hacl_HPKE_Curve51_CP256_SHA256.c Hacl_HPKE_Curve51_CP256_SHA512.c Hacl_HPKE_Curve64_CP256_SHA256.c Hacl_HPKE_Curve64_CP256_SHA512.c Hacl_HPKE_P256_CP256_SHA256.c Hacl_Hash_Blake2b_256.c Hacl_Poly1305_256.c Hacl_SHA2_Vec256.c Hacl_Streaming_Blake2b_256.c Hacl_Streaming_Poly1305_256.c\n"
        result += f"DISABLE_OCAML_BINDINGS=1\n"
        result += f"LDFLAGS	+= -Xlinker -z -Xlinker noexecstack -Xlinker --unresolved-symbols=report-all\n"

        if self.settings.compiler == 'gcc':
            cc = f"{toolchain_dir}/bin/{self.config.get_toolchain_name(self.settings)}-gcc"
            ar = f"{toolchain_dir}/bin/{self.config.get_toolchain_name(self.settings)}-ar"
        else:
            cc = "clang"
            ar = "llvm-ar"

        result += f"CC = {cc}\n"
        result += f"AR = {ar}\n"
        return result

    def build_lib(self):
        cwd = os.getcwd()

        os.chdir(f"{self.name}/dist/gcc-compatible")

        logging.info(
            f'Configuring {self.name} for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        cflags += f" {self.settings.optflag}"
        ldflags = ""
        if self.settings.compiler == 'gcc':
            if self.settings.arch == 'x86-i686':
                cflags += " -m32 -march=i386"
            if self.settings.arch == 'aarch64':
                cflags += " -march=armv8-a"
            if self.settings.arch == 'armv4':
                cflags += " -march=armv4"
        if self.settings.compiler == 'llvm':
            ldflags += self.llvm_ldflags(f'{cwd}/toolchain')
            cflags += self.llvm_cflags(f'{cwd}/toolchain')
            if self.settings.arch == 'aarch64':
                cflags += " -march=armv8-a"
            if self.settings.arch == 'armv4':
                cflags += " -march=armv4"
                cflags += ' -mfloat-abi=softfp'
            if self.settings.arch == 'mips32el':
                ldflags += ' -Wl,-z,notext'

        logging.info(f'Setting CFLAGS to {cflags}')
        logging.info(f'Setting LDFLAGS to {ldflags}')

        logging.info(f'Setting up config.h and Makefile.include')

        config_h = self.gen_config()
        with open('config.h', "w") as f:
            f.write(config_h)

        makefile_config = self.gen_makefile_config(
            cflags, ldflags, f'{cwd}/toolchain')
        with open('Makefile.config', "w") as f:
            f.write(makefile_config)

        logging.info('Removing hardcoded optimization level in Makefile')
        # Read the Makefile
        with open('Makefile', 'r') as file:
            filedata = file.read()

        # Replace the target string
        filedata = filedata.replace('-O3', '')

        # Write the file out again
        with open('Makefile', 'w') as file:
            file.write(filedata)

        logging.info(f'Building {self.name} (make)')
        run_subprocess('make')

        os.chdir(cwd)

    def copy_lib_rootfs(self):
        logging.info(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

        logging.info(f"pwd = {os.getcwd()}")
        logging.info(f"find ./ -name '{self.name}*.so'")
        run_subprocess(
            f'cp $(find ./{self.name} -name "*.so") {os.getcwd()}/{self.rootfs}/{self.libdir}')

        # emulation for ppc requires libs in a different dir
        if 'powerpc' in self.settings.arch:
            run_subprocess(
                f'mkdir -p {os.getcwd()}/../{self.rootfs}/{self.libdir}/tls/i686')
            run_subprocess(
                f'cp {os.getcwd()}/../{self.rootfs}/{self.libdir}/* {os.getcwd()}/../toolchain/{self.rootfs}/{self.libdir}/tls/i686/')

    def build(self):
        self.build_lib()
        self.copy_lib_rootfs()

        logging.info(f'- Building driver.c')

        cwd = os.getcwd()

        includestr = f'-Ihacl-star/dist/gcc-compatible/'
        includestr += f' -Ihacl-star/dist/karamel/include'
        includestr += f' -Ihacl-star/dist/karamel/krmllib/dist/minimal'
        librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -levercrypt'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_cflags(
            './toolchain') + self.llvm_ldflags('./toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {librarystr} {cflags} {cwd}/../frameworks/haclstar/driver.c -lm -o {self.rootfs}/driver.bin')

    def supported_ciphers(self) -> list[Algo]:
        return [
            Algo.CHACHA_POLY1305,
            Algo.HMAC_SHA1,
            Algo.HMAC_SHA2,
            Algo.HMAC_BLAKE2,
            Algo.ECDH_CURVE25519,
            Algo.ECDH_P256
        ]

    def gen_args(self, algo: Algo) -> list[str]:
        if algo not in self.supported_ciphers():
            raise "Unsupported algorithm"

        algo_str = {
            Algo.CHACHA_POLY1305: 'chacha_poly1305',
            Algo.HMAC_SHA1: 'hmac-sha1',
            Algo.HMAC_SHA2: 'hmac-sha2',
            Algo.HMAC_BLAKE2: 'hmac-blake2',
            Algo.ECDH_CURVE25519: 'ecdh-curve25519',
            Algo.ECDH_P256: 'ecdh-p256',
        }
        
        return f'@ {algo_str[algo]}'.split()

    def shared_objects(self) -> list[str]:
        return ['libevercrypt']

    def clean_report(self, scd):
        # mask = scd.DF['Symbol Name'].str.contains('hextobin')
        # scd.DF = scd.DF[~mask]
        # # recreate reports:
        # scd._generateReport()
        return scd
