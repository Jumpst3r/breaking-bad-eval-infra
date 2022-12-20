from ..util import git_clone
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
    'x86-i686': 'i686-unknown-linux-elf'
}


class Mbedtls():
    def __init__(self, settings: Settings, config: Config, rootfs: str):
        self.name = 'mbedtls'
        self.url = 'https://github.com/Mbed-TLS/mbedtls.git'
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

    def llvm_cflags(self, toolchain_dir):
        cflags = f' --target={arch_str_target[self.settings.arch]}'
        cflags += f' --sysroot={toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/sysroot/'
        cflags += f' -L{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += f' -B{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += ' -fuse-ld=lld -Wno-error'
        return cflags

    def build_lib(self):
        os.chdir(self.name)

        cwd = os.getcwd()

        logging.info(
            f'Configuring MBEDTLS for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        cflags += f" {self.settings.optflag}"
        if self.settings.compiler == 'gcc':
            if self.settings.arch == 'x86-i686':
                cflags += " -m32 -march=i386"
            if self.settings.arch == 'aarch64':
                cflags += " -march=armv8-a"
            if self.settings.arch == 'armv4':
                cflags += " -march=armv4"
            if self.settings.arch == 'armv7':
                cflags += ' -march=armv7 -mthumb'
        if self.settings.compiler == 'llvm':
            cflags += self.llvm_cflags(f'{cwd}/../toolchain')
            if self.settings.arch == 'aarch64':
                cflags += " -march=armv8-a"
            if self.settings.arch == 'armv4':
                cflags += " -march=armv4"
                cflags += ' -mfloat-abi=softfp'
            if self.settings.arch == 'mips32el':
                cflags += ' -Wl,-z,notext'

        logging.info(f'Setting CFLAGS to {cflags}')

        logging.info('Building mbedtls (make)')
        if self.settings.compiler == 'gcc':
            prefix = f'{cwd}/../toolchain/bin/{self.config.get_toolchain_name(self.settings)}'
            cc = f'{prefix}-gcc'
            ld = f'{prefix}-ld'
            ar = f'{prefix}-ar'
            run_subprocess_env(['SHARED=1 make lib'], cc=cc,
                               ld=ld, ar=ar, cflags=cflags)
        if self.settings.compiler == 'llvm':
            run_subprocess_env(['SHARED=1 make lib'], cc='clang', ar='llvm-ar',
                               cxx='clang++', ld='clang', cflags=cflags, ldflags=cflags)

        os.chdir('../')

    def copy_lib_rootfs(self):
        print(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

        print(f"pwd = {os.getcwd()}")
        print(f"find ./ -name '{self.name}*.so'")
        run_subprocess(
            f'cp $(find ./{self.name} -name "*.so") {os.getcwd()}/{self.rootfs}/{self.libdir}')
        run_subprocess(
            f'cp $(find ./{self.name} -name "*.so.*") {os.getcwd()}/{self.rootfs}/{self.libdir}')

        # emulation for ppc requires libs in a different dir
        if 'powerpc' in self.settings.arch:
            run_subprocess(
                f'mkdir -p {os.getcwd()}/../{self.rootfs}/{self.libdir}/tls/i686')
            run_subprocess(
                f'cp {os.getcwd()}/../{self.rootfs}/{self.libdir}/* {os.getcwd()}/../toolchain/{self.rootfs}/{self.libdir}/tls/i686/')

    def build(self):
        self.build_lib()
        self.copy_lib_rootfs()

        print(f'- Building driver.c')

        cwd = os.getcwd()

        includestr = f'-I{self.name}/include'
        includestr += f' -I{self.name}/include/mbedtls'
        includestr += f' -I{self.name}/include/psa'
        librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lmbedcrypto'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_cflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {librarystr} {cflags} {cwd}/../frameworks/{self.name}/driver.c -lm -o {self.rootfs}/driver.bin')

    def run(self, algo: str):
        pass
