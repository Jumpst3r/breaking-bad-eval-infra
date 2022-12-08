from ..util import git_clone
import os
from process import run_subprocess, run_subprocess_env
from config import Settings, get_prefix, get_toolchain_name
import logging

logging.getLogger().setLevel(logging.DEBUG)

arch_str_target = {
    'x86-64': 'x86_64-unknown-linux-elf',
    'aarch64': 'aarch64-unknown-linux-elf',
    'armv4': 'arm-unknown-linux-elf',
    'armv7': 'arm-unknown-linux-elf',
    'riscv64': 'riscv64-unknown-linux-elf',
    'mips32el': 'mipsel-unknown-linux-elf',
    'x86-686': 'i686-unknown-linux-elf'
}

host_str = {
    'riscv64': 'riscv64',
    'x86-64': 'x86_64',
    'x86': 'x86',
    'armv4': 'arm',
    'armv7': 'arm',
    'aarch64': 'arm',
    'mips32el': 'mips'
}


class Wolfssl():
    def __init__(self, settings: Settings, rootfs: str):
        self.name = 'wolfssl'
        self.url = 'https://github.com/wolfSSL/wolfssl.git'
        self.settings = settings
        self.prefix = get_prefix(settings)
        self.rootfs = rootfs
        self.libdir = '/lib' if 'armv7' in settings.arch or 'mips32el' in settings.arch else '/lib64'

        if not os.path.isdir(self.rootfs):
            os.mkdir(self.rootfs)
        # if not os.path.isdir(f'{self.rootfs}{self.libdir}'):
        #     os.mkdir(f'{self.rootfs}{self.libdir}')

    def download(self):
        if not os.path.isdir(self.name):
            git_clone(self.url, self.settings.commit, self.name)

    def llvm_cflags(self, toolchain_dir):
        cflags = f' --target={arch_str_target[self.settings.arch]}'
        cflags += f' --sysroot={toolchain_dir}/{get_toolchain_name(self.settings)}/sysroot/'
        cflags += f' -L{toolchain_dir}/lib/gcc/{get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += f' -B{toolchain_dir}/lib/gcc/{get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += ' -fuse-ld=lld -Wno-error'
        return cflags

    def build_lib(self):
        os.chdir(self.name)

        cwd = os.getcwd()

        logging.info(
            f'Configuring {self.name} for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        cflags += self.settings.optflag
        if self.settings.compiler == 'gcc':
            # if self.settings.arch == 'x86-686':
            #     cflags += " -m32 -march=i386"
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

        logging.info(f'Configuring {self.name} (autogen)')
        run_subprocess('./autogen.sh')

        logging.info(f'Configuring {self.name} (configure)')
        common = f'--enable-all-crypto --disable-shared --enable-opensslall --enable-static --host={host_str[self.settings.arch]}'

        prefix = f'{cwd}/../toolchain/bin/{get_toolchain_name(self.settings)}'
        if self.settings.compiler == 'gcc':
            cc = f'{prefix}-gcc'
            ld = f'{prefix}-ld'
            ar = f'{prefix}-ar'
            ranlib = f'{prefix}-ranlib'
        else:
            cc = 'clang'
            ld = 'lld'
            ar = 'llvm-ar'
            ranlib = 'llvm-ranlib'

        run_subprocess_env(f'./configure {common}', cc=cc,
                           ld=ld, ar=ar, cflags=cflags, ranlib=ranlib)

        logging.info(f'Building {self.name} (make)')
        run_subprocess_env('make')

        os.chdir('../')

    def copy_lib_rootfs(self):
        print(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

    def build(self):
        self.build_lib()
        self.copy_lib_rootfs()

        print(f'- Building driver.c')

        cwd = os.getcwd()

        includestr = f'-I{self.name}/'
        includestr += f' -I{self.name}/wolfssl'
        includestr += f' -I{self.name}/wolfssl/openssl'
        includestr += f' -I{self.name}/wolfssl/wolfcrypt'
        librarystr = f'{self.name}/src/.libs/libwolfssl.a'

        gcc_toolchain = f'{cwd}/toolchain/bin/{get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_cflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {cflags} -lm -lpthread {cwd}/../frameworks/{self.name}/driver.c {librarystr} -o {self.rootfs}/driver.bin')

    def run(self, algo: str):
        pass
