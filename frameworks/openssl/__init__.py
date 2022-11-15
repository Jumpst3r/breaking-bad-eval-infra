from ..util import git_clone
import os
from process import run_subprocess, run_subprocess_env
from config import Settings, get_prefix, get_toolchain_name
import logging

logging.getLogger().setLevel(logging.DEBUG)

compile_options = {"buildcmd-gcc": ["./Configure linux-aarch64 --cross-compile-prefix={cwd}/../toolchain/bin/aarch64-linux- $CFLAGS", "make -j4"],
                   "buildcmd-clang": ["./Configure linux-aarch64 $CFLAGS", "sed -i \"/^CC=/c\\CC=clang\" Makefile && sed -i \"/^AR=/c\\AR=llvm-ar\" Makefile && sed -i \"/^CXX=/c\\CXX=clang++\" Makefile", "make -j4"],
                   "cflags-clang": "--target=aarch64-elf-linux -gdwarf-4 -march=armv8-a --gcc-toolchain={cwd}/../toolchain/ -I{cwd}/../toolchain/aarch64-buildroot-linux-gnu/include/c++/7.3.0/ -I{cwd}/../toolchain/aarch64-buildroot-linux-gnu/include/c++/7.3.0/aarch64-buildroot-linux-gnu/ -I{cwd}/../toolchain/aarch64-buildroot-linux-gnu/include/ --sysroot={cwd}/../toolchain/aarch64-buildroot-linux-gnu/sysroot -L{cwd}/../toolchain/lib/gcc/aarch64-buildroot-linux-gnu/7.3.0/ -B {cwd}/../toolchain/lib/gcc/aarch64-buildroot-linux-gnu/7.3.0/ -fuse-ld=lld -Wno-error",
                                   "cflags-gcc": "-march=armv8-a -gdwarf-4"}

arch_str_gcc = {
    'x86-64': 'linux-x86_64',
    'aarch64': 'linux-aarch64',
    'armv4': 'linux-armv4',
    'armv7': 'linux-armv7',
    'riscv64': 'linux64-riscv64',
    'mips32el': 'linux-mips32',
    'x86-686': 'linux-x86'
}

arch_str_llvm = {
    'x86-64': 'linux-x86_64-clang',
    'aarch64': 'linux-aarch64',
    'armv4': 'linux-armv4',
    'armv7': 'linux-armv7',
    'riscv64': 'linux64-riscv64',
    'mips32el': 'linux-mips32',
    'x86-686': 'linux-x86-clang'
}

arch_str_target = {
    'x86-64': 'x86_64-unknown-linux-elf',
    'aarch64': 'aarch64-unknown-linux-elf',
    'armv4': 'arm-unknown-linux-elf',
    'armv7': 'arm-unknown-linux-elf',
    'riscv64': 'riscv64-unknown-linux-elf',
    'mips32el': 'mipsel-unknown-linux-elf',
    'x86-686': 'i686-unknown-linux-elf'
}

# Example configure call using LLVM and aarch64
# ./Configure linux-aarch64 \
# --target=aarch64-elf-linux -gdwarf-4 -march=armv8-a \
# --gcc-toolchain={cwd}/../toolchain/ \
# -I{cwd}/../toolchain/aarch64-buildroot-linux-musl/include/c++/11.3.0/ \
# -I{cwd}/../toolchain/aarch64-buildroot-linux-musl/include/c++/11.3.0/aarch64-buildroot-linux-musl/ \
# -I{cwd}/../toolchain/aarch64-buildroot-linux-musl/include/ \
# --sysroot={cwd}/../toolchain/aarch64-buildroot-linux-musl/sysroot \
# -L{cwd}/../toolchain/lib/gcc/aarch64-buildroot-linux-musl/11.3.0/ \
# -B {cwd}/../toolchain/lib/gcc/aarch64-buildroot-linux-musl/11.3.0/ \
# -fuse-ld=lld -Wno-error


class Openssl():
    def __init__(self, settings: Settings, rootfs: str):
        self.name = 'openssl'
        self.url = 'git://git.openssl.org/openssl.git'
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
        cflags += f' --gcc-toolchain={toolchain_dir}/'
        cflags += f' -I{toolchain_dir}/{get_toolchain_name(self.settings)}/include/c++/{self.settings.gcc_ver}/'
        cflags += f' -I{toolchain_dir}/{get_toolchain_name(self.settings)}/include/c++/{self.settings.gcc_ver}/{get_toolchain_name(self.settings)}/'
        cflags += f' -I{toolchain_dir}/{get_toolchain_name(self.settings)}/include/'
        cflags += f' --sysroot={toolchain_dir}/{get_toolchain_name(self.settings)}/sysroot/'
        cflags += f' -L{toolchain_dir}/lib/gcc/{get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += f' -B{toolchain_dir}/lib/gcc/{get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += ' -fuse-ld=lld -Wno-error'
        return cflags

    def build_lib(self):
        os.chdir(self.name)

        cwd = os.getcwd()

        logging.info(
            f'Configuring openssl for {self.settings.compiler} on {self.settings.arch}')

        cflags = "-gdwarf-4"
        if self.settings.compiler == 'gcc':
            # if self.settings.arch == 'x86-686':
            #     cflags += " -m32 -march=i386"
            if self.settings.arch == 'aarch64':
                cflags += " -march=armv8-a"
            if self.settings.arch == 'armv4':
                cflags += " -march=armv4"
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

        if self.settings.compiler == 'gcc':
            configure = [
                './Configure',
                f'{arch_str_gcc[self.settings.arch]}',
                f'--cross-compile-prefix={cwd}/../toolchain/{self.prefix}',
                cflags
            ]
            run_subprocess(configure)
        elif self.settings.compiler == 'llvm':
            configure = [
                './Configure',
                f'{arch_str_llvm[self.settings.arch]}',
                cflags
            ]
            run_subprocess_env(configure, 'clang', 'llvm-ar', 'clang++')
        else:
            logging.error('Unknown compiler for Openssl')
            raise Exception('Unknown compiler for Openssl')

        logging.info('Building OpenSSL (make)')
        if self.settings.compiler == 'gcc':
            run_subprocess(['make', '-j6'])
        if self.settings.compiler == 'llvm':
            run_subprocess_env(['make', '-j6'], 'clang', 'llvm-ar', 'clang++')

        os.chdir('../')

    def copy_lib_rootfs(self):
        print(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

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
        librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lcrypto'

        gcc_toolchain = f'{cwd}/toolchain/bin/{get_toolchain_name(self.settings)}-gcc'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_cflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {librarystr} {cflags} {cwd}/../frameworks/{self.name}/driver.c -lm -o {self.rootfs}/driver.bin')

    def run(self, algo: str):
        pass
