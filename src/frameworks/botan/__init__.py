from ..util import *
import os
from src.process import run_subprocess, run_subprocess_env
from src.config import Settings, Config
import logging

logging.getLogger().setLevel(logging.DEBUG)

host_str = {
    'riscv64': 'riscv64',
    'x86-64': 'x86_64',
    'x86-i686': 'x86_32',
    'armv4': 'arm',
    'armv7': 'arm',
    'aarch64': 'armv8',
    'mips32el': 'mips'
}


class Botan(Framework):
    def __init__(self, settings: Settings, config: Config, rootfs: str, fwDir: str):
        self.name = 'botan'
        self.url = 'https://github.com/randombit/botan.git'
        self.settings = settings
        self.prefix = config.get_prefix(settings)
        self.rootfs = rootfs
        self.libdir = '/lib' if 'armv7' in settings.arch or 'mips32el' in settings.arch else '/lib64'
        self.config = config
        self.fwDir = fwDir

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
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/c++/{self.settings.gcc_ver}/'
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/c++/{self.settings.gcc_ver}/{self.config.get_toolchain_name(self.settings)}/'
        cflags += f' -I{toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/include/'
        cflags += f' --sysroot={toolchain_dir}/{self.config.get_toolchain_name(self.settings)}/sysroot/'
        cflags += f' -L{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += f' -B{toolchain_dir}/lib/gcc/{self.config.get_toolchain_name(self.settings)}/{self.settings.gcc_ver}/'
        cflags += ' -fuse-ld=lld -Wno-error'
        return cflags

    def build_lib(self):
        os.chdir(self.name)

        cwd = os.getcwd()

        logging.info(
            f'Configuring {self.name} for {self.settings.compiler} on {self.settings.arch}')

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

        logging.info(f'Configuring {self.name} (configure.py)')
        common = f'--cpu={host_str[self.settings.arch]}'

        prefix = f'{cwd}/../toolchain/bin/{self.config.get_toolchain_name(self.settings)}'
        if self.settings.compiler == 'gcc':
            comp_configure = f'--cc-bin={prefix}-g++ --ar-command={prefix}-ar'
            comp_configure += f' --extra-cxxflags="{cflags}" --no-optimizations'
        else:
            comp_configure = f'--cc-bin=clang++ --disable-cc-tests'
            comp_configure += f' --ldflags="{cflags}" --extra-cxxflags="{cflags}"'
            comp_configure += f' --ar-command=llvm-ar --no-optimizations'
            comp_configure += f' --with-sysroot-dir={cwd}/../toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot'

        run_subprocess_env(f'./configure.py {common} {comp_configure}')

        logging.info(f'Building {self.name} (make)')
        run_subprocess_env('make libs -j6')

        os.chdir('../')

    def copy_lib_rootfs(self):
        logging.info(f'- Copying files to {self.rootfs}{self.libdir}')

        cwd = os.getcwd()

        run_subprocess(
            f'cp -r {cwd}/toolchain/{self.config.get_toolchain_name(self.settings)}/sysroot/* {os.getcwd()}/{self.rootfs}')

        logging.info(f"pwd = {os.getcwd()}")
        logging.info(f"find ./ -name '{self.name}*.so'")
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

        logging.info(f'- Building driver.c')

        cwd = os.getcwd()

        includestr = f'-I{self.name}/'
        includestr += f' -I{self.name}/build/include'

        # Use the correct name irrespectove of the version
        if self.settings.commit.startswith('2.'):
            librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lbotan-2'
        else:
            librarystr = f'-L{cwd}/{self.rootfs}/{self.libdir} -lbotan-3'

        gcc_toolchain = f'{cwd}/toolchain/bin/{self.config.get_toolchain_name(self.settings)}-g++'
        compiler_cmd = gcc_toolchain if self.settings.compiler == 'gcc' else 'clang++'

        cflags = '' if self.settings.compiler == 'gcc' else self.llvm_cflags(
            './toolchain')
        run_subprocess_env(
            f'{compiler_cmd} {includestr} {cflags} -lm -lpthread {self.fwDir}/{self.name}/driver.c {librarystr} -o {self.rootfs}/driver.bin')

    def supported_ciphers(self) -> list[Algo]:
        return [
            Algo.AES_CBC,
            Algo.AES_CTR,
            Algo.AES_GCM,
            Algo.CAMELLIA_CBC,
            Algo.ARIA_CBC,
            Algo.DES_CBC,
            Algo.CHACHA_POLY1305,
            Algo.HMAC_SHA2,
            Algo.ECDSA
        ]

    def gen_args(self, algo: Algo) -> list[str]:
        if algo not in self.supported_ciphers():
            raise "Unsupported algorithm"

        algo_str = {
            Algo.AES_CBC: 'aes-cbc',
            Algo.AES_CTR: 'aes-ctr',
            Algo.AES_GCM: 'aes-gcm',
            Algo.CAMELLIA_CBC: 'camellia-cbc',
            Algo.ARIA_CBC: 'aria-cbc',
            Algo.DES_CBC: 'des-cbc',
            Algo.CHACHA_POLY1305: 'chacha-poly1305',
            Algo.HMAC_SHA2: 'hmac-sha256',
            Algo.ECDSA: 'ecdsa'
        }

        return f'@ {algo_str[algo]}'.split()

    def shared_objects(self) -> list[str]:
        if self.settings.commit.startswith('2.'):
            return ['libbotan-2']
        else:
            return ['libbotan-3']

    def clean_report(self, scd):
        # mask = scd.DF['Symbol Name'].str.contains('hextobin')
        # scd.DF = scd.DF[~mask]
        # # recreate reports:
        # scd._generateReport()
        return scd
