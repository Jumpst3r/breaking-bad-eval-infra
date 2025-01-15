import subprocess
import logging
import os
from src.config import logger
# import logger from toolchain

# logging.getLogger().setLevel(logging.DEBUG)

def checkretcode(result):
    err = result.stderr
    if result.returncode != 0:
        logger.error(f"failed: {err}")
        exit(-1)


def run_subprocess(args, *additionalargs, **kwargs):
    """A wrapper around `subprocess.run` that sets some settings important for us."""
    command = ''
    if not isinstance(args, str):
        command = ' '.join(args)
    else:
        command = args
        args = args.split(' ')
    logger.debug(
        f"Running command: {command} (cwd: {os.getcwd()})")
    assert 'cwd' not in kwargs
    assert 'check' not in kwargs
    assert 'capture_output' not in kwargs
    result = subprocess.run(command, *additionalargs, shell=True,
                            check=False, capture_output=True, **kwargs)
    checkretcode(result)
    # logging.debug(f'subprocess output: {result.stdout}')
    return result


def run_subprocess_env(args, cc='', ar='', cxx='', ld_lib='', ld='', cflags='', ldflags='', ranlib='', path=''):
    """A wrapper around `subprocess.run` that sets the CC, CXX, and AR env variables."""
    my_env = os.environ.copy()
    my_env['CC'] = cc
    my_env['CXX'] = cxx
    my_env['AR'] = ar
    my_env['LD'] = ld
    my_env['RANLIB'] = ranlib
    my_env['CFLAGS'] = cflags
    my_env['LDFLAGS'] = ldflags
    my_env['LD_LIBRARY_PATH'] = ld_lib
    if path != '':
        if 'PATH' in my_env and len(my_env['PATH']) > 0:
            my_env['PATH'] = f'{path}{os.pathsep}{my_env["PATH"]}'
        else:
            my_env['PATH'] = path
    run_subprocess(args, env=my_env)
