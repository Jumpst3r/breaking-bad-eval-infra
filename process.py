import subprocess
import logging
import os

# logging.getLogger().setLevel(logging.DEBUG)


def checkretcode(result):
    err = result.stderr
    if result.returncode != 0:
        logging.error(f"failed: {err}")
        exit(-1)


def run_subprocess(args, *additionalargs, **kwargs):
    """A wrapper around `subprocess.run` that sets some settings important for us."""
    logging.getLogger().setLevel(logging.DEBUG)
    command = ''
    if not isinstance(args, str):
        command = ' '.join(args)
    else:
        command = args
        args = args.split(' ')
    logging.debug(
        f"Running command: {command} (cwd: {os.getcwd()})")
    assert 'cwd' not in kwargs
    assert 'check' not in kwargs
    assert 'capture_output' not in kwargs
    result = subprocess.run(command, *additionalargs, shell=True,
                            check=False, capture_output=True, **kwargs)
    checkretcode(result)
    # logging.debug(f'subprocess output: {result.stdout}')
    return result


def run_subprocess_env(args, cc='', ar='', cxx='', ld_lib=''):
    """A wrapper around `subprocess.run` that sets the CC, CXX, and AR env variables."""
    my_env = os.environ.copy()
    my_env['CC'] = cc
    my_env['CXX'] = cxx
    my_env['AR'] = ar
    my_env['LD_LIBRARY_PATH'] = ld_lib

    run_subprocess(args, env=my_env)
