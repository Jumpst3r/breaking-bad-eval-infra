import logging
import os

from process import run_subprocess

def git_clone(url: str, commit: str, name: str):
    logging.info(f'Cloning {name}')
    run_subprocess(['git', 'clone', url, name])

    os.chdir(name)
    logging.info(f'Selecting commit {commit}')
    run_subprocess(['git', 'checkout', commit])
    os.chdir('../')

def git_reset(commit: str, name: str):
    os.chdir(name)
    run_subprocess(f'git reset --hard {commit}')
    run_subprocess(f'git clean -f -x .')
    os.chdir('../')