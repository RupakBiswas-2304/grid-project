import subprocess
import os
from config import LOCAL_REPOSITORY_DIRECTORY


class BaseClone:
    def __init__(self, remote: str, branch: str | None = None):
        self.remote = remote
        self.branch = branch

    def refresh_temp(self):
        subprocess.call(['rm', '-rf', LOCAL_REPOSITORY_DIRECTORY])

    def set_branch(self, branch: str):
        self.branch = branch

    def set_remote(self, remote: str):
        self.remote = remote

    def clone_repository(self):
        self.refresh_temp()

        git_clone_args = ['git', 'clone']
        if self.branch:
            git_clone_args.extend(['-b', self.branch])
        git_clone_args.extend([self.remote, LOCAL_REPOSITORY_DIRECTORY])

        subprocess.call(git_clone_args)

    def pull_latest(self):
        if os.path.isdir(f'{LOCAL_REPOSITORY_DIRECTORY}/.git'):
            subprocess.call(['git', 'pull'], cwd=LOCAL_REPOSITORY_DIRECTORY)
