import os
import subprocess
from filefetcher.BaseClone import BaseClone
from config import LOCAL_REPOSITORY_DIRECTORY

TYPE = 'LOCAL'


class LocalClone(BaseClone):
    def __init__(self, url: str, branch: str | None):
        self.url = url
        super().__init__(url, branch)

    def clone_repository(self):
        if os.path.isdir(f'{self.remote}/.git'):
            super().clone_repository()
        else:
            self.refresh_temp()
            subprocess.call(
                ['cp', '-r', self.remote, LOCAL_REPOSITORY_DIRECTORY])
