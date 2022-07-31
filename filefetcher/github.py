from filefetcher.BaseClone import BaseClone

TYPE = "GITHUB"


class GithubClone(BaseClone):
    def __init__(self, remote: str, branch: str | None):
        super().__init__(remote, branch)
