from filefetcher.BaseClone import BaseClone

TYPE = "github"


class GithubClone(BaseClone):
    def __init__(self, remote: str, branch: str | None):
        self.type = TYPE
        self.url = remote
        super().__init__(remote, branch)
