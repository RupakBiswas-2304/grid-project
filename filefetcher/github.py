import sys
import subprocess

class GithubClone():
    def __init__(self,url):
        self.url = url
        self.type = "github"

    def download_repo(self):
        print("Downloading repo...")
        try:
            subprocess.call(["rm", "-rf", "tmp"])
            subprocess.call(['mkdir','tmp'])
            subprocess.call(["git", "clone", self.url, "tmp"])
        except Exception as e:
            print(e)
            print("Error: Could not download repo")
            sys.exit()
        print("Downloaded repo")
