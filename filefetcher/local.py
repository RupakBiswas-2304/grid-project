import sys
import os
import subprocess

class LocalClone():
    def __init__(self,url):
        self.url = url
        self.type = "local"
    def clone_repo(self):
        print("Cloneing repo....")
        try:
            subprocess.call(["rm", "-rf", "tmp"])
            subprocess.call(['mkdir','tmp'])
            if os.path.isdir(f'{self.url}/.git'):
                subprocess.call(["git", "clone", self.url, "tmp"])
            else:
                subprocess.call(["cp", "-r", self.url, "tmp"])

        except Exception as e:
            print(e)
            print("Error: Could not clone repo")
            sys.exit()
        print("Cloned repo")
    
