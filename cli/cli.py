from filefetcher.github import GithubClone
from filefetcher.pypi import PypiClone
from filefetcher.node import NodeClone
from filefetcher.local import LocalClone
from vulncheck.dependency_check import main as main1
from .tree import list_files

class Code():
    def __init__(self, source,type):
        self.source = source
        self.tree = list_files('tmp')
        self.type = type
    def dependency_check(self):
        main1.main(self)

def cli():
    print("Welcome to the file download utility!")
    while(True):
        print("Enter your source:\n 1. Github\n 2. Node Module\n 3. Pypi\n 4. Local Repo\n")
        command = input("> ")
        if command == "exit" or command == "Exit":
            return
        elif command == "1":
            url = input("Enter the github url: ")
            Github_Code = GithubClone(url)
            Github_Code.download_repo()
            code = Code(Github_Code,"github")
            code.dependency_check()

        elif command == "2":
            url = input("Enter the node module name : ")
            Node_Code = NodeClone(url)
            Node_Code.gather_info()
            Node_Code.download_file()
            if Node_Code.file_ext == "tgz":
                Node_Code.extract_tgz()

        elif command == "3":
            url = input("Enter the pypi module name : ")
            Pypi_Code = PypiClone(url)
            Pypi_Code.gather_info()
            Pypi_Code.dowload_file()
            print(Pypi_Code.file_ext,Pypi_Code.file_ext=="tar.gz")
            if Pypi_Code.file_ext == "tar.gz":
                Pypi_Code.extract_tar_gz()
            elif Pypi_Code.file_ext == "whl":
                Pypi_Code.extract_whl()
            elif Pypi_Code.file_ext == "zip":
                Pypi_Code.extract_zip()

            code = Code(Pypi_Code,"pypi")
        elif command == "4":
            url = input("Enter the local repo path : ")
            LocalClone_Code = LocalClone(url)
            LocalClone_Code.clone_repo()
            code = Code(LocalClone_Code,"github")
            code.dependency_check()            
        else:
            print("Not implemented yet")
        return