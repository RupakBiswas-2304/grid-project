from filefetcher.github import GithubClone
from filefetcher.pypi import PypiClone
from filefetcher.node import NodeClone
from vulncheck.dependency_check import main as main1

class Code():
    def __init__(self, source):
        self.source = source

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
            Pypi_Code.download_file()
            print(Pypi_Code.file_ext,Pypi_Code.file_ext=="tar.gz")
            if Pypi_Code.file_ext == "tar.gz":
                Pypi_Code.extract_tar_gz()
            elif Pypi_Code.file_ext == "whl":
                Pypi_Code.extract_whl()

            code = Code(Pypi_Code)
            
        else:
            print("Not implemented yet")