from filefetcher.github import GithubClone
from filefetcher.pypi import PypiClone
from filefetcher.node import NodeClone
from filefetcher.local import LocalClone
from vulncheck.dependency_check import main as main1
from vulncheck.hardcoded_secret_check.main import Check_Hardcoded_Secrets
from vulncheck.injection_check import main as main2
from vulncheck.php_vuln_check.main import task
from vulncheck.php_vuln_check.phpvuln import main as m
import vulncheck.php_vuln_check
from .tree import flatten_tree


class Code():
    def __init__(self, source, type: str):
        self.source = source
        self.tree = flatten_tree('tmp')
        self.type = type

    def dependency_check(self):
        main1.main(self)

    def injection_check(self):
        main2.main(self)

    def hardcoded_secret_check(self):
        checker = Check_Hardcoded_Secrets(self.tree)
        print(checker.find_hardcoded_secrets())

    def php_vuln_check(self):
        task()
        m()


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
            code = Code(Github_Code, "github")
            code.dependency_check()
            code.hardcoded_secret_check()
            code.php_vuln_check()

        elif command == "2":
            url = input("Enter the Node module name : ")
            Node_Code = NodeClone(url)
            Node_Code.gather_info()
            Node_Code.download_file()
            Node_Code.extract()

        elif command == "3":
            url = input("Enter the pypi module name : ")
            Pypi_Code = PypiClone(url)
            Pypi_Code.gather_info()
            Pypi_Code.download_file()
            print(Pypi_Code.file_ext, Pypi_Code.file_ext == "tar.gz")
            Pypi_Code.extract()
            code = Code(Pypi_Code, "pypi")

        elif command == "4":
            url = input("Enter the local repo path : ")
            LocalClone_Code = LocalClone(url)
            LocalClone_Code.clone_repo()
            code = Code(LocalClone_Code, "github")
            code.dependency_check()
            code.hardcoded_secret_check()

        else:
            print("Not implemented yet")
