from cli.report_former import Report
from filefetcher.github import GithubClone
from filefetcher.pypi import PypiClone
from filefetcher.node import NodeClone
from filefetcher.local import LocalClone
from vulncheck.dependency_check import main as main1
from vulncheck.hardcoded_secret_check.main import Check_Hardcoded_Secrets
from vulncheck.php_vuln_check.phpvuln import main as m
from vulncheck.code_check.main import main as main4
from .tree import flatten_tree
import datetime

Menu = '''
Enter your source:
1. Github
2. Node Module
3. PyPI
4. Local Repository
5. Pull and Re-analyze the previous repository
'''


class Code():
    def __init__(self, source: GithubClone | NodeClone | LocalClone | PypiClone, type: str):
        self.source = source
        self.tree = flatten_tree('tmp')
        self.type = type

    def dependency_check(self):
        return main1.main(self)

    def hardcoded_secret_check(self):
        checker = Check_Hardcoded_Secrets(self.tree)
        return checker.find_and_print_hardcoded_secrets()

    def php_vuln_check(self):
        m(self.tree)

    def code_check(self):
        main4(self)

    def initiate_analysis(self):
        report = Report(self.source.url)

        pypi, node = self.dependency_check()
        report.dependency(pypi, node)

        secrets = self.hardcoded_secret_check()
        report.hardcoded_secrets(secrets)

        self.code_check()

        self.php_vuln_check()


def cli():
    print('Welcome to the file download utility!')
    while(True):
        print(Menu)
        command = input('$> ')

        if command.lower() == 'exit':
            return

        elif command == '1':
            url = input('Enter the Github url/remote: ')
            branch = input('Specify the branch[Default: <Enter>]: ')
            if not branch:
                branch = None

            Github_Code = GithubClone(url, branch)
            Github_Code.clone_repository()

            code = Code(Github_Code, 'github')
            code.initiate_analysis()

        elif command == '2':
            url = input('Enter the Node module name: ')
            Node_Code = NodeClone(url)
            Node_Code.gather_info()
            Node_Code.download_file()
            Node_Code.extract()
            code = Code(Node_Code, 'node')
            code.initiate_analysis()

        elif command == "3":
            url = input("Enter the PyPI module name : ")
            Pypi_Code = PypiClone(url)
            Pypi_Code.gather_info()
            Pypi_Code.download_file()
            Pypi_Code.extract()
            code = Code(Pypi_Code, 'pypi')
            code.initiate_analysis()

        elif command == '4':
            url = input('Enter the Local repository path: ')
            branch = input('Specify the branch[Default: <Enter>]: ')
            if not branch:
                branch = None

            LocalClone_Code = LocalClone(url, branch)
            LocalClone_Code.clone_repository()
            code = Code(LocalClone_Code, 'github')
            code.initiate_analysis()

        elif command == '5':
            LocalClone_Code = LocalClone('tmp', None)
            LocalClone_Code.pull_latest()
            code = Code(LocalClone_Code, 'github')
            code.initiate_analysis()
