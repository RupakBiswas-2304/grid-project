from filefetcher.github import GithubClone
from filefetcher.pypi import PypiClone

def cli():
    print("Welcome to the file download utility!")
    while(True):
        print("Enter your source:\n 1. Github\n 2. Local file\n 3. Pypi\n 4. Npm\n")
        command = input("> ")
        if command == "exit" or command == "Exit":
            return
        elif command == "1":
            url = input("Enter the github url: ")
            Github_Code = GithubClone(url)
            Github_Code.download_repo()
        elif command == "3":
            url = input("Enter the pypi url: ")
            Pypi_Code = PypiClone(url)
            Pypi_Code.gather_info()
            Pypi_Code.dowload_file()
            print(Pypi_Code.file_ext,Pypi_Code.file_ext=="tar.gz")
            if Pypi_Code.file_ext == "tar.gz":
                Pypi_Code.extract_tar_gz()
            elif Pypi_Code.file_ext == "whl":
                Pypi_Code.extract_whl()
        else:
            print("Not implemented yet")