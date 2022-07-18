from filefetcher.github import GithubClone

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
        else:
            print("Not implemented yet")