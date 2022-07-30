from .pychecker import main as static_check

def main(code):
    if code.type == "pypi" or code.type == "github":
        all_files = code.tree
        for files in all_files:
            if files.endswith(".py"):
                static_check(files)




