from typing import Set
from .pychecker import main as static_check


def main(code):
    vulns = []
    if code.type == "pypi" or code.type == "github":
        all_files = code.tree
        for files in all_files:
            if files.endswith(".py"):
                print("[+] Checking for static vulnerabilities in {}".format(files))
                vulns.extend(list(static_check(files)))

    return vulns
