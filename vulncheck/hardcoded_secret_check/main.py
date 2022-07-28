import codecs
import re
import os

from typing import List, Pattern, Tuple


def get_common_protected_keywords() -> List[str]:
    with open(os.path.join(os.path.dirname(__file__), './Secret_Keywords.txt')) as f:
        return [x.strip() for x in f.readlines()]


class Check_Hardcoded_Secrets:
    def __init__(self, file_list: List[str]):
        self.keywords = get_common_protected_keywords()
        self.keyword_pattern_with_quotes = self.form_regex("""["'`]""")
        self.keyword_pattern_without_quotes = self.form_regex("")
        self.file_list = file_list

    def form_regex(self, quotation: str) -> List[Pattern[str]]:
        return [re.compile(r"""("|'|`|\b)[a-zA-Z\_]*{x}[a-zA-Z\_0-9]*\1\s*(={{1,3}}|:|:=)\s*(({quotation})(?:(?=(\\?))\5.)*?\4|([0-9][0-9]*))""".format(x=x, quotation=quotation), re.IGNORECASE) for x in self.keywords]

    def check_file_for_hardcoded_secrets(self, file_content: List[str], extension: str) -> List[Tuple[int, str]]:
        allowed_without_quotes = False
        if extension in ('txt', 'conf'):
            allowed_without_quotes = True

        hardcoded_secrets = []

        for idx, line in enumerate(file_content):
            found = False
            for pattern in self.keyword_pattern_with_quotes:
                if pattern.search(line):
                    hardcoded_secrets.append((idx, line.strip()))
                    found = True
                    break
            if allowed_without_quotes and not found:
                for pattern in self.keyword_pattern_without_quotes:
                    if pattern.search(line):
                        hardcoded_secrets.append((idx, line.strip()))
                        break

        return hardcoded_secrets

    def find_hardcoded_secrets(self) -> List[Tuple[str, List[Tuple[int, str]]]]:
        hardcoded_secrets = []
        for file in self.file_list:
            with codecs.open(file, 'r', encoding='utf-8', errors='ignore') as f:
                result = self.check_file_for_hardcoded_secrets(
                    [x.rstrip() for x in f.readlines()], file.split('.')[-1])

                if result:
                    hardcoded_secrets.append((file, result))

        return hardcoded_secrets


def test(file_list: List[str]):
    checker = Check_Hardcoded_Secrets(file_list)
    checker.find_hardcoded_secrets()


if __name__ == "__main__":
    test([])
