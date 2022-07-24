# function for listing all the files in tmp folder
import os
import re
from typing import AnyStr, List, Pattern

ignorable_patterns: List[Pattern[str]] = []


def matches_regex_patterns(path: str):
    for regex in ignorable_patterns:
        if regex.search(path):
            return True
    return False


def list_files(path) -> List[str]:
    files: List[str] = []
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)) and not matches_regex_patterns(f'{path}/{file}'):
            files.append(f"{path}/{file}")
        elif not matches_regex_patterns(f'{path}/{file}/'):
            files.extend(list_files(os.path.join(path, file)))

    return files


def flatten_tree(path):
    global ignorable_patterns

    with open('./.checkignore', 'r') as f:
        ignorable_patterns = [re.compile(
            f'(.*/)*{x.strip()}.*') for x in f.readlines()]

    return list_files(path)
