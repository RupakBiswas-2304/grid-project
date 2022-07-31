from typing import Dict, List
import requests
import re

import cli.loader as loader


session = requests.Session()


def check_pypi_CVE(module, CVEs: List):
    version = None
    if ("==" in module):
        version = module.split("==")[1]
        module = module.split("==")[0]
    elif (":" in module):
        version = module.split(":")[1]
        module = module.split(":")[0]

    url = f"https://pypi.org/pypi/{module}/json"
    if version != None:
        url = f"https://pypi.org/pypi/{module}/{version}/json"

    response = session.get(url)
    response.raise_for_status()
    info = response.json()
    CVEs.extend(info['vulnerabilities'])


def requirement_reader(filepath):
    with open(filepath) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    return content


def check_requirements(code) -> Dict:
    all_files = code.tree
    pattern = "(req)[a-z]*\.txt"
    requirements = []
    for file in all_files:
        if re.search(pattern, file):
            requirements.extend(requirement_reader(file))
    requirements = list(set(requirements))
    print(f"Found {len(requirements)} python requirements.")
    CVEs = []

    for idx, module in enumerate(requirements):
        loader.progress(idx, len(requirements),
                        status=f"{module.split('==' if '==' in module else ':')[0]}")
        check_pypi_CVE(module, CVEs)

    loader.reset()

    print(f"found {len(CVEs)} CVEs in python requirements.")
    return {"requirements": requirements, "CVEs": CVEs}


# format of exsisting_vuln:
'''
[
        {
            "aliases": [
                "CVE-2020-25626"
            ],
            "details": "A flaw was found in Django REST Framework versions before 3.12.0 and before 3.11.2. When using the browseable API viewer, Django REST Framework fails to properly escape certain strings that can come from user input. This allows a user who can control those strings to inject malicious <script> tags, leading to a cross-site-scripting (XSS) vulnerability.",
            "fixed_in": [
                "3.11.2"
            ],
            "id": "PYSEC-2020-263",
            "link": "https://osv.dev/vulnerability/PYSEC-2020-263",
            "source": "osv"
        },
        {
            "aliases": [
                "CVE-2020-25626"
            ],
            "details": "A flaw was found in Django REST Framework versions before 3.12.0 and before 3.11.2. When using the browseable API viewer, Django REST Framework fails to properly escape certain strings that can come from user input. This allows a user who can control those strings to inject malicious <script> tags, leading to a cross-site-scripting (XSS) vulnerability.",
            "fixed_in": [
                "3.11.2"
            ],
            "id": "GHSA-fx83-3ph3-9j2q",
            "link": "https://osv.dev/vulnerability/GHSA-fx83-3ph3-9j2q",
            "source": "osv"
        }
    ]


'''
