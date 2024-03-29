import datetime
import subprocess
from typing import List, Tuple

from config import VERSION


def report_top(url):
    return f'''
<h1 align="center"> Code Report for {url} </h1>
<h4 align="right"> Created By Static Code Analyzer {VERSION} </h4>
<h4 align="right">{ datetime.datetime.now() }</h4>  
  
#
    '''


class Report:
    def __init__(self, url: str):
        self.url = url
        self.filename = f"Report/REPORT_{url.split('/')[-1].split('.')[0]}.md"
        subprocess.call(["rm", "-f", self.filename])

        self.write(report_top(url))

    def write(self, content):
        with open(self.filename, 'a') as f:
            f.write(content)

    def dependency(self, pypi, node):
        content_py = f"""

# Python Dependencies

-   ### Total Python dependencies : {len(pypi["requirements"])}
-   ### Total vulnerable Python dependencies : {len(pypi["CVEs"])} 

### Vulnerabilities :

        """
        for cve in pypi["CVEs"]:
            content_py += f"""
-   `{cve["aliases"][0] if cve["aliases"] else "NO CVE SPECIFIED"}` : {cve["details"]}, Fixed in `{cve["fixed_in"][0]}`
            """

        content_npm = f"""
# Node Dependencies

### Vulnerabilities :

-   ### Total Node dependencies : {len(node["requirements"])}
-   ### Total vulnerable Node dependencies : {len(node["CVEs"])} 

        """

        for cve in node["CVEs"]:
            if cve["cves"]:
                content_npm += f"""
-   `{cve["cves"][0] if cve["cves"] else "NO CVE SPECIFIED"}` : {cve["title"]} [**{cve["module_name"]}**], with Severity of `{cve["severity"]}`
                """

        self.write(content_py)
        self.write(content_npm)

    def hardcoded_secrets(self, secrets: List[Tuple[str, List[Tuple[int, str, str]]]]):
        content = """
# Hard Coded Dependencies

### Vulnerabilities :
"""
        for file_secrets in secrets:
            for secret in file_secrets[1]:
                content += f"""
-   Found Hard Coded Secret on line `{secret[0]}` in the file `{'tmp'.join(file_secrets[0].split('tmp')[1:])}`  
    ```py
    {secret[2]}
    ```    
                """

        self.write(content)

    def code_check(self, static_analysis: List[str]):
        self.write('''
# Python Static Code Scan Report

### Vulnerabilities :

        ''')
        for line in static_analysis:
            self.write(f'''
```py
{line}
```
        ''')
