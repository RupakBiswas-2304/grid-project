import os
import argparse
from typing import List

from colorama import Fore


from vulncheck.php_vuln_check.lib.core import utils
from vulncheck.php_vuln_check.lib.core import log


# globals
found = 0


def main(tree: List[str],filepath : str):
    content = f'''
# PHP scan

### Vulnerabilities :
    '''
    with open(filepath, 'a') as f:
        f.write(content)
    xss = 0
    sqli = 0
    rfi = 0
    lfi = 0
    ip = 0
    cred = 0
    cmdi = 0

    vuln_classes = utils.get_vulnerability_classes()
    vulns_list = [(_class.name, _class.keyname) for _class in vuln_classes]

    vulns_ = ','.join(x[1] for x in vulns_list)

    included_vulns = vulns_.split(',')

    for vuln in included_vulns:
        if not [_class for _class in vuln_classes if _class.keyname == vuln]:
            log.error(f'unrecognized common vulnerability: {vuln}')
            return
            # exit(0)

    global found

    path = 'tmp'
    found = 0
    if path:
        for root, _, directory in os.walk(path):
            for file in directory:
                if not file.endswith('.php') and not file.endswith('.html'):
                    continue

                file_path = os.path.join(root, file)

                for vuln in included_vulns:
                    Vulnerability = [
                        _class for _class in vuln_classes if _class.keyname == vuln][0]

                    vuln_obj = Vulnerability(file_path)

                    for line, no, vuln_part in vuln_obj.find():
                        while line.endswith(' '):
                            line = line[:-1]
                        log.found(file_path, line, no,
                                  vuln_part, vuln_obj.name)
                        log.report_found(file_path, line, no,
                                  vuln_part, vuln_obj.name,filepath)
                                    
                        if vuln_obj.name == "CROSS-SITE SCRIPTING (XSS)":
                            xss += 1
                        if vuln_obj.name == "SQL INJECTION":
                            sqli += 1
                        if vuln_obj.name == "REMOTE FILE INCLUSION":
                            rfi += 1
                        if vuln_obj.name == "LOCAL FILE INCLUSION":
                            lfi += 1
                        if vuln_obj.name == "IP EXPOSURE":
                            ip += 1
                        if vuln_obj.name == "CONFIGURATION CREDENTIALS":
                            cred += 1
                        if vuln_obj.name == "COMMAND INJECTION":
                            cmdi += 1
                        found += 1

    if found > 0:
        log.info(
            f'phpvuln finished with {Fore.GREEN}{found} {Fore.RESET}potential vulnerabilit{"y" if found == 1 else "ies"} found')
        log.vuls(xss, sqli, rfi, lfi, ip, cred, cmdi)
    else:
        log.info(f'phpvuln finished, but no potential vulnerabilities were found')


if __name__ == '__main__':
    main()
