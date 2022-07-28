import os
import sys
import argparse

from colorama import Fore


from vulncheck.php_vuln_check.lib.core import utils
from vulncheck.php_vuln_check.lib.core import log


# globals
found = 0


def main():

    xss = 0
    sqli = 0
    rfi = 0
    lfi = 0
    ip = 0
    cred = 0
    cmdi = 0

    vuln_classes = utils.get_vulnerability_classes()
    vulns_list = [(_class.name, _class.keyname) for _class in vuln_classes]

    parser = argparse.ArgumentParser(usage='%(prog)s [options]')

    parser.error = log.error

    parser.add_argument(
        '-p', '--path', help='php project path', dest='path', metavar='')
    parser.add_argument('-v', '--vulns', help='common vulnerabilities to look for. Default: all',
                        dest='included', metavar='', default=','.join(x[1] for x in vulns_list))
    parser.add_argument(
        '--exclude', help='exclude common vulnerabilities', dest='excluded', metavar='')

    args = parser.parse_args()

    args.path = '../../tmp'

    if not args.path and not args.file:
        log.error('missing mandatory option: -p/--path or -f/--file')

    if args.path:
        args.file = None

        if not os.path.exists(args.path) or not os.path.isdir(args.path):
            log.error('directory not found')
    else:
        if not os.path.exists(args.file) or not os.path.isfile(args.file) or not args.file.endswith('.php') and not args.file.endswith('.html'):
            log.error('php file not found')

    included_vulns = args.included.lower().split(',')
    excluded_vulns = args.excluded.lower().split(',') if args.excluded else []

    for vuln in excluded_vulns:
        if not [_class for _class in vuln_classes if _class.keyname == vuln]:
            log.error(f'unrecognized common vulnerability: {vuln}')
            exit(0)
        included_vulns.remove(vuln)

    for vuln in included_vulns:
        if not [_class for _class in vuln_classes if _class.keyname == vuln]:
            log.error(f'unrecognized common vulnerability: {vuln}')
            exit(0)

    global found

    args.path = 'tmp'

    if args.path:
        for root, _, directory in os.walk(args.path):
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
    else:
        for vuln in included_vulns:
            Vulnerability = [
                _class for _class in vuln_classes if _class.keyname == vuln][0]

            vuln_obj = Vulnerability(args.file)

            for line, no, vuln_part in vuln_obj.find():
                while line.endswith(' '):
                    line = line[:-1]
                log.found(args.file, line, no, vuln_part, vuln_obj.name)
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
