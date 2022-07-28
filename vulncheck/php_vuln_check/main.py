import sys
import subprocess

def task():
    ec = 'rm -rf ./vulncheck/php_vuln_check/tmp'
    cmd = 'cp -r ./tmp ./vulncheck/php_vuln_check'
    subprocess.call(ec,shell=True)
    subprocess.call(cmd,shell=True)