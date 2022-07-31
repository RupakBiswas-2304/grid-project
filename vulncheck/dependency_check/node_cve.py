from signal import valid_signals
import requests
import re
import json

from colorama import Fore, Back


def check_node_cve(code):
    all_files = code.tree
    pattern = "(package-lock.json)"
    package_lock = []
    print("Started Checking for node dependencies")
    for file in all_files:
        if re.search(pattern, file):
            package_lock.append(file)

    url = "https://registry.npmjs.org/-/npm/v1/security/audits"

    vul = {
        "info": 0,
        "low": 0,
        "moderate": 0,
        "high": 0,
        "critical": 0
    }

    for file in package_lock:
        f = open(file, "r")
        data = json.load(f)
        payload = json.dumps({
            "name": "test",
            "version": "0.0.1",
            "requires": data['packages']['']['dependencies'],
            "dependencies": data['dependencies']
        })
        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        result = json.loads(response.text)
        # print(result.keys())
        vul["info"] = vul["info"] + \
            result['metadata']['vulnerabilities']['info']
        vul["low"] = vul["low"] + result['metadata']['vulnerabilities']['low']
        vul["moderate"] = vul["moderate"] + \
            result['metadata']['vulnerabilities']['moderate']
        vul["high"] = vul["high"] + \
            result['metadata']['vulnerabilities']['high']
        vul["critical"] = vul["critical"] + \
            result['metadata']['vulnerabilities']['critical']

    total_vuln = vul["info"] + vul["low"] + \
        vul["moderate"] + vul["high"] + vul["critical"]


    if total_vuln != 0:
        print(f"Found {total_vuln} vulnerabilities in package-lock.json")
        print(
            f"info: {vul['info']} \nlow: {vul['low']} \nmoderate: {vul['moderate']} \nhigh: {vul['high']} \ncritical: {vul['critical']}")
    else:
        print(f'{Fore.RED}Could not find any package-lock.json file!{Fore.RESET}')

    return vul
