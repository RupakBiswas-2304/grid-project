import re
from .settings import PY_SETTINGS as SETTINGS
from typing import List, Tuple

TAB_SIZE = 4
SUS_FUNCTIONS = SETTINGS['SUS_FUNCTIONS']
IGNORE_PATTERN = "^" + "|".join(SETTINGS['IGNORE'])
CONDITIONAL_PATTERN = "^" + "|".join(SETTINGS['CONDITIONALS'])
THRESHOLD = 80


def gettabs(s):
    i = 0
    while s[i] == " ":
        i += 1
    return i

# sink detecting function


def find_sink(line) -> bool:
    """
    TODO : 
        execute, commit, ...
    """
    pattern = "(return\s.*|execute\(.*\))"
    pattern = "(return\s.*)"
    if(re.search(pattern, line)):
        # print("Found sink")
        return True
    return False

# kuch toh hai ye ... dinesh ko pata hai

SAME_SCOPE_SEPARATOR = [',', '+', '-', '**', '*', '//', '/', '=']
# SUS_VARS = [('fn1', 80,"lol"), ('fn5', 30), ('a', 30), ('fn4', 100), ('c', 120)]


def calculate_scope_resolution(s: str) -> List[int]:
    scope: List[int] = [0] * len(s)
    for i in range(1, len(scope)):
        scope[i] = scope[i - 1]
        if s[i] == '(':
            scope[i] += 1
        elif s[i] == ')':
            scope[i] -= 1

    return scope


def base_risk_eval(var: str, malicious_vars: List[Tuple[str, int]]) -> int:
    # print(f'base ke andar : {malicious_vars}')
    res = [(v, r) for v, r in malicious_vars if v == var]
    res.extend([(v, r) for v, _, r in SUS_FUNCTIONS if v == var])
    if len(res) == 0:
        return 0

    assert len(res) == 1, "huh??"

    res = res[0]
    return res[1]


def functional_risk_eval(func: str, x: List[Tuple[str, int]]) -> int:
    sep = [func.split('(')[0],  '('.join(func.split('(')[1:])]
    base = base_risk_eval(sep[0], x)
    if len(sep[1]) != 0:
        base = min(base, recursive_solver(sep[1][:-1]))
    return base


def recursive_solver(s: str, mal_vars: List[Tuple[str, int]]) -> int:
    if len(s) == 0:
        return 0
    scope = calculate_scope_resolution(s)

    if scope.count(scope[0]) == len(scope) and scope[0] == 0:
        dist = [s]
        for sep in SAME_SCOPE_SEPARATOR:
            temp = dist[:]
            dist = []
            for x in temp:
                dist.extend(x.split(sep))

        return max(map(lambda y: base_risk_eval(y, mal_vars), dist))

    scope_distributed = []
    t = ""
    i = 0
    while i < len(s):
        if scope[i] == 0:
            if i < len(s) - 1 and f'{s[i]}{s[i + 1]}' in SAME_SCOPE_SEPARATOR:
                scope_distributed.append(t)
                t = ""
                i += 1
            elif s[i] in SAME_SCOPE_SEPARATOR:
                scope_distributed.append(t)
                t = ""
            else:
                t += s[i]
        else:
            t += s[i]
        i += 1

    if t != "":
        scope_distributed.append(t)

    return max(map(lambda y : functional_risk_eval(y, mal_vars), scope_distributed))


def extract_risk_factor_from_line(s: str, mal_vars: List[Tuple[str, int]]) -> int:
    s = s.strip()
    for sep in SAME_SCOPE_SEPARATOR:
        s = sep.join([x.strip() for x in s.split(sep)])
    return recursive_solver(s, mal_vars)


# print(extract_risk_factor_from_line('c + a + fn4(c)'))

def analyze_line(s: str, output: list, index: int, source: dict, sink: list, vulns: list, source_list: set):
    global TAB_SIZE
    global SUS_FUNCTIONS
    '''
    s = whole code base
    index = current index
    output = [{"key":"value"},{}]
    source = { "key" : [[varname, type, rating ],[],[]]}
    sink = { set of line no of detected sinks }
    vulns = list of all detected vulns
    source_list = source.keys()
    '''

    if (index == len(s)):
        return output, vulns, source, sink, source_list
    s[index] = s[index].rstrip()
    '''
    TODO:
    no need to process --> comments✅, 
                           imports✅,
    need to process --> classes✅, 
                        functions✅, 
                        assignments✅, 
                        conditionals ( if, elif, else, while )✅,
                        sinks(return)✅, 
                        normal lines with function use, 
                        decurator✅
    '''
    if re.search(IGNORE_PATTERN, s[index]):
        pass

    elif s[index].lstrip().startswith("class"):
        data = {
            "type": "class",
            "line-no": index,
            "name": s[index].split(" ")[-1].split(":")[0].strip()
        }
        data["in"] = [["class", data['name']]]
        output.append(data)

    elif s[index].lstrip().startswith("def"):
        data = {
            "type": "def",
            "line-no": index,
            "name": s[index].split("def")[1].split("(")[0].strip(),
        }
        data['in'] = ["def", data['name']]
        data["parametres"] = s[index].split("def")[1].split(
            "(")[1].split(")")[0].strip().split(",")
        if (data["parametres"][0]) == "":
            data["parametres"] = []

        for parametre in data["parametres"]:
            source[parametre] = [[parametre, "parametre", 90]]
            source_list.add(parametre)

        t = gettabs(s[index])
        if t > 0:
            if TAB_SIZE is None:
                TAB_SIZE = t
            data["in"] = output[-1]["in"].copy()
            while (len(data["in"]) > t//TAB_SIZE):
                data["in"].pop()
            data["in"].append(["def", data['name']])
        output.append(data)

    elif s[index].startswith("@"):
        data = {
            "type": "decorator",
            "line-no": index,
            "name": s[index].split("@")[1].strip()
        }
        output.append(data)
        '''
        TODO:
            need to check following function and reduce risk factor
        '''
    elif "=" in s[index]:
        data = {
            "type": "assignment",
            "line-no": index
        }
        data["variable"] = s[index].split("=")[0].strip()
        data["value"] = s[index].split("=")[1].strip()

        for source_var in source_list.copy():
            if re.search(fr"\b{source_var}\b",s[index]):
                x = source[source_var].copy()[0][2]
                # s = riskfactor(int(x)) [ some thing fishy here ]
                source[data["variable"]] = [
                    [source_var, "var", x]] + source[source_var]
                source_list.add(data["variable"])
        for func in SUS_FUNCTIONS.copy():
            if re.search(fr"\b{func[0]}\b",s[index]):
                # print('->>>>' + re.search(fr"\b{func[0]}\b",s[index]).group())
                data["vuln"] = True
                vulns.append(f"{index-1}|{s[index-1]}\n{index}|{s[index]}\n{index+1}|{s[index+1]}Insecure {func[1]} function used in line no.{index}\nScore: {func[2]}\n")
                source[data["variable"]] = [[func[0],"var",func[2]]] 
                source_list.add(data["variable"])

        t = gettabs(s[index])
        if t > 0:
            if TAB_SIZE is None:
                TAB_SIZE = t
            data["in"] = output[-1]["in"].copy()
            while (len(data["in"]) > t//TAB_SIZE):
                data["in"].pop()
        output.append(data)

    elif re.search(CONDITIONAL_PATTERN, s[index].strip()):
        data = {
            "type": "conditional",
            "line-no": index,
            "condition": s[index].strip()
        }
        for source_var in source_list.copy():
            if source_var in s[index]:
                pass
                # x = source[source_var][2]
                # s = riskfactor(x)
                # source[source_var][2] = s
                # source_list.add(data["condition"])
        t = gettabs(s[index])
        if t > 0:
            if TAB_SIZE is None:
                TAB_SIZE = t
            data["in"] = output[-1]["in"].copy()
            while (len(data["in"]) > t//TAB_SIZE):
                data["in"].pop()
        output.append(data)
    elif find_sink(s[index]):
        data = {
            "type": "sink",
            "line-no": index,
        }
        data["in"] = output[-1]["in"].copy()
        t = gettabs(s[index])
        while (len(data["in"]) > t//TAB_SIZE):
            data["in"].pop()

        scope = output[-1].copy()
        # print("🚩",data["in"])
        k = len(output)-1
        while (output[k]["type"] != "def"):
            k -= 1

        for func in SUS_FUNCTIONS.copy():
            if re.search(fr"\b{func[0]}\b",s[index]):
                # print('->>>>' + re.search(fr"\b{fun[0]}\b",s[index]).group())
                data["vuln"] = True
                vulns.append(f"{index-1}|{s[index-1]}\n{index}|{s[index]}\n{index+1}|{s[index+1]}Insecure {func[1]} function used in line no.{index}\n")
                scope = output[-1].copy()
                # print(scope)
                SUS_FUNCTIONS.append([output[k]["name"],"custom",func[2]])
        for source_var in source_list.copy():
            if re.search(fr"\b{source_var}\b",s[index]):
                x = [(source[source_var][0][0],source[source_var][0][2])]
                # print(f'{s[index]}<-: {x}')
                """fnc(1, sepp="sdfjk") """
                point = extract_risk_factor_from_line(s[index], x)
                # print(f"POINT---->{point}")
                # s = riskfactor(x)
                # if s > THRESHOLD:
                if point:
                    data["vuln"] = True
                    vulns.append(f"{index-1}|{s[index-1]}\n{index}|{s[index]}\n{index+1}|{s[index+1]}Insecure {source_var} used in line no.{index}\n")
                    source[source_var][0][2] = 69
                    SUS_FUNCTIONS.append([output[k]["name"],"custom",69])
                    # source_list = source_list - {source_var} #removing local varriables
                    # del source[source_var] #removing local varriable
                    # for p in output[k]["parametres"]:
                    #     if p in source.keys():
                    #         source_list = source_list - {p}
                    #         del source[p]
        output.append(data)
        sink.append(index)

    return analyze_line(s, output, index+1, source, sink, vulns, source_list)


def main(path):
    f = open(path, "r")
    lines = f.readlines()
    f.close()
    x = set()
    data, vulns, source, sink, source_list = analyze_line(
        lines, [], 0, {}, [], [], x)
    # print(source,sink,source_list)
    for v in vulns:
        print(v)

    # print(SUS_FUNCTIONS)


