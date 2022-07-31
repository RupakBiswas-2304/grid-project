from .pypi_cve import check_pypi_CVE, check_requirements
from .node_cve import check_node_cve


def main(code):
    if code.type == "pypi":
        dependency = code.dependency
        for i in dependency:
            i = i.split(" ")[0]
        existing_dependency = []
        for i in dependency:
            existing_dependency = existing_dependency + check_pypi_CVE(i)

        if len(existing_dependency) > 0:
            print(f"Found {len(existing_dependency)} CVE for this repository")
            for i in existing_dependency:
                print(i)
    if code.type == "github":
        pypi_cve = None
        node_cve = None

        # check for requirements.txt and find CVEs
        try:
            pypi_cve = check_requirements(code)
        except Exception as e:
            print(e)

        # check for package-lock.json and find CVEs
        try:
            node_cve = check_node_cve(code)
        except Exception as e:
            print(e)

        # for n in node_cve:
        #     print(n)

        # CVEs = pypi_cve

        return pypi_cve, node_cve
