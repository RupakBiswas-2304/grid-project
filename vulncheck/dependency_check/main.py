from .pypi_cve import check_pypi_CVE,requirment_reader,check_requirements

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
        try:
            pypi_cve = check_requirements(code)
        except Exception as e:
            print (e)
        CVEs = pypi_cve
        # print(len(CVEs))
        for cve in CVEs:
            print(cve["aliases"])
        return CVEs