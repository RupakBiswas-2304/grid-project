import sys
import subprocess
import requests

class PypiClone():
    '''
    A utility for  cloning a pypi repo to temp folder.
    '''

    def __init__(self,url) -> None:
        self.type = "pypi"
        version = None
        if ("==" in url):
            version = url.split("==")[1]
            url = url.split("==")[0]
        elif (":" in url):
            url = url.split(":")[0]
            version = url.split(":")[1]

        self.url = url
        self.version = version

        self.info_page_api = f"https://pypi.org/pypi/{url}/json"
        if version != None:
            self.info_page_api = f"https://pypi.org/pypi/{url}/{version}/json"

    def gather_info(self):
        print("Gathering info...")

        try:
            response = requests.get(self.info_page_api)
            response.raise_for_status()
            self.info = response.json()
        except Exception as e:
            print(e)
            print("Error: Could not gather info")
            sys.exit()

        if self.version == None:
            releases = self.info['releases'].keys()
            print(f"Found {len(releases)} releases")
            for release in releases:
                print(release+",")
            print("Downloading latest release...")

        self.download_url = self.info['urls'][0]['url']
        self.filename = self.info['urls'][0]['filename']
        filename = self.filename.split(".")
        self.file_ext = "whl"
        if filename[-1] == "gz":
            self.file_ext = "tar.gz"
        elif filename[-1] == "whl":
            self.file_ext = "whl"
        
        print(f"Found download link : {self.download_url}")

    def download_file(self):
        print("Downloading file...")
        try:
            subprocess.call(["rm", "-rf", "tmp"])
            subprocess.call(['mkdir','tmp'])
            subprocess.call(["wget", self.download_url, "-O", "tmp/{}".format(self.filename)])
        except Exception as e:
            print(e)
            print("Error: Could not download file")
            sys.exit()
        print("File Downloaded.")

    def extract_tar_gz(self):
        print("Extracting tar.gz...")
        try:
            subprocess.call(["tar", "-xzf", "tmp/{}".format(self.filename), "-C", "tmp"])
        except Exception as e:
            print(e)
            print("Error: Could not extract tar.gz")
            sys.exit()
        print("Extracted tar.gz")

    def extract_whl(self):
        print("Extracting whl...")
        try:
            subprocess.call(["unzip", "tmp/{}".format(self.filename), "-d", "tmp"])
            subprocess.call(["rm","-f", "tmp/{}".format(self.filename)])
        except Exception as e:
            print(e)
            print("Error: Could not extract whl")
            sys.exit()
        print("Extracted whl")